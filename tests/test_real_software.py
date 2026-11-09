"""진짜 소프트웨어로 배포 흐름 검증: 실제 nginx·Apache·Tomcat(JKS/PKCS12, 실제 keytool/JVM)을 로컬에 띄워 certdeploy 로 인증서를 교체하고,
실제 TLS 핸드셰이크로 새 인증서 서빙 확인 → 설정 오류·재로드 실패 시 롤백. 해당 프로그램이 없으면 건너뛴다(VM/장비 검증은 아님)."""
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from certdeploy.bundle import load_bundle
from certdeploy.config import parse_config
from certdeploy.engine import Deployer
from certdeploy.notify import NullNotifier
from certdeploy.state import State
from certdeploy.verify import tls_serial
from pki_helpers import make_pki

need = lambda *bins: pytest.mark.skipif(not all(shutil.which(b) for b in bins), reason=f"{'/'.join(bins)} 없음")  # noqa: E731


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_serving(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            return tls_serial("127.0.0.1", port, None)
        except Exception:  # noqa: BLE001
            time.sleep(0.3)
    raise AssertionError(f"포트 {port} 에서 TLS 응답 없음")


def wait_serial(port, serial, timeout=20):
    """재로드 직후에는 이전 워커가 잠깐 남아 있을 수 있어(그래서 certdeploy 에 soak 옵션이 있다) 기대한 일련번호가 보일 때까지 확인한다."""
    end, got = time.time() + timeout, None
    while time.time() < end:
        try:
            got = tls_serial("127.0.0.1", port, None)
            if got == serial:
                return got
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.2)
    raise AssertionError(f"기대한 일련번호가 {timeout}초 안에 서빙되지 않음(마지막 {got})")


class Site:
    """tmp 안에서 도는 실제 웹서버 한 대 + 그 서버에 인증서를 배포할 certdeploy Deployer 생성기"""

    def __init__(self, tmp, port):
        self.tmp, self.port = Path(tmp), port
        self.ssl = self.tmp / "ssl"
        self.ssl.mkdir()
        self.procs = []
        self.gen = 0

    def new_pki(self, name):
        c, k, _, _ = make_pki(self.tmp, name=name, san=("localhost",), days_to=90)
        return str(c), str(k)

    def install_initial(self, name="initial"):
        c, k = self.new_pki(name)
        b = load_bundle(c, k)
        (self.ssl / "site.crt").write_bytes(b.fullchain_pem())
        (self.ssl / "site.key").write_bytes(b.key_pem())
        (self.ssl / "site.key").chmod(0o600)
        return b

    def deployer(self, target, name):
        c, k = self.new_pki(name)
        cfg = parse_config({"certificate": {"cert_file": c, "key_file": k}, "state_dir": str(self.tmp / "state"),
                            "options": {"verify_attempts": 6, "verify_interval": 0.5}, "targets": [target]})
        b = load_bundle(c, k)
        return Deployer(cfg, b, State(cfg.state_dir).load(), notifier=NullNotifier(), sleep=time.sleep), b


# ------------------------------------------------------------------ nginx
@pytest.fixture
def nginx(tmp_path):
    port = free_port()
    s = Site(tmp_path, port)
    (tmp_path / "snippets").mkdir()
    (tmp_path / "snippets/extra.conf").write_text("# ok\n")
    conf = tmp_path / "nginx.conf"
    conf.write_text(f"""pid {tmp_path}/nginx.pid;
error_log {tmp_path}/error.log;
events {{ worker_connections 64; }}
http {{
  access_log off;
  client_body_temp_path {tmp_path}/t1; proxy_temp_path {tmp_path}/t2; fastcgi_temp_path {tmp_path}/t3; uwsgi_temp_path {tmp_path}/t4; scgi_temp_path {tmp_path}/t5;
  include {tmp_path}/snippets/*.conf;
  server {{ listen 127.0.0.1:{port} ssl; ssl_certificate {s.ssl}/site.crt; ssl_certificate_key {s.ssl}/site.key; location / {{ return 200 "ok"; }} }}
}}
""")
    s.conf = conf
    s.initial = s.install_initial()
    subprocess.run(["nginx", "-c", str(conf), "-p", str(tmp_path)], check=True, capture_output=True)
    wait_serving(port)
    yield s
    subprocess.run(["nginx", "-c", str(conf), "-p", str(tmp_path), "-s", "stop"], capture_output=True)


def nginx_target(s, **over):
    t = {"name": "web", "type": "nginx", "cert_path": str(s.ssl / "site.crt"), "key_path": str(s.ssl / "site.key"),
         "check_cmd": f"nginx -t -c {s.conf} -p {s.tmp}", "reload_cmd": f"nginx -c {s.conf} -p {s.tmp} -s reload",
         "verify": {"host": "127.0.0.1", "port": s.port}}
    t.update(over)
    return t


@need("nginx")
def test_real_nginx_deploy_serves_new_certificate(nginx):
    assert tls_serial("127.0.0.1", nginx.port, None) == nginx.initial.serial
    d, b = nginx.deployer(nginx_target(nginx), "renewed")
    (r,) = d.deploy()
    assert r.status == "deployed", r.message
    assert wait_serial(nginx.port, b.serial) == b.serial != nginx.initial.serial                  # 실제 nginx 가 새 인증서를 서빙
    (again,) = d.deploy()
    assert again.status == "skipped"                                                      # 멱등
    assert any(p.name.startswith("site.crt.bak-") for p in nginx.ssl.iterdir())          # 백업 보존


@need("nginx")
def test_real_nginx_config_error_rolls_back_and_keeps_serving_old_cert(nginx):
    (nginx.tmp / "snippets/extra.conf").write_text("this is not valid nginx syntax;\n")   # nginx -t 가 실패하도록
    d, b = nginx.deployer(nginx_target(nginx), "renewed")
    before = (nginx.ssl / "site.crt").read_bytes()
    (r,) = d.deploy()
    assert r.status in ("rolled_back", "failed") and "unknown directive" in r.message or "nginx" in r.message.lower()
    assert (nginx.ssl / "site.crt").read_bytes() == before                                # 파일 원복
    (nginx.tmp / "snippets/extra.conf").write_text("# fixed\n")
    assert tls_serial("127.0.0.1", nginx.port, None) == nginx.initial.serial              # 서비스는 계속 이전 인증서


@need("nginx")
def test_real_nginx_reload_failure_restores_files(nginx):
    d, b = nginx.deployer(nginx_target(nginx, reload_cmd=f"nginx -c {nginx.tmp}/missing.conf -p {nginx.tmp} -s reload"), "renewed")
    before = (nginx.ssl / "site.key").read_bytes()
    (r,) = d.deploy()
    assert r.status == "rolled_back" and (nginx.ssl / "site.key").read_bytes() == before


# ------------------------------------------------------------------ Apache
@pytest.fixture
def apache(tmp_path):
    port = free_port()
    s = Site(tmp_path, port)
    mods = "/usr/lib/apache2/modules"
    s.conf = tmp_path / "httpd.conf"
    s.conf.write_text(f"""ServerRoot "{tmp_path}"
ServerName localhost
PidFile {tmp_path}/apache.pid
ErrorLog {tmp_path}/error.log
DefaultRuntimeDir {tmp_path}
Mutex file:{tmp_path} default
User www-data
Group www-data
Listen 127.0.0.1:{port}
LoadModule mpm_event_module {mods}/mod_mpm_event.so
LoadModule authz_core_module {mods}/mod_authz_core.so
LoadModule socache_shmcb_module {mods}/mod_socache_shmcb.so
LoadModule ssl_module {mods}/mod_ssl.so
SSLSessionCache shmcb:{tmp_path}/ssl_scache(512000)
IncludeOptional {tmp_path}/snippets/*.conf
<VirtualHost 127.0.0.1:{port}>
  SSLEngine on
  SSLCertificateFile {s.ssl}/site.crt
  SSLCertificateKeyFile {s.ssl}/site.key
</VirtualHost>
""")
    (tmp_path / "snippets").mkdir()
    (tmp_path / "snippets/extra.conf").write_text("# ok\n")
    s.initial = s.install_initial()
    r = subprocess.run(["apache2", "-f", str(s.conf), "-k", "start"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    wait_serving(port)
    yield s
    subprocess.run(["apache2", "-f", str(s.conf), "-k", "stop"], capture_output=True)


def apache_target(s, **over):
    t = {"name": "web", "type": "apache", "cert_path": str(s.ssl / "site.crt"), "key_path": str(s.ssl / "site.key"),
         "check_cmd": f"apache2 -t -f {s.conf}", "reload_cmd": f"apache2 -f {s.conf} -k graceful",
         "verify": {"host": "127.0.0.1", "port": s.port}}
    t.update(over)
    return t


@need("apache2")
def test_real_apache_deploy_serves_new_certificate(apache):
    d, b = apache.deployer(apache_target(apache), "renewed")
    (r,) = d.deploy()
    assert r.status == "deployed", r.message
    assert wait_serial(apache.port, b.serial) == b.serial != apache.initial.serial


@need("apache2")
def test_real_apache_config_error_rolls_back(apache):
    (apache.tmp / "snippets/extra.conf").write_text("NoSuchDirective yes\n")
    d, b = apache.deployer(apache_target(apache), "renewed")
    before = (apache.ssl / "site.crt").read_bytes()
    (r,) = d.deploy()
    assert r.status in ("rolled_back", "failed") and (apache.ssl / "site.crt").read_bytes() == before
    (apache.tmp / "snippets/extra.conf").write_text("# fixed\n")
    assert tls_serial("127.0.0.1", apache.port, None) == apache.initial.serial


# ------------------------------------------------------------------ Tomcat (실제 JVM, 실제 keytool 로 만든 JKS / PKCS12)
CATALINA_HOME = Path("/usr/share/tomcat10")


@pytest.fixture(params=["pkcs12", "jks"])
def tomcat(tmp_path, request):
    if not (shutil.which("keytool") and (CATALINA_HOME / "bin/catalina.sh").exists()):
        pytest.skip("Tomcat/JDK 없음")
    port, base = free_port(), tmp_path / "base"
    for d in ("conf", "logs", "temp", "work", "webapps", "ks"):
        (base / d).mkdir(parents=True)
    s = Site(tmp_path, port)
    s.fmt, s.base, s.password = request.param, base, "ks-Pass-123"
    s.ks = base / "ks" / ("server.p12" if request.param == "pkcs12" else "server.jks")
    for f in ("web.xml", "logging.properties", "catalina.properties"):
        shutil.copy(Path("/etc/tomcat10") / f, base / "conf" / f)
    (base / "conf/server.xml").write_text(f"""<Server port="-1"><Service name="Catalina">
 <Connector port="{port}" address="127.0.0.1" protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true">
  <SSLHostConfig><Certificate certificateKeystoreFile="{s.ks}" certificateKeystorePassword="{s.password}" certificateKeystoreType="{'PKCS12' if request.param == 'pkcs12' else 'JKS'}" type="RSA"/></SSLHostConfig>
 </Connector>
 <Engine name="Catalina" defaultHost="localhost"><Host name="localhost" appBase="webapps"/></Engine></Service></Server>""")
    s.env = {**os.environ, "CATALINA_HOME": str(CATALINA_HOME), "CATALINA_BASE": str(base), "CATALINA_PID": str(base / "tomcat.pid"), "JAVA_OPTS": "-Xmx128m"}
    # 초기 키스토어는 인증서 배포와 같은 코드로 만들어 둔다(실제 keytool 이 읽는지는 아래에서 Tomcat 이 증명)
    c, k = s.new_pki("initial")
    b = load_bundle(c, k)
    s.initial = b
    s.ks.write_bytes(b.pkcs12(s.password, "tomcat") if request.param == "pkcs12" else b.jks(s.password, "tomcat"))
    s.restart = f"CATALINA_HOME={CATALINA_HOME} CATALINA_BASE={base} CATALINA_PID={base}/tomcat.pid JAVA_OPTS=-Xmx128m {CATALINA_HOME}/bin/catalina.sh stop 10 -force >/dev/null 2>&1; " \
                f"CATALINA_HOME={CATALINA_HOME} CATALINA_BASE={base} CATALINA_PID={base}/tomcat.pid JAVA_OPTS=-Xmx128m {CATALINA_HOME}/bin/catalina.sh start"
    subprocess.run(["bash", "-c", s.restart], capture_output=True, env=s.env)
    wait_serving(port, 60)
    yield s
    subprocess.run([str(CATALINA_HOME / "bin/catalina.sh"), "stop", "10", "-force"], capture_output=True, env=s.env)


@need("keytool")
def test_real_tomcat_keystore_deploy_and_restart(tomcat):
    t = {"name": "tc", "type": "tomcat", "format": tomcat.fmt, "keystore_path": str(tomcat.ks), "password_env": "KS_PW", "alias": "tomcat",
         "reload_cmd": tomcat.restart, "verify": {"host": "127.0.0.1", "port": tomcat.port}}
    d, b = tomcat.deployer(t, "renewed")
    d.environ = {**os.environ, "KS_PW": tomcat.password}
    d.cfg.options.command_timeout = 90
    (r,) = d.deploy()
    assert r.status == "deployed", r.message
    assert wait_serial(tomcat.port, b.serial) == b.serial != tomcat.initial.serial            # 실제 JVM 이 새 키스토어를 읽어 서빙
    out = subprocess.run(["keytool", "-list", "-keystore", str(tomcat.ks), "-storepass", tomcat.password, "-storetype", "PKCS12" if tomcat.fmt == "pkcs12" else "JKS"],
                         capture_output=True, text=True)
    assert out.returncode == 0 and "tomcat" in out.stdout.lower()                         # 실제 keytool 이 우리가 만든 키스토어를 열고 별칭을 확인


# ------------------------------------------------------------------ BIND (실제 named, RFC 2136 + TSIG)
SECRET = "c2VjcmV0LXRzaWctYmFzZTY0LXZhbHVlLTEyMzQ1Ng=="      # base64


@pytest.fixture
def bind(tmp_path):
    if not shutil.which("named"):
        pytest.skip("named 없음")
    port = free_port()
    (tmp_path / "hnu.test.zone").write_text("$TTL 60\n@ IN SOA ns.hnu.test. admin.hnu.test. 1 3600 600 86400 60\n@ IN NS ns.hnu.test.\nns IN A 127.0.0.1\n")
    (tmp_path / "named.conf").write_text(f"""options {{ directory "{tmp_path}"; listen-on port {port} {{ 127.0.0.1; }}; listen-on-v6 {{ none; }}; pid-file "{tmp_path}/named.pid";
  session-keyfile "{tmp_path}/session.key"; recursion no; allow-query {{ any; }}; dnssec-validation no; }};
key "acme-key" {{ algorithm hmac-sha256; secret "{SECRET}"; }};
zone "hnu.test" {{ type primary; file "hnu.test.zone"; allow-update {{ key "acme-key"; }}; }};
""")
    chk = subprocess.run(["named-checkconf", str(tmp_path / "named.conf")], capture_output=True, text=True)
    assert chk.returncode == 0, chk.stderr
    p = subprocess.Popen(["named", "-c", str(tmp_path / "named.conf"), "-f", "-u", "root"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    from certdeploy import dnsquery
    for _ in range(50):
        try:
            if dnsquery.query_txt("hnu.test", "127.0.0.1", port, 1.0) is not None:
                break
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    yield port
    p.terminate()
    p.wait(timeout=10)


def dig_txt(port, name):
    r = subprocess.run(["dig", "+short", "+time=2", "+tries=1", "-p", str(port), "@127.0.0.1", "TXT", name], capture_output=True, text=True)
    return r.stdout.strip()


@need("named", "dig")
def test_real_bind_rfc2136_present_and_cleanup_with_tsig(bind):
    from certdeploy.dnsprov import Rfc2136Provider
    pr = Rfc2136Provider(f"127.0.0.1:{bind}", "hnu.test", "acme-key", SECRET)
    pr.present("_acme-challenge.hnu.test", "tokenvalue-ABC")
    assert "tokenvalue-ABC" in dig_txt(bind, "_acme-challenge.hnu.test")                  # 실제 BIND 가 TSIG 서명 갱신을 수락하고 TXT 를 응답
    from certdeploy import dnsquery
    assert dnsquery.txt_visible("_acme-challenge.hnu.test", "tokenvalue-ABC", [f"127.0.0.1:{bind}"]) or "tokenvalue-ABC" in dnsquery.query_txt("_acme-challenge.hnu.test", "127.0.0.1", bind, 3.0)
    pr.present("_acme-challenge.hnu.test", "second-token")                                # 와일드카드+기본 도메인처럼 TXT 가 두 개 필요한 경우
    out = dig_txt(bind, "_acme-challenge.hnu.test")
    assert "tokenvalue-ABC" in out and "second-token" in out
    pr.cleanup("_acme-challenge.hnu.test", "tokenvalue-ABC")                              # 해당 값만 삭제(다른 값 유지)
    out = dig_txt(bind, "_acme-challenge.hnu.test")
    assert "tokenvalue-ABC" not in out and "second-token" in out
    pr.cleanup("_acme-challenge.hnu.test", "second-token")
    assert dig_txt(bind, "_acme-challenge.hnu.test") == ""


@need("named", "dig")
def test_real_bind_rejects_wrong_key_and_unsigned_updates(bind):
    from certdeploy.dnsprov import DnsProviderError, Rfc2136Provider
    for pr in (Rfc2136Provider(f"127.0.0.1:{bind}", "hnu.test", "acme-key", "d3Jvbmctc2VjcmV0LXZhbHVlLWFhYWFhYWFh"),     # 잘못된 비밀
               Rfc2136Provider(f"127.0.0.1:{bind}", "hnu.test"),                                                          # 서명 없음
               Rfc2136Provider(f"127.0.0.1:{bind}", "hnu.test", "other-key", SECRET)):                                    # 모르는 키 이름
        with pytest.raises(DnsProviderError):
            pr.present("_acme-challenge.hnu.test", "x")
    assert dig_txt(bind, "_acme-challenge.hnu.test") == ""


@need("named", "dig")
def test_real_bind_wrong_zone_is_refused(bind):
    from certdeploy.dnsprov import DnsProviderError, Rfc2136Provider
    with pytest.raises(DnsProviderError):
        Rfc2136Provider(f"127.0.0.1:{bind}", "other.test", "acme-key", SECRET).present("_acme-challenge.other.test", "x")


# ------------------------------------------------------------------ 설치가 만드는 설정 파일을 진짜 도구로 문법 검사
ROOT = Path(__file__).resolve().parent.parent


@need("nginx")
def test_generated_nginx_configs_pass_real_nginx_t(tmp_path):
    """설치 스크립트가 예시 파일을 치환해 만드는 grafana.conf / certdeploy-admin.conf 가 실제 nginx -t 를 통과한다."""
    c, k, _, _ = make_pki(tmp_path, name="mgmt", san=("mgmt.hnu.kr",))
    (tmp_path / "conf.d").mkdir()
    for n in ("grafana", "certdeploy-admin"):
        t = (ROOT / f"monitoring/nginx/{n}.conf.example").read_text(encoding="utf-8")
        t = (t.replace("monitor.univ.example", "mgmt.hnu.kr").replace("mgmt.univ.example", "mgmt.hnu.kr")
              .replace("/etc/pki/tls/certs/monitor.crt", str(c)).replace("/etc/pki/tls/private/monitor.key", str(k))
              .replace("/etc/pki/tls/certs/mgmt.crt", str(c)).replace("/etc/pki/tls/private/mgmt.key", str(k)))
        assert "univ.example" not in t and "/etc/pki" not in t
        (tmp_path / "conf.d" / f"{n}.conf").write_text(t)
    main = tmp_path / "nginx.conf"
    main.write_text(f"pid {tmp_path}/n.pid; error_log {tmp_path}/e.log;\nevents {{}}\nhttp {{ access_log off; include {tmp_path}/conf.d/*.conf; }}\n")
    r = subprocess.run(["nginx", "-t", "-c", str(main), "-p", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    (tmp_path / "conf.d/grafana.conf").write_text("server { listen 443 ssl; bogus_directive on; }\n")      # 검사 도구가 실제로 오류를 잡는지(음성 대조)
    assert subprocess.run(["nginx", "-t", "-c", str(main), "-p", str(tmp_path)], capture_output=True).returncode != 0


@need("systemd-analyze")
def test_systemd_units_pass_systemd_analyze_verify(tmp_path):
    """모든 certdeploy 유닛이 실제 systemd 파서로 경고 없이 통과(알 수 없는 키·잘못된 값·없는 실행 파일·의존 유닛 오류)."""
    sysdir = Path("/usr/lib/systemd/system")
    if not sysdir.exists():
        pytest.skip("systemd 유닛 디렉터리 없음")
    root = tmp_path / "root"
    dest = root / "usr/lib/systemd/system"
    shutil.copytree(sysdir, dest, symlinks=True)
    for f in (ROOT / "certdeploy/systemd").iterdir():
        shutil.copy(f, dest / f.name)
    for b in ("certdeploy", "certdeploy-discover", "gunicorn"):
        p = root / "opt/certdeploy/venv/bin" / b
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("#!/bin/sh\n")
        p.chmod(0o755)
    for d in ("etc/certdeploy", "var/lib/certdeploy", "var/lib/certdeploy-admin", "var/lib/lego", "var/backups/certdeploy"):
        (root / d).mkdir(parents=True, exist_ok=True)
    for f in ("env", "admin.env", "backup.env"):
        (root / "etc/certdeploy" / f).write_text("")
    units = sorted(f.name for f in (ROOT / "certdeploy/systemd").iterdir())
    assert len(units) >= 7
    r = subprocess.run(["systemd-analyze", "verify", f"--root={root}", *units], capture_output=True, text=True, cwd=str(tmp_path))
    out = "\n".join(l for l in (r.stdout + r.stderr).splitlines() if "IPv6" not in l)         # 시험 커널의 IPv6 미지원 안내는 환경 메시지
    assert out.strip() == "", out                       # 경고·오류가 한 줄도 없어야 함
    bad = dest / "bad.service"
    bad.write_text((ROOT / "certdeploy/systemd/certdeploy-admin.service").read_text().replace("Restart=on-failure", "Restart=sometimes").replace("User=certdeploy", "Bogus=1"))
    r2 = subprocess.run(["systemd-analyze", "verify", f"--root={root}", "bad.service"], capture_output=True, text=True, cwd=str(tmp_path))
    assert "Bogus" in r2.stderr + r2.stdout and "sometimes" in r2.stderr + r2.stdout      # 음성 대조: 검사 도구가 실제로 오류를 잡음


# ------------------------------------------------------------------ 진짜 sshd + sudo + 진짜 nginx (프로세스 내 가짜 SSH 서버가 아님)
@pytest.fixture
def real_ssh(tmp_path):
    """root 소유 폴더에 배포하려면 sudo 가 필요한 상황을 만든다: 배포 계정 cdeploy(NOPASSWD sudo)로 실제 OpenSSH 서버에 접속."""
    if os.geteuid() != 0 or not all(shutil.which(b) for b in ("sshd", "ssh-keygen", "ssh-keyscan", "sudo", "useradd")):
        pytest.skip("root·sshd·sudo 필요")
    for d in [tmp_path, *tmp_path.parents]:                       # 배포 계정(비root)이 시험 폴더까지 들어올 수 있게 상위 폴더 통과 권한을 연다
        if str(d) in ("/", "/tmp"):
            break
        os.chmod(d, 0o755)
    user = f"cdep{os.getpid() % 10000}"
    subprocess.run(["useradd", "-m", "-s", "/bin/bash", user], check=True, capture_output=True)
    subprocess.run(["usermod", "-p", "*", user], check=True, capture_output=True)       # 잠긴 계정(!)은 UsePAM no 일 때 공개키 로그인도 거부된다
    sshdir = tmp_path / "sshd"
    sshdir.mkdir()
    key = tmp_path / "client_key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(sshdir / "host_key")], check=True)
    home = Path(f"/home/{user}")
    (home / ".ssh").mkdir(mode=0o700)
    (home / ".ssh/authorized_keys").write_text((tmp_path / "client_key.pub").read_text())
    subprocess.run(["chown", "-R", f"{user}:{user}", str(home / ".ssh")], check=True)
    (home / ".ssh/authorized_keys").chmod(0o600)
    sudoers = Path(f"/etc/sudoers.d/{user}")
    sudoers.write_text(f"{user} ALL=(root) NOPASSWD: /bin/sh -c *\n")
    sudoers.chmod(0o440)
    port = free_port()
    (tmp_path / "sshd_config").write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {sshdir}/host_key\nPidFile {sshdir}/sshd.pid\nPasswordAuthentication no\nUsePAM no\n"
                                          f"PubkeyAuthentication yes\nAuthorizedKeysFile {home}/.ssh/authorized_keys\nAllowUsers {user}\nStrictModes no\n")
    Path("/run/sshd").mkdir(exist_ok=True)
    p = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(tmp_path / "sshd_config")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    kh = tmp_path / "known_hosts"
    for _ in range(40):
        r = subprocess.run(["ssh-keyscan", "-p", str(port), "-t", "ed25519", "127.0.0.1"], capture_output=True, text=True)
        if r.stdout.strip():
            kh.write_text(r.stdout)
            break
        time.sleep(0.2)
    else:
        raise AssertionError("sshd 가 기동되지 않음")
    yield type("SSH", (), {"port": port, "user": user, "key": str(key), "known_hosts": str(kh), "tmp": tmp_path})
    p.terminate()
    p.wait(timeout=10)
    sudoers.unlink(missing_ok=True)
    subprocess.run(["userdel", "-r", user], capture_output=True)


@need("nginx", "sshd")
def test_real_ssh_sudo_deploy_to_real_nginx_and_rollback(nginx, real_ssh):
    # nginx 가 읽는 인증서 폴더는 root 소유(배포 계정은 직접 쓸 수 없음) → sudo 경로가 실제로 쓰여야 성공
    os.chmod(nginx.ssl, 0o755)
    for f in nginx.ssl.iterdir():
        os.chmod(f, 0o644 if f.suffix == ".crt" else 0o600)
    tr = {"kind": "ssh", "host": "127.0.0.1", "port": real_ssh.port, "user": real_ssh.user, "key_file": real_ssh.key, "known_hosts": real_ssh.known_hosts, "sudo": True}
    t = nginx_target(nginx, transport=tr)
    d, b = nginx.deployer(t, "renewed")
    d.cfg.options.command_timeout = 30
    (r,) = d.deploy()
    assert r.status == "deployed", r.message
    assert wait_serial(nginx.port, b.serial) == b.serial != nginx.initial.serial
    st = os.stat(nginx.ssl / "site.key")
    assert st.st_uid == 0 and oct(st.st_mode & 0o777) == "0o600"                          # sudo 로 root 소유·600 으로 설치(chown --reference 유지)
    # 실패 → 롤백도 같은 실제 SSH+sudo 경로로 수행
    (nginx.tmp / "snippets/extra.conf").write_text("broken directive;\n")
    d2, b2 = nginx.deployer(t, "renewed2")
    d2.cfg.options.command_timeout = 30
    served_before = (nginx.ssl / "site.crt").read_bytes()
    (r2,) = d2.deploy()
    assert r2.status in ("rolled_back", "failed") and (nginx.ssl / "site.crt").read_bytes() == served_before
    (nginx.tmp / "snippets/extra.conf").write_text("# ok\n")
    assert tls_serial("127.0.0.1", nginx.port, None) == b.serial


@need("sshd")
def test_real_ssh_rejects_changed_host_key_and_sudo_denied(real_ssh, tmp_path):
    from certdeploy.transport import SSHTransport, TransportError
    tr = SSHTransport("127.0.0.1", real_ssh.user, real_ssh.port, real_ssh.key, real_ssh.known_hosts, sudo=False)
    assert tr.run("echo ok").out.strip() == "ok"
    assert tr.run("sudo -n id").rc != 0                                                   # sudoers 가 허용한 형태(sh -c) 외의 명령은 거부됨(최소 권한 확인)
    tr.close()
    other = tmp_path / "kh_other"
    k2 = tmp_path / "k2"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(k2)], check=True)
    other.write_text(f"[127.0.0.1]:{real_ssh.port} " + (tmp_path / "k2.pub").read_text())     # 다른 호스트 키가 등록된 known_hosts → 접속 거부
    with pytest.raises(TransportError):
        SSHTransport("127.0.0.1", real_ssh.user, real_ssh.port, real_ssh.key, str(other))
    with pytest.raises(TransportError):
        SSHTransport("127.0.0.1", real_ssh.user, real_ssh.port, real_ssh.key, str(tmp_path / "missing_known_hosts"))


@need("nginx", "sshd")
def test_real_least_privilege_deploy_user_writes_cert_dir_and_sudo_only_for_reload(nginx, real_ssh):
    """문서가 권하는 방식: 배포 계정은 인증서 폴더만 쓰고(소유자=deploy), 점검·재로드 명령만 sudoers 로 허용 — 전체 root 권한(sudo: true) 없이 동작."""
    user = real_ssh.user
    subprocess.run(["chown", "-R", f"{user}:{user}", str(nginx.ssl)], check=True)
    nginx_bin = shutil.which("nginx")
    sudoers = Path(f"/etc/sudoers.d/{user}")
    sudoers.write_text(f"{user} ALL=(root) NOPASSWD: {nginx_bin} -t -c {nginx.conf} -p {nginx.tmp}, {nginx_bin} -c {nginx.conf} -p {nginx.tmp} -s reload\n")
    sudoers.chmod(0o440)
    assert subprocess.run(["visudo", "-cf", str(sudoers)], capture_output=True).returncode == 0
    tr = {"kind": "ssh", "host": "127.0.0.1", "port": real_ssh.port, "user": user, "key_file": real_ssh.key, "known_hosts": real_ssh.known_hosts}   # sudo: false(기본)
    t = nginx_target(nginx, transport=tr, check_cmd=f"sudo -n {nginx_bin} -t -c {nginx.conf} -p {nginx.tmp}",
                     reload_cmd=f"sudo -n {nginx_bin} -c {nginx.conf} -p {nginx.tmp} -s reload")
    d, b = nginx.deployer(t, "renewed")
    d.cfg.options.command_timeout = 30
    from certdeploy.preflight import run_preflight
    checks = run_preflight(d)
    assert any("sudo 허용" in c.name and c.ok for c in checks), [(c.name, c.ok, c.detail) for c in checks]        # 사전 점검이 sudoers 허용 여부를 실제로 확인
    (r,) = d.deploy()
    assert r.status == "deployed", r.message
    assert wait_serial(nginx.port, b.serial) == b.serial
    assert os.stat(nginx.ssl / "site.key").st_uid == os.stat(nginx.ssl / "site.crt").st_uid != 0               # 배포 계정 소유(root 권한 없이 설치)
    # sudoers 에 없는 명령(예: 다른 설정 파일 재로드)은 사전 점검에서 잡힌다
    t2 = nginx_target(nginx, transport=tr, check_cmd=f"sudo -n {nginx_bin} -t -c {nginx.conf} -p {nginx.tmp}", reload_cmd="sudo -n systemctl restart sshd")
    d3, _ = nginx.deployer(t2, "renewed3")
    bad = [c for c in run_preflight(d3) if "sudo 허용" in c.name and not c.ok]
    assert bad and "sudoers" in bad[0].detail


def test_sudo_reload_makes_default_check_use_sudo_too():
    base = {"certificate": {"cert_file": "/a.crt", "key_file": "/a.key"}}
    tgt = {"name": "w", "type": "apache", "cert_path": "/c", "key_path": "/k", "reload_cmd": "sudo -n systemctl reload httpd", "transport": {"kind": "ssh", "host": "h", "user": "u"}}
    assert parse_config({**base, "targets": [tgt]}).targets[0].check_cmd == "sudo -n apachectl configtest"
    assert parse_config({**base, "targets": [{**tgt, "type": "nginx"}]}).targets[0].check_cmd == "sudo -n nginx -t"
    assert parse_config({**base, "targets": [{**tgt, "check_cmd": "true"}]}).targets[0].check_cmd == "true"                      # 직접 지정은 그대로
    assert "sudo" not in parse_config({**base, "targets": [{**tgt, "reload_cmd": "systemctl reload httpd"}]}).targets[0].check_cmd   # sudo 를 안 쓰면 기본 그대로
    assert "sudo" not in parse_config({**base, "targets": [{**tgt, "transport": {**tgt["transport"], "sudo": True}}]}).targets[0].check_cmd   # sudo: true 는 전체가 sudo 로 감싸지므로 중복 안 함


# ------------------------------------------------------------------ ACME CNAME 위임 (실제 BIND 두 영역: 챌린지 이름 → 다른 영역의 대상)
@pytest.fixture
def bind2(tmp_path):
    """hnu.test 영역에는 CNAME 만 두고, TXT 는 acme.test 영역(갱신 허용 키 있음)에 넣는다 — 실제 위임 구성."""
    if not shutil.which("named"):
        pytest.skip("named 없음")
    port = free_port()
    soa = "$TTL 60\n@ IN SOA ns.{z}. admin.{z}. 1 3600 600 86400 60\n@ IN NS ns.{z}.\nns IN A 127.0.0.1\n"
    (tmp_path / "hnu.test.zone").write_text(soa.format(z="hnu.test") + "_acme-challenge IN CNAME _acme-challenge.hnu.acme.test.\n")
    (tmp_path / "acme.test.zone").write_text(soa.format(z="acme.test"))
    (tmp_path / "named.conf").write_text(f"""options {{ directory "{tmp_path}"; listen-on port {port} {{ 127.0.0.1; }}; listen-on-v6 {{ none; }}; pid-file "{tmp_path}/named.pid";
  session-keyfile "{tmp_path}/session.key"; recursion no; allow-query {{ any; }}; dnssec-validation no; }};
key "acme-key" {{ algorithm hmac-sha256; secret "{SECRET}"; }};
zone "hnu.test" {{ type primary; file "hnu.test.zone"; }};
zone "acme.test" {{ type primary; file "acme.test.zone"; allow-update {{ key "acme-key"; }}; }};
""")
    assert subprocess.run(["named-checkconf", str(tmp_path / "named.conf")], capture_output=True).returncode == 0
    p = subprocess.Popen(["named", "-c", str(tmp_path / "named.conf"), "-f", "-u", "root"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    from certdeploy import dnsquery
    for _ in range(50):
        try:
            dnsquery.query_txt("hnu.test", "127.0.0.1", port, 1.0)
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    yield port
    p.terminate()
    p.wait(timeout=10)


@need("named", "dig")
def test_real_bind_cname_delegation_auto_and_explicit(bind2):
    from certdeploy import dnsquery
    from certdeploy.dnsprov import DelegatingProvider, Rfc2136Provider
    res = [f"127.0.0.1:{bind2}"]
    assert dnsquery.resolve_cname("_acme-challenge.hnu.test", res) == "_acme-challenge.hnu.acme.test"       # 실제 BIND 의 CNAME 을 DNS 로 조회
    assert dnsquery.resolve_cname("ns.hnu.test", res) is None                                                  # CNAME 이 아니면 None
    inner = Rfc2136Provider(f"127.0.0.1:{bind2}", "acme.test", "acme-key", SECRET)                             # 갱신은 위임 대상 영역(acme.test)에만 허용
    for prov in (DelegatingProvider(inner, auto=True, resolvers=res),
                 DelegatingProvider(inner, mapping={"_acme-challenge.hnu.test": "_acme-challenge.hnu.acme.test"})):
        prov.present("_acme-challenge.hnu.test", "delegated-token")
        assert "delegated-token" in dig_txt(bind2, "_acme-challenge.hnu.acme.test")                           # TXT 는 대상 이름에 생기고
        assert dnsquery.txt_visible("_acme-challenge.hnu.acme.test", "delegated-token", res)                  # 전파 확인은 대상 이름으로(권한 DNS 는 영역 간 CNAME 을 따라가지 않음)
        from certdeploy import acme
        assert acme.delegated_records([("_acme-challenge.hnu.test", "delegated-token")], provider=prov) == [("_acme-challenge.hnu.acme.test", "delegated-token")]
        prov.cleanup("_acme-challenge.hnu.test", "delegated-token")
        assert "delegated-token" not in dig_txt(bind2, "_acme-challenge.hnu.acme.test")
    from certdeploy.dnsprov import DnsProviderError
    with pytest.raises(DnsProviderError):                                                                      # 위임 없이 챌린지 이름에 직접 쓰면 그 영역은 갱신 허용이 아니라 거부
        Rfc2136Provider(f"127.0.0.1:{bind2}", "hnu.test", "acme-key", SECRET).present("_acme-challenge.hnu.test", "x")
