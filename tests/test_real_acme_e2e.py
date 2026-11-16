"""진짜 ACME 서버로 발급→배포→교체 전 과정 검증(개발 환경).

- CA: **Pebble**(Let's Encrypt 가 만든 ACME 시험 서버. Let's Encrypt 운영 서버와 같은 RFC 8555 규칙을 엄격히 검사)
- DNS: **실제 BIND** 에 RFC 2136(TSIG) 로 TXT 등록 → Pebble 이 그 BIND 에 직접 물어 DNS-01 검증
- 배포: **실제 OpenSSH+sudo** 로 nginx, 로컬로 Apache, 실제 Tomcat(JVM) 키스토어
- 실행: 운영과 같은 `certdeploy` CLI(subprocess)

실제 Let's Encrypt·Infoblox·학교 서버가 아니라는 점만 다르다(그건 VM 시험 T-14~T-16). 필요한 프로그램이 없으면 건너뛴다.
"""
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest
import yaml
from cryptography import x509

from test_real_software import (SECRET, CATALINA_HOME, apache_site, bind_site, dig_txt, free_port, nginx_site, real_ssh_site,
                                wait_serial)
from certdeploy.verify import tls_serial
from pki_helpers import make_pki

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(not all(shutil.which(b) for b in ("pebble", "named", "dig", "nginx", "apache2", "sshd", "openssl")),
                                reason="pebble/named/nginx/apache2/sshd 필요")


def _sub(gen_fn, tmp_path, name):
    d = tmp_path / name
    d.mkdir()
    return gen_fn(d)


@pytest.fixture
def bind(tmp_path):
    yield from _sub(bind_site, tmp_path, "dns")


@pytest.fixture
def nginx(tmp_path):
    yield from _sub(nginx_site, tmp_path, "nginx")


@pytest.fixture
def apache(tmp_path):
    yield from _sub(apache_site, tmp_path, "apache")


@pytest.fixture
def real_ssh(tmp_path):
    yield from _sub(real_ssh_site, tmp_path, "ssh")


@pytest.fixture
def pebble(tmp_path, bind):
    """Pebble 를 띄우고 DNS-01 검증을 실제 BIND 로 하게 한다. 관리 API 로 Pebble 의 루트 CA 를 받아 둔다."""
    d = tmp_path / "pebble"
    d.mkdir()
    # Pebble 자신의 HTTPS 인증서(시험용 사설 CA) — certdeploy 는 SSL_CERT_FILE 로 이 CA 를 신뢰(사설 ACME CA 를 쓰는 운영 환경과 같은 방식)
    crt, key, _, _ = make_pki(d, name="pebble-https", san=("localhost",), days_to=30)
    ca = d / "pebble-https.root.pem"
    port, mport = free_port(), free_port()
    (d / "config.json").write_text(json.dumps({"pebble": {
        "listenAddress": f"127.0.0.1:{port}", "managementListenAddress": f"127.0.0.1:{mport}",
        "certificate": str(crt), "privateKey": str(key), "httpPort": free_port(), "tlsPort": free_port(),
        "ocspResponderURL": "", "externalAccountBindingRequired": False}}))
    env = {**os.environ, "PEBBLE_VA_NOSLEEP": "1"}                     # 기본값 그대로: 5% 확률로 nonce 를 거부(badNonce) — 재시도 로직도 함께 검증
    log = open(d / "pebble.log", "w")
    p = subprocess.Popen(["pebble", "-config", str(d / "config.json"), "-dnsserver", f"127.0.0.1:{bind}"], stdout=log, stderr=subprocess.STDOUT, env=env)
    ctx = ssl.create_default_context(cafile=str(ca))
    for _ in range(100):
        try:
            urllib.request.urlopen(f"https://localhost:{port}/dir", context=ctx, timeout=2).read()
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    else:
        raise AssertionError("pebble 가 기동되지 않음: " + (d / "pebble.log").read_text())
    root_pem = urllib.request.urlopen(f"https://localhost:{mport}/roots/0", context=ctx, timeout=5).read()
    (d / "issuer-root.pem").write_bytes(root_pem)
    yield type("Pebble", (), {"dir": f"https://localhost:{port}/dir", "https_ca": str(ca), "root": str(d / "issuer-root.pem"),
                              "dns_port": bind, "log": d / "pebble.log"})
    p.terminate()
    p.wait(timeout=10)
    log.close()


def write_cfg(tmp, pebble, targets, renew_days=30, tsig=SECRET, extra=None, dns_mode="rfc2136"):
    state = tmp / "state"
    cfg = {"state_dir": str(state), "audit_log": str(tmp / "audit"),
           "options": {"verify_attempts": 10, "verify_interval": 0.5, "command_timeout": 90},
           "certificates": [{
               "name": "hnu",
               "acme": {"directory": pebble.dir, "email": "cert-admin@hnu.test", "domains": ["*.hnu.test", "hnu.test"], "key_type": "rsa2048",
                        "renew_days": renew_days,
                        "dns": {"mode": "rfc2136", "check_resolvers": [f"127.0.0.1:{pebble.dns_port}"], "propagation_timeout": 30,
                                "rfc2136": {"server": f"127.0.0.1:{pebble.dns_port}", "zone": "hnu.test",
                                            "tsig_key_name": "acme-key", "tsig_secret_env": "TSIG_SECRET"}}
                        if dns_mode == "rfc2136" else {"mode": "manual", "check_resolvers": [f"127.0.0.1:{pebble.dns_port}"]}},
               "targets": targets, **(extra or {})}]}
    p = tmp / "certdeploy.yml"
    p.write_text(yaml.safe_dump(cfg, allow_unicode=True))
    env = {**os.environ, "TSIG_SECRET": tsig, "SSL_CERT_FILE": pebble.https_ca, "KS_PW": "ks-Pass-123", "KEY_PW": "key-Pass-phrase-123",
           "PYTHONPATH": str(ROOT)}
    return p, env, state


def cd(cfg, env, *args, timeout=300):
    r = subprocess.run([sys.executable, "-m", "certdeploy", "-c", str(cfg), *args], capture_output=True, text=True, env=env, timeout=timeout)
    if os.environ.get("E2E_VERBOSE"):                                    # E2E_VERBOSE=1 pytest -s … 로 실제 명령 출력 보기
        print(f"\n$ certdeploy {' '.join(args)}   (종료 코드 {r.returncode})\n" + "\n".join(l for l in (r.stdout + r.stderr).splitlines() if " INFO " not in l))
    return r.returncode, r.stdout + r.stderr


def served(port):
    """실제 TLS 핸드셰이크로 받은 인증서(검증 없이) — 일련번호·SAN 확인용"""
    pem = ssl.get_server_certificate(("127.0.0.1", port))
    return x509.load_pem_x509_certificate(pem.encode())


def sans(c):
    return sorted(c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))


def openssl_verify(pebble, cert_file):
    """발급된 체인을 Pebble 루트로 실제 OpenSSL 검증"""
    certs = Path(cert_file).read_text().split("-----END CERTIFICATE-----")
    leaf = certs[0] + "-----END CERTIFICATE-----\n"
    inter = "".join(c + "-----END CERTIFICATE-----\n" for c in certs[1:] if "BEGIN" in c)
    Path(cert_file + ".leaf").write_text(leaf)
    Path(cert_file + ".inter").write_text(inter or leaf)
    r = subprocess.run(["openssl", "verify", "-CAfile", pebble.root, "-untrusted", cert_file + ".inter", cert_file + ".leaf"], capture_output=True, text=True)
    return r.returncode == 0, r.stdout + r.stderr


def ssh_nginx_target(nginx, real_ssh):
    os.chmod(nginx.ssl, 0o755)                                           # 인증서 폴더는 root 소유 → 배포 계정은 sudo 로만 쓸 수 있음
    for f in nginx.ssl.iterdir():
        os.chmod(f, 0o644 if f.suffix == ".crt" else 0o600)
    return {"name": "web-nginx", "type": "nginx", "cert_path": str(nginx.ssl / "site.crt"), "key_path": str(nginx.ssl / "site.key"),
            "check_cmd": f"nginx -t -c {nginx.conf} -p {nginx.tmp}", "reload_cmd": f"nginx -c {nginx.conf} -p {nginx.tmp} -s reload",
            "verify": {"host": "127.0.0.1", "port": nginx.port, "sni": "www.hnu.test"},
            "transport": {"kind": "ssh", "host": "127.0.0.1", "port": real_ssh.port, "user": real_ssh.user, "key_file": real_ssh.key,
                          "known_hosts": real_ssh.known_hosts, "sudo": True}}


def apache_target(apache):
    return {"name": "web-apache", "type": "apache", "cert_path": str(apache.ssl / "site.crt"), "key_path": str(apache.ssl / "site.key"),
            "check_cmd": f"apache2 -t -f {apache.conf}", "reload_cmd": f"apache2 -f {apache.conf} -k graceful",
            "verify": {"host": "127.0.0.1", "port": apache.port, "sni": "www.hnu.test"}}


# ------------------------------------------------------------------ 1. 최초 발급 → 2대 배포 → 불필요 갱신 건너뜀 → 교체(갱신) → 2대 반영
def test_real_acme_issue_deploy_then_renew_replaces_on_real_servers(tmp_path, pebble, nginx, apache, real_ssh):
    cfg, env, state = write_cfg(tmp_path, pebble, [ssh_nginx_target(nginx, real_ssh), apache_target(apache)])
    old_n, old_a = served(nginx.port).serial_number, served(apache.port).serial_number

    # ⓪ 첫 발급 전 점검: 설정 검증과 대상 서버 사전 점검(실제 SSH 접속·sudo·쓰기 권한·현재 TLS)이 발급 전에도 동작해야 한다
    rc, out = cd(cfg, env, "validate")
    assert rc == 0 and "아직 발급 전" in out, out
    rc, out = cd(cfg, env, "preflight")
    assert rc == 0, out
    assert "실패 0건" in out, out

    # ① 최초 발급(Pebble 이 실제 BIND 에서 TXT 2개를 조회해 검증) + 배포(SSH+sudo nginx, Apache)
    rc, out = cd(cfg, env, "issue")
    assert rc == 0, out + (pebble.log.read_text()[-3000:])
    assert "발급 완료" in out
    cert_file = str(state / "hnu" / "managed" / "_.hnu.test.crt") if (state / "hnu" / "managed" / "_.hnu.test.crt").exists() else None
    managed = list((state / "hnu").rglob("*.crt")) if cert_file is None else [Path(cert_file)]
    issued = [p for p in managed if "staging" not in str(p) and "backup" not in str(p)]
    assert issued, list((state).rglob("*"))
    ok, why = openssl_verify(pebble, str(issued[0]))
    assert ok, why                                                                          # 체인이 Pebble 루트까지 실제로 검증됨
    new = x509.load_pem_x509_certificate(issued[0].read_bytes())
    assert sans(new) == ["*.hnu.test", "hnu.test"]                                         # 와일드카드 + 루트 도메인
    assert wait_serial(nginx.port, new.serial_number) == new.serial_number != old_n         # 실제 nginx(SSH+sudo 배포)가 새 인증서 서빙
    assert wait_serial(apache.port, new.serial_number) == new.serial_number != old_a        # 실제 Apache 도 서빙
    assert dig_txt(pebble.dns_port, "_acme-challenge.hnu.test") == ""                       # 검증 후 TXT 정리됨
    assert oct(os.stat(nginx.ssl / "site.key").st_mode & 0o777) == "0o600"

    # ② 아직 만료까지 여유 → 갱신 건너뜀(같은 인증서 유지, 재배포·재발급 없음)
    rc, out = cd(cfg, env, "renew")
    assert rc == 0, out
    assert "갱신 불필요" in out
    assert served(nginx.port).serial_number == new.serial_number

    # ③ 교체: 갱신 기준일을 넘긴 상황(renew_days 를 유효기간보다 크게) → 새로 발급해 두 서버 모두 교체
    cfg, env, state = write_cfg(tmp_path, pebble, [ssh_nginx_target(nginx, real_ssh), apache_target(apache)], renew_days=100000)
    rc, out = cd(cfg, env, "renew")
    assert rc == 0, out + (pebble.log.read_text()[-3000:])
    renewed = x509.load_pem_x509_certificate(issued[0].read_bytes())
    assert renewed.serial_number != new.serial_number
    assert wait_serial(nginx.port, renewed.serial_number) == renewed.serial_number
    assert wait_serial(apache.port, renewed.serial_number) == renewed.serial_number
    ok, why = openssl_verify(pebble, str(issued[0]))
    assert ok, why

    # ④ 상태·감사 기록
    rc, out = cd(cfg, env, "status")
    assert rc == 0 and "web-nginx" in out and "web-apache" in out, out
    logs = "".join(p.read_text() for p in (tmp_path / "audit").rglob("*") if p.is_file())
    assert "web-nginx" in logs and "web-apache" in logs, "감사 로그에 대상별 배포 기록이 남아야 함"
    assert "BEGIN" not in logs and "PRIVATE" not in logs                                  # 개인키·인증서 본문은 감사 로그에 남지 않음
    last = json.loads((state / "hnu" / "last-run.json").read_text())
    assert last, last


# ------------------------------------------------------------------ 2. 교체 중 한 서버 설정이 깨져 있으면: 그 서버는 롤백, 이전 인증서 계속 서빙
def test_real_acme_renew_with_broken_server_rolls_back_and_keeps_serving(tmp_path, pebble, nginx, apache, real_ssh):
    cfg, env, state = write_cfg(tmp_path, pebble, [ssh_nginx_target(nginx, real_ssh), apache_target(apache)])
    rc, out = cd(cfg, env, "issue")
    assert rc == 0, out
    first = served(apache.port).serial_number
    assert wait_serial(nginx.port, first) == first
    (nginx.tmp / "snippets/extra.conf").write_text("broken directive;\n")                  # 운영 중 누군가 nginx 설정을 깨뜨려 둔 상황
    cfg, env, state = write_cfg(tmp_path, pebble, [ssh_nginx_target(nginx, real_ssh), apache_target(apache)], renew_days=100000)
    rc, out = cd(cfg, env, "renew")
    assert rc != 0, out                                                                     # 실패를 종료 코드로 알림(타이머·감시가 감지)
    assert "롤백" in out or "rolled_back" in out or "실패" in out, out
    assert served(nginx.port).serial_number == first                                        # 깨진 서버는 이전 인증서 그대로 서빙
    (nginx.tmp / "snippets/extra.conf").write_text("# ok\n")


# ------------------------------------------------------------------ 3. DNS 권한이 틀리면(잘못된 TSIG) 발급 실패, 아무것도 바뀌지 않음
def test_real_acme_wrong_dns_key_fails_safely(tmp_path, pebble, apache):
    import base64
    bad = base64.b64encode(b"x" * 32).decode()
    cfg, env, state = write_cfg(tmp_path, pebble, [apache_target(apache)], tsig=bad)
    before = served(apache.port).serial_number
    rc, out = cd(cfg, env, "issue")
    assert rc != 0, out
    assert "발급 실패" in out, out
    assert served(apache.port).serial_number == before
    assert not [p for p in (state / "hnu").rglob("*.crt") if "staging" not in str(p)] if (state / "hnu").exists() else True
    # 직전 실패 후에는 대기(속도 제한 보호) — 실제 Let's Encrypt 에서 연속 실패로 차단당하지 않게
    rc, out = cd(cfg, env, "issue")
    assert "건너뜀" in out or rc != 0, out


# ------------------------------------------------------------------ 4. 발급된 인증서를 실제 Tomcat(JVM) 키스토어로 배포
@pytest.mark.skipif(not (shutil.which("keytool") and (CATALINA_HOME / "bin/catalina.sh").exists()), reason="Tomcat/JDK 없음")
def test_real_acme_issue_to_real_tomcat_keystore(tmp_path, pebble):
    from test_real_software import Site, wait_serving
    port, base = free_port(), tmp_path / "base"
    for d in ("conf", "logs", "temp", "work", "webapps", "ks"):
        (base / d).mkdir(parents=True)
    for f in ("web.xml", "logging.properties", "catalina.properties"):
        shutil.copy(Path("/etc/tomcat10") / f, base / "conf" / f)
    ks, pw = base / "ks/server.p12", "ks-Pass-123"
    (base / "conf/server.xml").write_text(f"""<Server port="-1"><Service name="Catalina">
 <Connector port="{port}" address="127.0.0.1" protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true">
  <SSLHostConfig><Certificate certificateKeystoreFile="{ks}" certificateKeystorePassword="{pw}" certificateKeystoreType="PKCS12" type="RSA"/></SSLHostConfig>
 </Connector>
 <Engine name="Catalina" defaultHost="localhost"><Host name="localhost" appBase="webapps"/></Engine></Service></Server>""")
    s = Site(tmp_path / "init", port) if (tmp_path / "init").mkdir() is None else None
    c, k = s.new_pki("initial")
    from certdeploy.bundle import load_bundle
    ks.write_bytes(load_bundle(c, k).pkcs12(pw, "tomcat"))
    envs = f"CATALINA_HOME={CATALINA_HOME} CATALINA_BASE={base} CATALINA_PID={base}/tomcat.pid JAVA_OPTS=-Xmx128m"
    restart = f"{envs} {CATALINA_HOME}/bin/catalina.sh stop 10 -force >/dev/null 2>&1; {envs} {CATALINA_HOME}/bin/catalina.sh start"
    subprocess.run(["bash", "-c", restart], capture_output=True)
    try:
        wait_serving(port, 60)
        t = {"name": "was-tomcat", "type": "tomcat", "format": "pkcs12", "keystore_path": str(ks), "password_env": "KS_PW", "alias": "tomcat",
             "reload_cmd": restart, "verify": {"host": "127.0.0.1", "port": port, "sni": "was.hnu.test"}}
        cfg, env, state = write_cfg(tmp_path, pebble, [t])
        rc, out = cd(cfg, env, "issue")
        assert rc == 0, out
        got = served(port)
        assert sans(got) == ["*.hnu.test", "hnu.test"]                                    # 실제 JVM 이 ACME 로 받은 인증서를 키스토어에서 읽어 서빙
        assert got.issuer.rfc4514_string() != got.subject.rfc4514_string()
    finally:
        subprocess.run(["bash", "-c", f"{envs} {CATALINA_HOME}/bin/catalina.sh stop 10 -force"], capture_output=True)


# ------------------------------------------------------------------ 5. 수동 TXT 방식(DNS 연동 없음): 안내 → 아직 미등록이면 대기 → DNS 담당자가 등록 → 재실행으로 발급
def nsupdate_txt(port, name, value, add=True):
    """DNS 담당자가 직접 TXT 를 등록/삭제하는 것을 실제 nsupdate 로 재현"""
    cmd = f"server 127.0.0.1 {port}\nzone hnu.test\nupdate {'add' if add else 'delete'} {name}. 60 TXT \"{value}\"\nsend\n"
    r = subprocess.run(["nsupdate", "-y", f"hmac-sha256:acme-key:{SECRET}"], input=cmd, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(not shutil.which("nsupdate"), reason="nsupdate 없음")
def test_real_acme_manual_txt_two_step(tmp_path, pebble, apache):
    from certdeploy import acme
    cfg, env, state = write_cfg(tmp_path, pebble, [apache_target(apache)], dns_mode="manual")
    before = served(apache.port).serial_number
    rc, out = cd(cfg, env, "issue")
    assert rc == 4, out                                                                    # 4 = 사람이 TXT 등록하기를 기다리는 중
    assert "_acme-challenge.hnu.test" in out and "TXT" in out, out
    pend = acme.load_pending(str(state / "hnu"), "hnu")
    recs = acme.txt_records(pend)
    assert len(recs) == 2 and all(n.rstrip(".") == "_acme-challenge.hnu.test" for n, _ in recs)   # 와일드카드+루트 → 같은 이름에 값 2개
    for _, v in recs:
        assert v in out                                                                    # 안내 문구에 등록할 값이 그대로 나옴
    rc, out = cd(cfg, env, "issue")                                                        # 아직 등록 안 함 → 계속 대기, 아무것도 안 바뀜
    assert rc == 4 and served(apache.port).serial_number == before, out
    nsupdate_txt(pebble.dns_port, recs[0][0].rstrip("."), recs[0][1])                      # 하나만 등록 → 아직 부족
    rc, out = cd(cfg, env, "issue")
    assert rc == 4 and "아직 보이지 않는" in out, out
    nsupdate_txt(pebble.dns_port, recs[1][0].rstrip("."), recs[1][1])                      # 둘 다 등록 → 같은 주문으로 이어서 발급
    rc, out = cd(cfg, env, "issue")
    assert rc == 0 and "발급 완료" in out, out + pebble.log.read_text()[-2000:]
    assert "지워도 됩니다" in out and "_acme-challenge.hnu.test" in out, out                # 발급 후 TXT 정리 안내
    got = served(apache.port)
    assert got.serial_number != before and sans(got) == ["*.hnu.test", "hnu.test"]
    assert acme.load_pending(str(state / "hnu"), "hnu") is None                              # 대기 주문 정리됨


# ------------------------------------------------------------------ 6. 개인키 암호 보호 + 배포 승인: 발급 후 승인 대기 → 승인 → 배포(서버의 키는 평문)
def test_real_acme_with_key_encryption_and_approval(tmp_path, pebble, apache):
    extra = {"certificate": {"key_encryption": "passphrase", "key_password_env": "KEY_PW"}, "approval": {"required": True, "approvers": 1}}
    cfg, env, state = write_cfg(tmp_path, pebble, [apache_target(apache)], extra=extra)
    before = served(apache.port).serial_number
    rc, out = cd(cfg, env, "issue")
    assert "발급 완료" in out, out
    assert "승인" in out, out                                                               # 배포는 승인 대기
    assert served(apache.port).serial_number == before                                     # 승인 전에는 서버가 바뀌지 않음
    key_file = state / "hnu" / "managed" / "_.hnu.test.key"
    assert b"ENCRYPTED" in key_file.read_bytes()                                           # 관리 서버에 저장된 키는 암호화
    rc, out = cd(cfg, env, "approvals")
    assert rc == 0 and "승인 대기" in out or "대기" in out, out
    req_id = out.split()[0]
    rc, out = cd(cfg, env, "approve", req_id, "--by", "security-officer")
    assert rc == 0 and "승인 완료" in out, out
    rc, out = cd(cfg, env, "deploy")
    assert rc == 0, out
    issued = x509.load_pem_x509_certificate((state / "hnu" / "managed" / "_.hnu.test.crt").read_bytes())
    assert wait_serial(apache.port, issued.serial_number) == issued.serial_number
    deployed_key = (apache.ssl / "site.key").read_bytes()
    assert b"PRIVATE KEY" in deployed_key and b"ENCRYPTED" not in deployed_key            # 웹서버가 읽는 키는 평문(권한 600)
    rc, out = cd(cfg, env, "validate")
    assert rc == 0 and "암호화됨" in out, out
