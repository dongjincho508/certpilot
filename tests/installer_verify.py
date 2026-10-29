"""installer_harness.sh 가 같은 네임스페이스에서 실행하는 설치 결과 검증(시나리오별). 실패하면 AssertionError → 종료 코드 1."""
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

import yaml

scen, work = sys.argv[1], sys.argv[2]
rd = lambda p: open(p, encoding="utf-8").read()  # noqa: E731
mode = lambda p: stat.S_IMODE(os.stat(p).st_mode)  # noqa: E731
owner = lambda p: pwd.getpwuid(os.stat(p).st_uid).pw_name if os.stat(p).st_uid != 65534 else "65534"  # noqa: E731
rc = lambda n: int(rd(f"{work}/rc{n}").strip())  # noqa: E731
SUM, LOG = "/root/cert-install-summary.txt", "/var/log/cert-install.log"
STEPS = "preflight base docker source monitoring nginx certdeploy admin verify".split()
MON = "/opt/cert-monitor/src/monitoring"
out1 = rd(f"{work}/install1.out")


def secrets_in_summary():
    s = rd(SUM)
    g = re.search(r"admin / 비밀번호 (\S+)", s).group(1)
    a = re.search(r"계정 \S+ / 비밀번호 (\S+)", s.split("관리자 화면")[1]).group(1)
    b = re.search(r"백업 비밀번호.*\): (\S+)", s)
    return g, a, (b.group(1) if b else None)


def check_full():
    assert rc(1) == 0, out1[-800:]
    assert mode(SUM) == 0o600 and owner(SUM) == "root"
    g, a, b = secrets_in_summary()
    assert len(g) >= 20 and len(a) >= 20 and b and len(b) >= 20, "비밀번호 자동 생성"
    log = rd(LOG)
    for s in (g, a, b):
        assert s not in log, "생성된 비밀번호가 로그에 남음"
    assert os.path.exists(f"/var/lib/cert-install/{STEPS[-1]}.done") and all(os.path.exists(f"/var/lib/cert-install/{s}.done") for s in STEPS)
    # 감시 스택
    env = rd(f"{MON}/.env")
    assert mode(f"{MON}/.env") == 0o600 and f"GRAFANA_ADMIN_PASSWORD={g}" in env and "GRAFANA_ROOT_URL=https://mgmt.hnu.kr" in env
    am = yaml.safe_load(rd(f"{MON}/alertmanager/alertmanager.local.yml"))
    recips = {e["to"] for r in am["receivers"] for e in r.get("email_configs", [])}
    assert recips == {"a@hnu.kr,b@hnu.kr"} and am["global"]["smtp_smarthost"] == "smtp.hnu.kr:587" and "smtp_auth_username" in am["global"]
    assert any(r["name"] == "ops-critical" and "webhook_configs" not in r for r in am["receivers"]), "웹훅 미사용 시 제거"
    sd = f"{MON}/alertmanager/secrets"
    assert mode(sd) == 0o700 and os.stat(sd).st_uid == 65534
    for f in os.listdir(sd):
        assert mode(f"{sd}/{f}") == 0o600 and os.stat(f"{sd}/{f}").st_uid == 65534
    assert rd(f"{sd}/smtp_password").strip() == "smtp-secret-pw", "SMTP 비밀번호는 환경변수로 전달"
    ov = yaml.safe_load(rd(f"{MON}/docker-compose.override.yml"))
    assert "alertmanager.local.yml" in ov["services"]["alertmanager"]["volumes"][0]
    assert os.path.exists(f"{MON}/prometheus/targets/servers.yml")
    # nginx
    for n in ("grafana", "certdeploy-admin"):
        c = rd(f"/etc/nginx/conf.d/{n}.conf")
        assert "mgmt.hnu.kr" in c and "univ.example" not in c and "/etc/pki/tls/certs/mgmt.crt" in c
    assert mode("/etc/pki/tls/private/mgmt.key") == 0o600
    subprocess.run(["openssl", "x509", "-in", "/etc/pki/tls/certs/mgmt.crt", "-noout", "-subject"], check=True, capture_output=True)
    # certdeploy + 관리자 화면 설정
    ae = rd("/etc/certdeploy/admin.env")
    assert mode("/etc/certdeploy/admin.env") == 0o600 and owner("/etc/certdeploy/admin.env") == "certdeploy"
    assert f"CERTPILOT_ADMIN_PASSWORD={a}" in ae and "CERTPILOT_REQUIRE_MFA=1" in ae and "CERTPILOT_ADMIN_USER=certadmin2" in ae
    assert mode("/etc/certdeploy/env") == 0o600 and owner("/etc/certdeploy/env") == "certdeploy"
    assert os.path.exists("/var/lib/certdeploy/.ssh/id_ed25519.pub") and mode("/var/lib/certdeploy/.ssh") == 0o700
    for u in ("certdeploy-admin.service", "certdeploy-renew.service", "certdeploy-renew.timer", "certdeploy-discover.timer", "certdeploy-backup.timer"):
        assert os.path.exists(f"/etc/systemd/system/{u}"), u
    # 설정 파일을 실제 로더로 검증 + 백업 설정/비밀번호
    sys.path.insert(0, "/opt/cert-monitor/src")
    from certdeploy.config import load_config
    cfg = load_config("/etc/certdeploy/certdeploy.yml")
    assert cfg.backup and cfg.backup["copy_to"][0]["path"] == "/mnt/nas/cd" and cfg.backup["passphrase_env"] == "CERTDEPLOY_BACKUP_PASSPHRASE"
    assert rd("/etc/certdeploy/certdeploy.yml").count("\nbackup:") == 1
    be = rd("/etc/certdeploy/backup.env")
    assert mode("/etc/certdeploy/backup.env") == 0o600 and f"CERTDEPLOY_BACKUP_PASSPHRASE={b}" in be
    disc = yaml.safe_load(rd("/etc/certdeploy/discovery.yml"))
    from certdeploy.discover_cli import CONFIG_KEYS
    assert set(disc) <= CONFIG_KEYS and disc["cidr"] == ["10.10.0.0/24", "10.20.0.0/24"]
    # 설치된 venv 의 certdeploy 실행
    v = subprocess.run(["/opt/certdeploy/venv/bin/certdeploy", "--version"], capture_output=True, text=True)
    assert v.returncode == 0, v.stderr
    # 설치 결과로 실제 백업 실행(설정·비밀번호·경로가 서로 맞는지)
    env_ = {**os.environ, "CERTDEPLOY_BACKUP_PASSPHRASE": b}
    os.makedirs("/mnt/nas/cd", exist_ok=True)
    r = subprocess.run(["/opt/certdeploy/venv/bin/certdeploy", "-c", "/etc/certdeploy/certdeploy.yml", "backup-run"], capture_output=True, text=True, env=env_)
    assert r.returncode == 0, r.stdout + r.stderr
    assert any(f.endswith(".cdbk") for f in os.listdir("/var/backups/certdeploy")) and any(f.endswith(".cdbk") for f in os.listdir("/mnt/nas/cd"))
    from certdeploy import backup as bk
    names = {m["name"] for m in bk.list_members(open(os.path.join("/var/backups/certdeploy", sorted(f for f in os.listdir("/var/backups/certdeploy") if f.endswith(".cdbk"))[0]), "rb").read(), b)}
    assert "monitoring/.env" in names and "etc/certdeploy/admin.env" in names and "monitoring/alertmanager/secrets/smtp_password" in names
    # 관리자 화면: 설치가 만든 설정으로 실제 서버 기동 → 로그인 → 설정·운영 API
    envf = dict(l.split("=", 1) for l in ae.strip().splitlines())
    srv = subprocess.Popen(["/opt/certdeploy/venv/bin/python", "-m", "gunicorn", "--workers", "1", "--bind", "127.0.0.1:18199", "certpilot_api.app:create_app()"],
                           env={**os.environ, **envf, "CERTPILOT_DATA_DIR": os.path.join(work, "admin-data"), "CERTPILOT_SECURE_COOKIE": "0"}, cwd="/opt/cert-monitor/src",
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            try:
                urllib.request.urlopen("http://127.0.0.1:18199/health", timeout=2).read()
                break
            except OSError:
                time.sleep(0.5)
        else:
            raise AssertionError("관리자 화면이 기동되지 않음")
        import http.cookiejar
        cj = http.cookiejar.CookieJar()
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        req = urllib.request.Request("http://127.0.0.1:18199/auth/login", data=json.dumps({"username": "certadmin2", "password": a}).encode(), headers={"Content-Type": "application/json"})
        assert json.loads(op.open(req).read())["role"] == "admin"
        mfa = json.loads(op.open("http://127.0.0.1:18199/auth/mfa").read())
        assert mfa["required"] is True and mfa["enabled"] is False
        try:
            op.open("http://127.0.0.1:18199/certdeploy/overview")
            raise AssertionError("2단계 인증 등록 전에는 다른 기능이 막혀야 함")
        except urllib.error.HTTPError as e:
            assert e.code == 403 and b"mfa_enrollment_required" in e.read()
        post = lambda path, body: json.loads(op.open(urllib.request.Request("http://127.0.0.1:18199" + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})).read())  # noqa: E731
        secret = post("/auth/mfa/setup", {"password": a})["secret"]
        sys.path.insert(0, "/opt/cert-monitor/src")
        from certpilot_core import totp
        assert len(post("/auth/mfa/enable", {"code": totp.code_at(secret, time.time())})["recovery_codes"]) == 10
        ov = json.loads(op.open("http://127.0.0.1:18199/certdeploy/overview").read())
        assert ov["configured"] is True
        bkv = json.loads(op.open("http://127.0.0.1:18199/certdeploy/backup").read())
        assert bkv["configured"] and bkv["last"] and bkv["last"]["ok"]
    finally:
        srv.terminate()
        srv.wait(timeout=10)
    # 가짜 시스템 명령 호출 순서
    calls = [l.split()[0:3] for l in rd(f"{work}/stub.log").splitlines()]
    flat = [" ".join(c) for c in calls]
    assert any("docker run --rm" in c for c in flat) and flat.index(next(c for c in flat if c.startswith("docker run --rm"))) < flat.index(next(c for c in flat if c.startswith("docker compose")))
    stub = rd(f"{work}/stub.log")
    assert "firewall-cmd --permanent --add-rich-rule=rule family=\"ipv4\" source address=\"10.10.0.0/24\"" in stub
    assert "systemctl enable --now certdeploy-backup.timer" in stub and "systemctl enable --now certdeploy-discover.timer" in stub and "systemctl enable --now certdeploy-renew.timer" in stub
    assert "setsebool -P httpd_can_network_connect on" in stub and "hostnamectl set-hostname mgmt.hnu.kr" in stub


def check_rerun():
    assert rc(1) == 0 and rc(2) == 0
    out2 = rd(f"{work}/install2.out")
    assert out2.count("이미 완료(건너뜀") == 8, out2[-600:]          # verify 외 8단계는 건너뜀
    g, a, b = secrets_in_summary()
    assert f"GRAFANA_ADMIN_PASSWORD={g}" in rd(f"{MON}/.env")           # 두 번째 실행이 비밀번호를 바꾸지 않음
    assert f"CERTPILOT_ADMIN_PASSWORD={a}" in rd("/etc/certdeploy/admin.env")
    assert rd("/etc/certdeploy/certdeploy.yml").count("\nbackup:") == 1
    stub = rd(f"{work}/stub.log")
    assert stub.count("docker run --rm hello-world") == 1 and stub.count("dnf -y install docker-ce") == 1
    # --force 로 단계를 다시 실행해도 기존 비밀번호·설정은 유지
    r = subprocess.run(["bash", "/home/user/certpilot/scripts/install-mgmt-server.sh", "--yes", "--no-network-check", "--skip-update", "--local-src", "/home/user/certpilot",
                        "--force", "--only", "monitoring,admin,certdeploy", "--hostname", "mgmt.hnu.kr"], capture_output=True, text=True,
                       env={**os.environ, "PATH": os.environ.get("STUBDIR", "") + "/bin:" + os.environ["PATH"], "PIP_NO_INDEX": "1", "PIP_NO_BUILD_ISOLATION": "0"})
    assert r.returncode == 0, r.stdout[-500:] + r.stderr[-500:]
    assert f"GRAFANA_ADMIN_PASSWORD={g}" in rd(f"{MON}/.env") and f"CERTPILOT_ADMIN_PASSWORD={a}" in rd("/etc/certdeploy/admin.env")


def check_resume():
    assert rc(1) != 0, "docker 실패 시 중단되어야 함"
    assert "docker 시험 실패" in out1 or "오류" in out1 or rc(1) != 0
    done = rd(f"{work}/done_after_fail").split()
    assert sorted(done) == ["base.done", "preflight.done", "source.done"] or sorted(done) == ["base.done", "preflight.done"], done   # docker 이후 단계는 표시되지 않음
    assert "docker.done" not in done and "monitoring.done" not in done
    assert rc(2) == 0
    out2 = rd(f"{work}/install2.out")
    assert "preflight — 이미 완료" in out2 and "base — 이미 완료" in out2        # 끝난 단계는 건너뛰고 이어서 진행
    assert all(os.path.exists(f"/var/lib/cert-install/{s}.done") for s in STEPS)
    assert rd(f"{work}/stub.log").count("hostnamectl set-hostname") == 1


def check_minimal():
    assert rc(1) == 0, out1[-600:]
    assert "Alertmanager 설정은 예시 값 그대로" in out1                       # 메일 옵션이 없으면 경고
    assert not os.path.exists(f"{MON}/alertmanager/alertmanager.local.yml") and not os.path.exists(f"{MON}/docker-compose.override.yml")
    s = rd(SUM)
    assert "백업 비밀번호" not in s and not os.path.exists("/etc/certdeploy/backup.env")
    assert "CERTPILOT_REQUIRE_MFA=0" in rd("/etc/certdeploy/admin.env")
    assert mode("/etc/certdeploy/admin.env") == 0o600


def check_notrocky():
    assert rc(1) != 0 and "Rocky Linux 10" in out1
    assert not os.path.exists("/etc/certdeploy") and not os.path.exists("/var/lib/cert-install/base.done")


{"full": check_full, "rerun": check_rerun, "resume": check_resume, "minimal": check_minimal, "notrocky": check_notrocky}[scen]()
print("INSTALL_VERIFY_OK", scen)
