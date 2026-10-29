"""백업 자동화: 설정 검증, 수집(SQLite 일관 스냅샷·제외·누락 보고), 암호화·검증, 보관 정리(GFS), 외부 복사(폴더/SSH), 상태·지표, CLI, 복구, 관리자 화면"""
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from certdeploy import backup as bk, backupjob as bj
from certdeploy.cli import main
from certdeploy.config import ConfigError, load_config, parse_config
from certdeploy.transport import LocalTransport
from pki_helpers import make_pki

ROOT = Path(__file__).resolve().parent.parent
PW = "backup-Pass-phrase-1"
NOW = datetime(2026, 10, 29, 2, 10, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------------ 가짜 관리 서버 파일 구조
class Box:
    def __init__(self, tmp, **backup_over):
        self.tmp = tmp
        self.etc, self.state, self.admin, self.mon = tmp / "etc/certdeploy", tmp / "var/lib/certdeploy", tmp / "var/lib/certdeploy-admin", tmp / "opt/monitoring"
        for d in (self.etc, self.state / "managed", self.admin, self.mon / "alertmanager/secrets", self.mon / "prometheus/targets", tmp / "nginx"):
            d.mkdir(parents=True, exist_ok=True)
        self.cert, self.key, _, _ = make_pki(self.state / "managed", name="hnu", san=("*.hnu.kr",), days_to=90)
        (self.etc / "env").write_text("SMTP_PASSWORD=secret\n")
        (self.etc / "admin.env").write_text("CERTPILOT_ADMIN_PASSWORD=x\n")
        (self.state / "settings.json").write_text('{"mail": {"enabled": false, "password": "p"}}')
        (self.state / "trace.jsonl").write_text("noise\n" * 10)
        (self.state / "lock").write_text("")
        (self.admin / "mfa.key").write_text("fernet-key")
        db = sqlite3.connect(self.admin / "certpilot.db")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE users (name TEXT)")
        db.executemany("INSERT INTO users VALUES (?)", [("alice",), ("bob",)])
        db.commit()
        self.db = db                                    # 열어 둔 채로 백업(운영 중 상태 흉내)
        (self.mon / ".env").write_text("GRAFANA_ADMIN_PASSWORD=g\n")
        (self.mon / "alertmanager/secrets/smtp_password").write_text("smtp-secret\n")
        (self.mon / "prometheus/targets/servers.yml").write_text("- targets: ['a:443']\n")
        (tmp / "nginx/grafana.conf").write_text("server {}\n")
        self.back = tmp / "backups"
        self.b = {"dir": str(self.back), "passphrase_env": "BK_PASS", "etc_dir": str(self.etc), "admin_data_dir": str(self.admin),
                  "monitoring_dir": str(self.mon), "nginx_files": [str(tmp / "nginx/grafana.conf"), str(tmp / "nginx/missing.conf")]}
        self.b.update(backup_over)
        self.cfgdoc = {"state_dir": str(self.state), "certificate": {"cert_file": str(self.cert), "key_file": str(self.key)},
                       "targets": [{"name": "w", "type": "apache", "cert_path": "/c", "key_path": "/k"}], "backup": self.b}
        self.cfgfile = self.etc / "certdeploy.yml"
        self.write()

    def write(self):
        self.cfgdoc["backup"] = self.b
        self.cfgfile.write_text(yaml.safe_dump(self.cfgdoc, allow_unicode=True))

    def cfg(self):
        return parse_config(self.cfgdoc)

    def run(self, now=NOW, **kw):
        c = self.cfg()
        return bj.run_backup(c, str(self.cfgfile), c.backup, PW, now=now, hostname="mgmt", **kw)


@pytest.fixture
def box(tmp_path, monkeypatch):
    monkeypatch.setenv("BK_PASS", PW)
    return Box(tmp_path)


# ------------------------------------------------------------------ 설정
def test_config_parse_defaults(box):
    b = box.cfg().backup
    assert b["keep_daily"] == 7 and b["keep_weekly"] == 4 and b["keep_monthly"] == 6 and b["verify"] is True
    assert "trace.jsonl" in b["exclude"]


@pytest.mark.parametrize("over,msg", [
    ({"passphrase_env": None}, "passphrase"), ({"dir": "relative"}, "절대 경로"), ({"keep_daily": -1}, "keep_daily"), ({"keep_weekly": 9999}, "keep_weekly"),
    ({"bogus": 1}, "알 수 없는 키"), ({"include": ["rel/path"]}, "절대 경로"), ({"verify": "yes"}, "verify"),
    ({"copy_to": [{"kind": "ftp", "path": "/x"}]}, "kind"), ({"copy_to": [{"kind": "ssh", "path": "/x", "host": "h"}]}, "known_hosts"),
    ({"copy_to": [{"kind": "dir", "path": "x"}]}, "절대 경로"),
    ({"copy_to": [{"kind": "dir", "name": "a", "path": "/x"}, {"kind": "dir", "name": "a", "path": "/y"}]}, "중복"),
])
def test_config_errors(box, over, msg):
    box.b.update(over)
    with pytest.raises(ConfigError, match=msg):
        box.cfg()


def test_passphrase_sources(tmp_path, monkeypatch):
    b = {"passphrase_env": "NOPE", "passphrase_file": None}
    with pytest.raises(bk.BackupError):
        bj.passphrase_of(b, {})
    f = tmp_path / "pw"
    f.write_text("file-passphrase-12\n")
    f.chmod(0o644)
    with pytest.raises(bk.BackupError, match="권한"):
        bj.passphrase_of({"passphrase_env": None, "passphrase_file": str(f)}, {})
    f.chmod(0o600)
    assert bj.passphrase_of({"passphrase_env": None, "passphrase_file": str(f)}, {}) == "file-passphrase-12"
    assert bj.passphrase_of(b, {"NOPE": "from-env-pass-12"}) == "from-env-pass-12"


# ------------------------------------------------------------------ 수집·암호화
def test_sqlite_snapshot_is_consistent(box):
    snap = bj.snapshot_sqlite(str(box.admin / "certpilot.db"))
    p = box.tmp / "snap.db"
    p.write_bytes(snap)
    assert [r[0] for r in sqlite3.connect(p).execute("SELECT name FROM users ORDER BY name")] == ["alice", "bob"]


def test_run_backup_contents_and_encryption(box):
    r = box.run()
    assert r.ok and r.verified and not r.partial and r.members > 8, r.error
    path = box.back / r.name
    assert oct(path.stat().st_mode & 0o777) == "0o600" and r.name == "certdeploy-20261029-021000.cdbk"
    blob = path.read_bytes()
    names = {m["name"] for m in bk.list_members(blob, PW)}
    for want in ("manifest.json", "etc/certdeploy/env", "etc/certdeploy/admin.env", "state/settings.json", "state/managed/hnu.key",
                 "admin-data/certpilot.db", "admin-data/mfa.key", "monitoring/.env", "monitoring/alertmanager/secrets/smtp_password",
                 "monitoring/prometheus/targets/servers.yml", "nginx/" + str(box.tmp / "nginx/grafana.conf").lstrip("/").replace("/", "__")):
        assert want in names, want
    assert not any("trace.jsonl" in n or n.endswith("/lock") for n in names)                 # 제외 패턴
    assert b"smtp-secret" not in blob and b"BEGIN" not in blob                               # 평문 노출 없음
    with pytest.raises(bk.BackupError):
        bk.list_members(blob, "wrong-passphrase-123")
    bad = bytearray(blob)
    bad[-5] ^= 1
    with pytest.raises(bk.BackupError, match="변조"):
        bk.list_members(bytes(bad), PW)
    side = json.loads((box.back / (r.name + ".manifest.json")).read_text())
    import hashlib
    assert side["sha256"] == hashlib.sha256(blob).hexdigest() and side["size"] == len(blob) and side["partial"] is False


def test_db_in_backup_is_loadable_and_manifest_has_origins(box):
    r = box.run()
    blob = (box.back / r.name).read_bytes()
    mf = json.loads(bk.read_member(blob, PW, "manifest.json"))
    assert mf["host"] == "mgmt" and mf["origin"]["admin-data/certpilot.db"]["path"].endswith("certdeploy-admin/certpilot.db")
    db = box.tmp / "restored.db"
    db.write_bytes(bk.read_member(blob, PW, "admin-data/certpilot.db"))
    assert sqlite3.connect(db).execute("SELECT count(*) FROM users").fetchone()[0] == 2


def test_unreadable_items_make_partial_not_failure(box):
    (box.state / "weird-link").symlink_to("/etc/hostname")
    r = box.run()
    assert r.ok and r.partial and any("weird-link" in s for s in r.skipped)
    assert json.loads((box.back / (r.name + ".manifest.json")).read_text())["partial"] is True


def test_nothing_to_backup_fails_cleanly(tmp_path, monkeypatch):
    monkeypatch.setenv("BK_PASS", PW)
    b = Box(tmp_path)
    for d in (b.etc, b.state, b.admin, b.mon):
        import shutil
        shutil.rmtree(d)
    (tmp_path / "nginx/grafana.conf").unlink()
    r = b.run()
    assert not r.ok and "대상이 하나도 없" in r.error


# ------------------------------------------------------------------ 보관 정리
def names_for(days, hour=2):
    base = datetime(2026, 10, 29, hour, 10, tzinfo=timezone.utc)
    return [f"certdeploy-{(base - timedelta(days=d)):%Y%m%d-%H%M%S}.cdbk" for d in range(days)]


def test_gfs_retention_rules():
    names = names_for(200)
    keep = bj.to_keep(names, 7, 4, 6)
    assert names[0] in keep and len(keep) <= 7 + 4 + 6 and len(keep) >= 7
    assert set(names[:7]) <= set(keep)                                   # 최근 7일은 전부
    assert bj.to_keep(names, 0, 0, 0) == [names[0]]                       # 설정이 0 이어도 가장 최근 1개는 남긴다
    assert bj.to_keep(["junk.txt", "certdeploy-bad.cdbk"], 7, 4, 6) == []
    twice = names_for(3) + [f"certdeploy-20261029-{h}0000.cdbk" for h in ("03", "04")]
    assert len([n for n in bj.to_keep(twice, 1, 0, 0)]) == 1               # 같은 날 여러 개면 가장 최근 1개만 '일' 몫


def test_repeated_runs_prune_old_files_and_sidecars(box):
    box.b.update(keep_daily=3, keep_weekly=0, keep_monthly=0)
    for d in range(10):
        r = box.run(now=NOW + timedelta(days=d))
        assert r.ok
    files = sorted(p.name for p in box.back.iterdir())
    assert len([f for f in files if f.endswith(".cdbk")]) == 3 and len([f for f in files if f.endswith(".manifest.json")]) == 3
    assert files[-2].startswith("certdeploy-20261107")
    (box.back / "my-notes.txt").write_text("keep me")
    box.run(now=NOW + timedelta(days=11))
    assert (box.back / "my-notes.txt").exists()                            # 우리 이름이 아닌 파일은 건드리지 않음


# ------------------------------------------------------------------ 외부 복사
def test_copy_to_dir_and_failure_isolation(box, tmp_path):
    ok_dir, blocked = tmp_path / "nas", tmp_path / "blocked"
    blocked.write_text("a file, not a dir")
    box.b["copy_to"] = [{"kind": "dir", "name": "nas", "path": str(ok_dir)}, {"kind": "dir", "name": "bad", "path": str(blocked / "sub")}]
    r = box.run()
    assert (box.back / r.name).exists() and (ok_dir / r.name).exists()      # 한 곳이 실패해도 로컬·다른 외부 복사는 유지
    assert not r.ok and "bad" in r.error
    assert [c["ok"] for c in r.copies] == [True, False]
    assert (box.back / r.name).read_bytes() == (ok_dir / r.name).read_bytes()
    assert oct((ok_dir / r.name).stat().st_mode & 0o777) == "0o600"


def test_copy_to_ssh_store_with_pruning(box, tmp_path):
    remote = tmp_path / "remote-backups"
    box.b.update(keep_daily=2, keep_weekly=0, keep_monthly=0)
    box.b["copy_to"] = [{"kind": "ssh", "name": "off", "host": "backup.hnu.kr", "user": "bk", "known_hosts": "/kh", "path": str(remote)}]
    for d in range(4):
        r = box.run(now=NOW + timedelta(days=d), ssh_factory=lambda spec: LocalTransport())
        assert r.ok, r.copies
    assert len([p for p in remote.iterdir() if p.name.endswith(".cdbk")]) == 2 and oct(next(remote.iterdir()).stat().st_mode & 0o777) == "0o600"


def test_ssh_connect_failure_is_reported(box):
    from certdeploy.transport import TransportError
    box.b["copy_to"] = [{"kind": "ssh", "name": "off", "host": "x.hnu.kr", "user": "u", "known_hosts": "/kh", "path": "/r"}]

    def boom(spec):
        raise TransportError("연결 실패")
    r = box.run(ssh_factory=boom)
    assert not r.ok and r.copies[0]["ok"] is False and "연결 실패" in r.copies[0]["error"] and (box.back / r.name).exists()


# ------------------------------------------------------------------ 지표·상태
def test_metrics_text_and_status_roundtrip(box):
    r = box.run()
    m = bj.metrics_text(r)
    assert "certdeploy_backup_ok 1" in m and "certdeploy_backup_last_success_timestamp_seconds" in m and "certdeploy_backup_partial 0" in m
    bj.save_status(str(box.state), r)
    st = bj.load_status(str(box.state))
    assert st["ok"] and st["name"] == r.name and st["partial"] is False
    box.b["copy_to"] = [{"kind": "dir", "name": "x", "path": str(box.tmp / "f" / "g")}]
    (box.tmp / "f").write_text("file")
    bad = box.run(now=NOW + timedelta(days=1))
    mb = bj.metrics_text(bad)
    assert "certdeploy_backup_ok 0" in mb and "last_success" not in mb and "copies_failed 1" in mb


# ------------------------------------------------------------------ CLI
class Sink(BaseHTTPRequestHandler):
    bodies = []

    def do_POST(self):
        Sink.bodies.append((self.path, self.rfile.read(int(self.headers["Content-Length"])).decode()))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def cli(box, *args):
    return CliRunner().invoke(main, ["-c", str(box.cfgfile), *args])


def test_cli_run_status_list_verify(box):
    srv = HTTPServer(("127.0.0.1", 0), Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    Sink.bodies = []
    box.cfgdoc["notify"] = {"pushgateway_url": f"http://127.0.0.1:{srv.server_port}"}
    box.write()
    try:
        r = cli(box, "backup-run")
        assert r.exit_code == 0 and "백업 완료" in r.output, r.output
        assert any(p == "/metrics/job/certdeploy/cert/backup" and "certdeploy_backup_ok 1" in b for p, b in Sink.bodies)
    finally:
        srv.shutdown()
    assert cli(box, "backup-status").exit_code == 0
    lst = cli(box, "backup-list")
    assert lst.exit_code == 0 and "certdeploy-" in lst.output and "총 1개" in lst.output
    v = cli(box, "backup-verify", "--deep")
    assert v.exit_code == 0 and "복호화·목록 확인 OK" in v.output and "무결성 OK" in v.output and "hnu.crt: OK" in v.output, v.output
    assert cli(box, "backup-run", "--quiet").exit_code == 0


def test_cli_failure_exit_codes_and_missing_config(box, monkeypatch):
    monkeypatch.delenv("BK_PASS")
    r = cli(box, "backup-run")
    assert r.exit_code != 0 and "비밀번호" in r.output
    monkeypatch.setenv("BK_PASS", PW)
    assert cli(box, "backup-status").exit_code == 1                         # 기록 없음
    box.cfgdoc.pop("backup")
    box.cfgfile.write_text(yaml.safe_dump(box.cfgdoc, allow_unicode=True))
    r2 = cli(box, "backup-run")
    assert r2.exit_code != 0 and "backup:" in r2.output


def test_cli_verify_wrong_passphrase_and_corruption(box, monkeypatch):
    cli(box, "backup-run")
    monkeypatch.setenv("BK_PASS", "another-wrong-pass-9")
    v = cli(box, "backup-verify")
    assert v.exit_code == 1 and "복호화 실패" in v.output
    monkeypatch.setenv("BK_PASS", PW)
    f = next(box.back.glob("*.cdbk"))
    data = bytearray(f.read_bytes())
    data[100] ^= 0xFF
    f.write_bytes(bytes(data))
    assert cli(box, "backup-verify").exit_code == 1


def test_deep_verify_detects_key_mismatch(box):
    other = make_pki(box.tmp, name="other", san=("x.hnu.kr",))[1]
    (box.state / "managed" / "hnu.key").write_bytes(Path(other).read_bytes())          # 인증서와 다른 키
    r = box.run()
    rep = bj.deep_verify((box.back / r.name).read_bytes(), PW)
    assert rep["problems"] and any("hnu.crt" in p for p in rep["problems"])


# ------------------------------------------------------------------ 복구
def test_restore_plan_apply_and_preservation(box, tmp_path):
    r = box.run()
    blob = (box.back / r.name).read_bytes()
    fake_root = tmp_path / "newvm"
    plan = bj.restore_apply(blob, PW, str(fake_root), dry_run=True)
    assert not fake_root.exists() and any(p["archive"] == "etc/certdeploy" for p in plan)
    (fake_root / "etc/certdeploy").mkdir(parents=True)
    (fake_root / "etc/certdeploy/env").write_text("OLD")
    applied = bj.restore_apply(blob, PW, str(fake_root), dry_run=False)
    dest_env = fake_root / str(box.etc).lstrip("/") / "env"
    assert dest_env.read_text() == "SMTP_PASSWORD=secret\n"
    assert (fake_root / str(box.state).lstrip("/") / "managed/hnu.key").read_bytes() == box.key.read_bytes()
    db = sqlite3.connect(fake_root / str(box.admin).lstrip("/") / "certpilot.db")
    assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 2
    assert applied and (fake_root / str(box.mon).lstrip("/") / "alertmanager/secrets/smtp_password").read_text() == "smtp-secret\n"
    again = bj.restore_apply(blob, PW, str(fake_root), dry_run=False)           # 두 번째 적용: 기존 파일은 .pre-restore 로 보존
    assert again and any(".pre-restore-" in p.name for p in (fake_root / str(box.etc).lstrip("/")).parent.iterdir())


def test_restore_cli_requires_apply_flag(box, tmp_path):
    r = box.run()
    f = box.back / r.name
    plan = cli(box, "backup-restore", "--file", str(f), "--root", str(tmp_path / "x"))
    assert plan.exit_code == 0 and "복구 예정" in plan.output and not (tmp_path / "x").exists()
    done = cli(box, "backup-restore", "--file", str(f), "--root", str(tmp_path / "x"), "--apply")
    assert done.exit_code == 0 and "복구 완료" in done.output and (tmp_path / "x").exists()


def test_malicious_archive_is_rejected(tmp_path):
    evil = tmp_path / "e.txt"
    evil.write_text("x")
    blob = bk.create_backup({"../escape": str(evil)}, PW, extra={"manifest.json": b"{}"})
    with pytest.raises(bk.BackupError, match="경로 이탈"):
        bk.list_members(blob, PW)
    with pytest.raises(bk.BackupError):
        bj.restore_apply(blob, PW, str(tmp_path / "root"), dry_run=False)
    assert not (tmp_path / "escape").exists()


# ------------------------------------------------------------------ 관리자 화면·배포 파일
def test_admin_overview_and_endpoint(box, tmp_path, sandbox):
    from certdeploy import adminapi
    assert adminapi.backup_overview(str(box.cfgfile))["last"] is None
    r = box.run()
    bj.save_status(str(box.state), r)
    ov = adminapi.backup_overview(str(box.cfgfile))
    assert ov["configured"] and ov["last"]["ok"] and ov["stale"] is False
    assert ov["backups"][0]["name"] == r.name and PW not in json.dumps(ov)
    from certpilot_api.app import create_app
    from certpilot_core.remote import SandboxExecutor
    pw = "Str0ng!Passw0rd"
    app = create_app({"DATA_DIR": str(tmp_path / "data"), "ADMIN_USER": "root1", "ADMIN_PASSWORD": pw, "SECURE_COOKIE": False,
                      "CERTDEPLOY_CONFIG": str(box.cfgfile)}, executor_factory=lambda t: SandboxExecutor(sandbox.path))
    c = app.test_client()
    assert c.get("/certdeploy/backup").status_code == 401
    c.post("/auth/login", json={"username": "root1", "password": pw})
    assert c.get("/certdeploy/backup").json["configured"] is True
    c.post("/users", json={"username": "op1", "password": "An0ther!Passw0rd", "role": "operator"})
    op = app.test_client()
    op.post("/auth/login", json={"username": "op1", "password": "An0ther!Passw0rd"})
    assert op.get("/certdeploy/backup").status_code == 403


def test_not_configured_overview(box):
    from certdeploy import adminapi
    box.cfgdoc.pop("backup")
    box.cfgfile.write_text(yaml.safe_dump(box.cfgdoc))
    assert adminapi.backup_overview(str(box.cfgfile)) == {"configured": False}


def test_units_example_and_frontend():
    svc = (ROOT / "certdeploy/systemd/certdeploy-backup.service").read_text()
    assert "backup-run" in svc and "User=root" in svc and "ProtectSystem=strict" in svc and "EnvironmentFile=/etc/certdeploy/backup.env" in svc
    assert "OnCalendar" in (ROOT / "certdeploy/systemd/certdeploy-backup.timer").read_text()
    html = (ROOT / "frontend/templates/index.html").read_text()
    js = (ROOT / "frontend/js/app.js").read_text()
    assert 'id="cd-bk-body"' in html and "/certdeploy/backup" in js and "loadBackup" in js
    r = yaml.safe_load((ROOT / "monitoring/prometheus/rules/certdeploy.yml").read_text())
    assert {"CertBackupFailed", "CertBackupStale", "CertBackupNotRunning", "CertBackupPartial"} <= {x["alert"] for g in r["groups"] for x in g["rules"]}


def test_malformed_settings_json_gives_clear_error(box):
    (box.state / "settings.json").write_text('{"mail": {"password": "p"}}')
    with pytest.raises(ConfigError, match="settings.json"):
        load_config(str(box.cfgfile))


def test_multi_cert_config_backs_up_global_state_once(tmp_path, monkeypatch):
    """인증서가 여러 개일 때: 전역 상태 폴더(settings.json·.ssh)와 인증서별 폴더가 모두, 한 번씩 들어가고, 아직 발급 전이어도 검증이 통과한다."""
    monkeypatch.setenv("BK_PASS", PW)
    b = Box(tmp_path)
    (b.state / ".ssh").mkdir()
    (b.state / ".ssh/id_ed25519").write_text("PRIVATE")
    b.cfgdoc.pop("certificate"), b.cfgdoc.pop("targets")
    b.cfgdoc["certificates"] = [{"name": n, "certificate": {"cert_file": str(b.cert), "key_file": str(b.key)},
                                 "targets": [{"name": "w", "type": "apache", "cert_path": "/c", "key_path": "/k"}]} for n in ("hnu", "hannam")]
    (b.state / "hnu").mkdir()
    (b.state / "hnu/state.json").write_text("{}")
    r = b.run()
    assert r.ok and r.verified, r.error
    names = [m["name"] for m in bk.list_members((b.back / r.name).read_bytes(), PW)]
    assert "state/settings.json" in names and "state/.ssh/id_ed25519" in names and "state/hnu/state.json" in names
    assert len(names) == len(set(names))                                          # 중복 없음


def test_backup_dir_inside_state_dir_is_not_recursed(tmp_path, monkeypatch):
    monkeypatch.setenv("BK_PASS", PW)
    b = Box(tmp_path)
    b.b["dir"] = str(b.state / "backups")
    first = b.run()
    second = b.run(now=NOW + timedelta(days=1))
    names = [m["name"] for m in bk.list_members((b.state / "backups" / second.name).read_bytes(), PW)]
    assert first.ok and second.ok and not any("backups" in n for n in names)
