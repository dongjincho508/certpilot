from datetime import datetime, timedelta

import pytest

from certpilot_api.app import create_app
from certpilot_core.remote import FailureCause, RemoteError, SandboxExecutor
from conftest import make_cert, pem

PW = "Str0ng!Passw0rd"


@pytest.fixture
def ctx(tmp_path, sandbox):
    clock = {"now": datetime(2026, 10, 28, 12, 0, 0)}
    app = create_app(
        {"DATA_DIR": str(tmp_path / "data"), "ADMIN_USER": "root1", "ADMIN_PASSWORD": PW,
         "SECURE_COOKIE": False, "max_failures": 3},
        executor_factory=lambda t: SandboxExecutor(sandbox.path),
        clock=lambda: clock["now"], sleep=lambda s: None)
    return type("Ctx", (), {"app": app, "box": sandbox, "clock": clock, "client": app.test_client})


def login(c, user="root1", pw=PW):
    r = c.post("/auth/login", json={"username": user, "password": pw})
    return r


def admin(ctx):
    c = ctx.client()
    assert login(c).status_code == 200
    return c


def test_health_public(ctx):
    assert ctx.client().get("/health").json["status"] == "ok"


def test_index_and_static_public(ctx):
    c = ctx.client()
    assert c.get("/").status_code == 200
    for path in ("/static/css/app.css", "/static/js/app.js", "/static/js/theme.js",
                 "/static/vendor/flatly.min.css", "/static/vendor/darkly.min.css",
                 "/static/vendor/bootstrap.bundle.min.js", "/static/vendor/bootstrap-icons.min.css",
                 "/static/vendor/fonts/bootstrap-icons.woff2"):
        assert c.get(path).status_code == 200, path


@pytest.mark.parametrize("method,path", [
    ("get", "/servers"), ("post", "/servers"), ("get", "/audit-logs"), ("get", "/users"),
    ("get", "/export.csv"), ("post", "/scan"),
])
def test_requires_login(ctx, method, path):  # S-6
    assert getattr(ctx.client(), method)(path).status_code == 401


def test_login_and_session_cookie(ctx):
    c = ctx.client()
    r = login(c)
    assert r.status_code == 200 and r.json["role"] == "admin"
    assert "HttpOnly" in r.headers["Set-Cookie"] and "SameSite=Strict" in r.headers["Set-Cookie"]
    assert c.get("/auth/me").json["username"] == "root1"


def test_login_wrong_password_and_lockout(ctx):
    c = ctx.client()
    for _ in range(3):
        assert login(c, pw="wrong").status_code == 401
    assert login(c).status_code == 423  # 올바른 비밀번호여도 잠금
    ctx.clock["now"] += timedelta(minutes=16)
    assert login(c).status_code == 200  # 잠금 시간 경과 후 허용


def test_idle_session_expires(ctx):
    c = admin(ctx)
    ctx.clock["now"] += timedelta(minutes=31)
    assert c.get("/servers").status_code == 401


def test_rbac_operator_cannot_manage(ctx):
    a = admin(ctx)
    assert a.post("/users", json={"username": "op1", "password": PW + "x", "role": "operator"}).status_code == 201
    op = ctx.client()
    assert login(op, "op1", PW + "x").status_code == 200
    assert op.get("/servers").status_code == 200
    assert op.post("/servers", json={}).status_code == 403
    assert op.get("/audit-logs").status_code == 403
    assert op.get("/users").status_code == 403


def test_weak_password_rejected(ctx):
    a = admin(ctx)
    r = a.post("/users", json={"username": "op2", "password": "short", "role": "operator"})
    assert r.status_code == 422 and r.json["error"]["code"] == "weak_password"


SERVER = {"name": "web1", "hostname": "web1.example", "account": "certscan", "tls_ports": []}


def test_server_crud_and_duplicate(ctx):  # AC-1
    a = admin(ctx)
    assert a.post("/servers", json=SERVER).status_code == 201
    assert a.post("/servers", json=SERVER).status_code == 409  # Q-IDENT
    lst = a.get("/servers").json["servers"]
    assert [s["name"] for s in lst] == ["web1"] and lst[0]["port"] == 22 and lst[0]["warn_days"] == 30
    assert lst[0]["status_label"] == "미조회"
    assert a.delete(f"/servers/{lst[0]['id']}").status_code == 200
    assert a.get("/servers").json["servers"] == []


@pytest.mark.parametrize("patch", [
    {"name": "bad name!"}, {"hostname": ""}, {"port": 70000}, {"account": "Root;rm"},
    {"paths": ["relative/x"]}, {"paths": ["/etc/../shadow"]}, {"warn_days": 0},
])
def test_server_validation(ctx, patch):
    r = admin(ctx).post("/servers", json={**SERVER, **patch})
    assert r.status_code == 422


def test_scan_flow_and_ui_fields(ctx):  # AC-2..AC-6
    ctx.box.put("/etc/nginx/ssl/ok.crt", pem(make_cert("ok.test", -1, 90, ["ok.test"])[1]))
    ctx.box.put("/etc/nginx/ssl/warn.crt", pem(make_cert("warn.test", -60, 10)[1]))
    a = admin(ctx)
    sid = a.post("/servers", json=SERVER).json["server"]["id"]
    r = a.post(f"/servers/{sid}/scan").json
    assert r["status"] == "WARN" and r["scanned_at"].endswith("Z")
    certs = {c["subject"]: c for c in r["certificates"]}
    assert certs["CN=warn.test"]["status"] == "WARN" and certs["CN=warn.test"]["remaining_days"] >= 0
    assert certs["CN=ok.test"]["san"] == ["DNS:ok.test"]
    ov = a.get("/servers").json["servers"][0]
    assert ov["status"] == "WARN" and ov["last_scanned_at"] and ov["certificate_count"] == 2
    assert a.get(f"/servers/{sid}/certificates").json["status"] == "WARN"


def test_overview_sort_and_filter(ctx):  # Q-UX
    ctx.box.put("/etc/nginx/ssl/ok.crt", pem(make_cert()[1]))
    a = admin(ctx)
    for n, g in (("a-ok", "g1"), ("b-ok", "g2")):
        a.post("/servers", json={**SERVER, "name": n, "group": g})
    a.post("/servers", json={**SERVER, "name": "c-fail", "group": "g1"})
    ids = {s["name"]: s["id"] for s in a.get("/servers").json["servers"]}
    # c-fail 은 인증 실패
    import certpilot_core.service as svc
    ctx.app.extensions["certpilot"]["service"].scanner.executor_factory = (
        lambda t: (_ for _ in ()).throw(RemoteError(FailureCause.AUTH, "denied")) if t.name == "c-fail"
        else SandboxExecutor(ctx.box.path))
    assert a.post("/scan").json["scanned"] == 3
    names = [s["name"] for s in a.get("/servers").json["servers"]]
    assert names == ["c-fail", "a-ok", "b-ok"]  # 위험 순 → 서버명
    assert [s["name"] for s in a.get("/servers?status=OK").json["servers"]] == ["a-ok", "b-ok"]
    assert [s["name"] for s in a.get("/servers?group=g1").json["servers"]] == ["c-fail", "a-ok"]


def test_failure_message_has_no_raw_detail(ctx):  # S-8
    ctx.app.extensions["certpilot"]["service"].scanner.executor_factory = (
        lambda t: (_ for _ in ()).throw(RemoteError(FailureCause.AUTH, "user certscan key SHA256:abc")))
    a = admin(ctx)
    sid = a.post("/servers", json=SERVER).json["server"]["id"]
    r = a.post(f"/servers/{sid}/scan")
    assert r.json["status"] == "FETCH_FAIL" and r.json["cause_label"] == "인증 실패"
    assert "SHA256:abc" not in r.get_data(as_text=True)
    logs = a.get("/audit-logs").json["logs"]
    assert any("SHA256:abc" in str(l["details"]) for l in logs)  # 원문은 감사 로그에만


def test_hostkey_changed_blocks_and_reset(ctx):  # Q-HOSTKEY
    a = admin(ctx)
    sid = a.post("/servers", json=SERVER).json["server"]["id"]
    ctx.app.extensions["certpilot"]["service"].scanner.executor_factory = (
        lambda t: (_ for _ in ()).throw(RemoteError(FailureCause.HOSTKEY, "changed")))
    r = a.post(f"/servers/{sid}/scan").json
    assert r["hostkey_blocked"] and r["cause"] == "HOSTKEY"
    types = [l["event_type"] for l in a.get("/audit-logs").json["logs"]]
    assert "security_hostkey_changed" in types
    assert a.post(f"/servers/{sid}/hostkey/reset").status_code == 200


def test_audit_trail_and_integrity(ctx):  # AC-10
    a = admin(ctx)
    sid = a.post("/servers", json=SERVER).json["server"]["id"]
    a.post(f"/servers/{sid}/scan")
    types = [l["event_type"] for l in a.get("/audit-logs").json["logs"]]
    assert {"login", "server_add", "scan"} <= set(types)
    assert a.get("/audit-logs/verify").json["integrity_valid"] is True
    audit = ctx.app.extensions["certpilot"]["audit"]
    text = open(audit.log_file).read().replace('"server_add"', '"server_xxx"')
    open(audit.log_file, "w").write(text)
    assert a.get("/audit-logs/verify").json["integrity_valid"] is False


def test_csv_export_and_injection_guard(ctx):
    ctx.box.put("/etc/nginx/ssl/ok.crt", pem(make_cert("=cmd|x", -1, 90)[1]))
    a = admin(ctx)
    sid = a.post("/servers", json=SERVER).json["server"]["id"]
    a.post(f"/servers/{sid}/scan")
    r = a.get("/export.csv")
    assert r.mimetype == "text/csv" and "web1" in r.get_data(as_text=True)
    import csv, io
    cells = [c for row in csv.reader(io.StringIO(r.get_data(as_text=True))) for c in row]
    assert not [c for c in cells if c[:1] in ("=", "+", "@")]


def test_csv_safe_helper():
    from certpilot_core.service import _csv_safe
    assert _csv_safe("=1+1") == "'=1+1" and _csv_safe("ok") == "ok"


def test_scan_unknown_server_404(ctx):
    assert admin(ctx).post("/servers/nope/scan").status_code == 404


def test_security_headers(ctx):
    r = ctx.client().get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"


def test_change_password_flow(ctx):  # S-6
    c = admin(ctx)
    assert c.post("/auth/password", json={"old_password": "bad", "new_password": PW + "2"}).status_code == 401
    assert c.post("/auth/password", json={"old_password": PW, "new_password": "weak"}).status_code == 422
    assert c.post("/auth/password", json={"old_password": PW, "new_password": PW}).status_code == 422
    assert c.post("/auth/password", json={"old_password": PW, "new_password": PW + "2"}).status_code == 200
    assert c.get("/servers").status_code == 401  # 기존 세션 폐기
    assert login(ctx.client(), pw=PW).status_code == 401
    assert login(ctx.client(), pw=PW + "2").status_code == 200


def test_ui_has_no_external_dependencies(ctx):  # 폐쇄망 동작 + CSP self 전용
    import re
    c = ctx.client()
    html = c.get("/").get_data(as_text=True)
    assert not re.search(r'(?:src|href)="https?://', html)
    for css in ("flatly", "darkly"):
        assert "@import" not in c.get(f"/static/vendor/{css}.min.css").get_data(as_text=True)
    csp = c.get("/").headers["Content-Security-Policy"]
    assert "http" not in csp and "script-src 'self'" in csp


def test_boots_even_if_admin_password_is_weak(tmp_path, capsys):
    app = create_app({"DATA_DIR": str(tmp_path), "ADMIN_USER": "admin", "ADMIN_PASSWORD": "weak",
                      "SECURE_COOKIE": False})
    assert app.test_client().get("/health").status_code == 200
    err = capsys.readouterr().err
    assert "관리자 생성/재설정 실패" in err and "weak" not in err.replace("weak_password", "")


def test_unwritable_data_dir_gives_clear_error(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(RuntimeError, match="데이터 디렉터리"):
        create_app({"DATA_DIR": str(blocker / "sub")})


def test_admin_password_not_overwritten_without_reset_flag(tmp_path, capsys):
    cfg = {"DATA_DIR": str(tmp_path), "ADMIN_USER": "admin", "ADMIN_PASSWORD": PW, "SECURE_COOKIE": False}
    create_app(cfg)
    app2 = create_app({**cfg, "ADMIN_PASSWORD": PW + "new"})  # 재시작 + 환경변수 변경
    c = app2.test_client()
    assert login(c, "admin", PW).status_code == 200           # 기존 비밀번호 유지
    assert login(app2.test_client(), "admin", PW + "new").status_code == 401
    assert "이미 존재" in capsys.readouterr().err


def test_admin_reset_flag_recovers_login_and_unlocks(tmp_path):
    cfg = {"DATA_DIR": str(tmp_path), "ADMIN_USER": "admin", "ADMIN_PASSWORD": PW, "SECURE_COOKIE": False}
    app = create_app(cfg)
    c = app.test_client()
    for _ in range(5):
        login(c, "admin", "wrong")
    assert login(c, "admin", PW).status_code == 423              # 잠김
    app2 = create_app({**cfg, "ADMIN_PASSWORD": PW + "new", "ADMIN_RESET": True})
    assert login(app2.test_client(), "admin", PW + "new").status_code == 200
    assert login(app2.test_client(), "admin", PW).status_code == 401
    logs = app2.extensions["certpilot"]["audit"].read_logs()
    assert any(l["event_type"] == "admin_password_reset" for l in logs)


def test_reset_with_weak_password_keeps_old(tmp_path):
    cfg = {"DATA_DIR": str(tmp_path), "ADMIN_USER": "admin", "ADMIN_PASSWORD": PW, "SECURE_COOKIE": False}
    create_app(cfg)
    app2 = create_app({**cfg, "ADMIN_PASSWORD": "weak", "ADMIN_RESET": True})
    assert login(app2.test_client(), "admin", PW).status_code == 200
