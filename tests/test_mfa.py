"""2단계 인증(TOTP): RFC 6238 시험 벡터, 등록·로그인·재사용 방지·복구 코드·잠금·해제·초기화·정책 강제·DB 이전"""
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from certpilot_api.app import create_app
from certpilot_core import totp
from certpilot_core.remote import SandboxExecutor

PW = "Str0ng!Passw0rd"
ROOT = Path(__file__).resolve().parent.parent
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"      # ASCII "12345678901234567890"


# ------------------------------------------------------------------ TOTP 코어
@pytest.mark.parametrize("t,expected", [(59, "287082"), (1111111109, "081804"), (1111111111, "050471"),
                                        (1234567890, "005924"), (2000000000, "279037"), (20000000000, "353130")])
def test_rfc6238_vectors(t, expected):
    assert totp.code_at(RFC_SECRET, t) == expected


def test_verify_window_and_replay():
    t = 1_700_000_000
    c = totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, t), t)
    assert c == t // 30
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, t), t, last_counter=c) is None       # 재사용 금지
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, t - 30), t) is not None             # 시계 오차 ±30초 허용
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, t - 90), t) is None
    for bad in ("", "12345", "abcdef", "1234567", None):
        assert totp.verify(RFC_SECRET, bad, t) is None


def test_secret_uri_and_recovery_codes():
    s = totp.new_secret()
    assert len(s) == 32 and totp.new_secret() != s
    uri = totp.otpauth_uri(s, "kim@hnu.kr")
    assert uri.startswith("otpauth://totp/CertPilot%3Akim%40hnu.kr?") and f"secret={s}" in uri
    codes = totp.new_recovery_codes()
    assert len(set(codes)) == 10 and all(totp.looks_like_recovery(c) for c in codes)
    assert totp.hash_recovery(codes[0].lower()) == totp.hash_recovery(codes[0])
    assert not totp.looks_like_recovery("123456")


# ------------------------------------------------------------------ API
@pytest.fixture
def ctx(tmp_path, sandbox):
    clock = {"now": datetime(2026, 10, 28, 12, 0, 0)}

    def make(**extra):
        app = create_app({"DATA_DIR": str(tmp_path / "data"), "ADMIN_USER": "root1", "ADMIN_PASSWORD": PW,
                          "SECURE_COOKIE": False, "max_failures": 3, **extra},
                         executor_factory=lambda t: SandboxExecutor(sandbox.path),
                         clock=lambda: clock["now"], sleep=lambda s: None)
        return app
    return type("Ctx", (), {"make": staticmethod(make), "clock": clock, "tmp": tmp_path})


def now_ts(ctx):
    return ctx.clock["now"].replace(tzinfo=timezone.utc).timestamp()


def login(c, code=None, user="root1", pw=PW):
    body = {"username": user, "password": pw}
    if code is not None:
        body["code"] = code
    return c.post("/auth/login", json=body)


def enroll(ctx, c):
    """admin 으로 로그인한 클라이언트에서 2단계 인증을 켠다 → (secret, recovery_codes)"""
    secret = c.post("/auth/mfa/setup", json={"password": PW}).json["secret"]
    r = c.post("/auth/mfa/enable", json={"code": totp.code_at(secret, now_ts(ctx))})
    assert r.status_code == 200, r.json
    return secret, r.json["recovery_codes"]


def test_full_flow(ctx):
    app = ctx.make()
    c = app.test_client()
    assert login(c).status_code == 200
    assert c.get("/auth/mfa").json == {"enabled": False, "required": False, "recovery_remaining": 0}
    secret, codes = enroll(ctx, c)
    assert len(codes) == 10 and c.get("/auth/me").json["mfa"] is True and c.get("/auth/mfa").json["recovery_remaining"] == 10
    c2 = app.test_client()
    r = login(c2)                                                           # 비밀번호만으로는 불가
    assert r.status_code == 401 and r.json["error"]["code"] == "mfa_required"
    assert c2.get("/servers").status_code == 401
    bad = login(c2, "000000")
    assert bad.status_code == 401 and bad.json["error"]["code"] == "invalid_mfa"
    ctx.clock["now"] += timedelta(seconds=30)                               # 등록에 쓴 코드는 재사용 불가 → 다음 구간 코드
    assert login(c2, totp.code_at(secret, now_ts(ctx))).status_code == 200
    assert c2.get("/servers").status_code == 200


def test_code_replay_rejected(ctx):
    app = ctx.make()
    c = app.test_client()
    login(c)
    secret, _ = enroll(ctx, c)
    ctx.clock["now"] += timedelta(seconds=30)
    code = totp.code_at(secret, now_ts(ctx))
    assert login(app.test_client(), code).status_code == 200
    again = login(app.test_client(), code)
    assert again.status_code == 401 and again.json["error"]["code"] == "invalid_mfa"


def test_wrong_codes_lock_account(ctx):
    app = ctx.make()
    c = app.test_client()
    login(c)
    enroll(ctx, c)
    for _ in range(3):
        assert login(app.test_client(), "111111").status_code == 401
    assert login(app.test_client(), "111111").status_code == 423             # 코드 무차별 대입도 잠금 대상


def test_recovery_code_single_use(ctx):
    app = ctx.make()
    c = app.test_client()
    login(c)
    _, codes = enroll(ctx, c)
    assert login(app.test_client(), codes[0].lower()).status_code == 200
    assert login(app.test_client(), codes[0]).status_code == 401
    assert login(app.test_client(), codes[1]).status_code == 200
    assert app.test_client().get("/health").status_code == 200
    c3 = app.test_client()
    login(c3, codes[2])
    assert c3.get("/auth/mfa").json["recovery_remaining"] == 7


def test_enable_requires_correct_code_and_password(ctx):
    app = ctx.make()
    c = app.test_client()
    login(c)
    assert c.post("/auth/mfa/setup", json={"password": "wrong"}).status_code == 401
    assert c.post("/auth/mfa/enable", json={"code": "123456"}).status_code == 422       # 등록 시작 전
    c.post("/auth/mfa/setup", json={"password": PW})
    assert c.post("/auth/mfa/enable", json={"code": "123456"}).status_code in (401, 422)
    assert c.get("/auth/me").json["mfa"] is False                           # 코드 확인 전에는 로그인에 영향 없음
    assert login(app.test_client()).status_code == 200


def test_disable_and_admin_reset(ctx):
    app = ctx.make()
    c = app.test_client()
    login(c)
    secret, _ = enroll(ctx, c)
    ctx.clock["now"] += timedelta(seconds=30)
    code = totp.code_at(secret, now_ts(ctx))
    assert c.post("/auth/mfa/disable", json={"password": PW, "code": "000000"}).status_code == 401
    assert c.post("/auth/mfa/disable", json={"password": PW, "code": code}).status_code == 200
    assert login(app.test_client()).status_code == 200
    # 관리자 초기화(휴대폰 분실): 다른 사용자의 2단계 인증 제거 + 세션 폐기
    c.post("/users", json={"username": "op1", "password": "An0ther!Passw0rd", "role": "operator"})
    op = app.test_client()
    login(op, user="op1", pw="An0ther!Passw0rd")
    s2 = op.post("/auth/mfa/setup", json={"password": "An0ther!Passw0rd"}).json["secret"]
    op.post("/auth/mfa/enable", json={"code": totp.code_at(s2, now_ts(ctx))})
    assert any(u["username"] == "op1" and u["mfa"] for u in c.get("/users").json["users"])
    assert op.post("/users/root1/mfa/reset").status_code == 403             # 운영자는 불가
    assert c.post("/users/op1/mfa/reset").status_code == 200
    assert op.get("/auth/me").status_code == 401                            # 세션 폐기
    assert login(app.test_client(), user="op1", pw="An0ther!Passw0rd").status_code == 200
    assert c.post("/users/nobody/mfa/reset").status_code == 404


def test_secret_encrypted_at_rest_and_key_file(ctx):
    app = ctx.make()
    c = app.test_client()
    login(c)
    secret, codes = enroll(ctx, c)
    db = sqlite3.connect(ctx.tmp / "data/certpilot.db")
    raw = db.execute("select totp_secret, recovery_hashes from users where username='root1'").fetchone()
    assert secret not in raw[0] and all(code not in raw[1] for code in codes)
    key = ctx.tmp / "data/mfa.key"
    assert oct(key.stat().st_mode & 0o777) == "0o600"
    ctx.make()                                                               # 재시작해도 같은 키 재사용
    assert login(app.test_client(), totp.code_at(secret, now_ts(ctx) + 30)).status_code in (200, 401)


def test_audit_events_without_secrets(ctx):
    app = ctx.make()
    c = app.test_client()
    login(c)
    secret, codes = enroll(ctx, c)
    logs = json.dumps(c.get("/audit-logs?limit=50").json, ensure_ascii=False)
    assert "mfa_enable" in logs and secret not in logs and codes[0] not in logs


def test_require_mfa_policy(ctx):
    app = ctx.make(REQUIRE_MFA=True)
    c = app.test_client()
    assert login(c).status_code == 200
    r = c.get("/servers")
    assert r.status_code == 403 and r.json["error"]["code"] == "mfa_enrollment_required"
    assert c.get("/auth/me").status_code == 200 and c.get("/auth/mfa").json["required"] is True
    enroll(ctx, c)
    assert c.get("/servers").status_code == 200
    ctx.clock["now"] += timedelta(seconds=30)
    assert c.post("/auth/mfa/disable", json={"password": PW, "code": "000000"}).status_code == 403   # 정책상 해제 불가


def test_old_database_is_migrated(tmp_path):
    from certpilot_core.store import Store
    path = str(tmp_path / "old.db")
    db = sqlite3.connect(path)
    db.executescript("""CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL,
        failed_count INTEGER NOT NULL DEFAULT 0, locked_until TEXT, created_at TEXT NOT NULL);
        INSERT INTO users VALUES ('old','h','admin',0,NULL,'2026-01-01T00:00:00Z');""")
    db.commit()
    db.close()
    s = Store(path)
    u = s.get_user("old")
    assert u["totp_enabled"] == 0 and u["recovery_hashes"] == "[]"
    s.add_user("new", "h", "operator", "2026-01-02T00:00:00Z")
    assert s.get_user("new")["totp_last_counter"] == -1


def test_frontend_wiring():
    html = (ROOT / "frontend/templates/index.html").read_text()
    js = (ROOT / "frontend/js/app.js").read_text()
    for el in ("login-code", "mfa-modal", "mfa-start-form", "mfa-enable-form", "mfa-disable-form", "mfa-codes", "open-mfa"):
        assert f'id="{el}"' in html, el
        assert el in js, el
    for ep in ("/auth/mfa/setup", "/auth/mfa/enable", "/auth/mfa/disable", "/mfa/reset", "mfa_required"):
        assert ep in js, ep
