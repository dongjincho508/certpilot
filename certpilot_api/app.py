"""CertPilot REST API (Flask).  create_app() 팩토리로 설정·의존성을 주입한다."""
import json
import os
import time
import uuid
from functools import wraps
from pathlib import Path
from typing import Callable, Optional

from werkzeug.exceptions import HTTPException
from flask import Flask, Response, g, jsonify, request, send_from_directory

from certpilot_core import diag, trace
from certpilot_core.audit_storage import AuditLogWriter
from certpilot_core.auth import ADMIN, OPERATOR, AuthError, AuthService
from certpilot_core.osprofiles import list_profiles
from certpilot_core.scanner import Scanner
from certpilot_core.service import (CertPilotService, Conflict, NotFound, ValidationError,
                                    default_executor_factory)
from certpilot_core.status import utcnow
from certpilot_core.store import Store

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
COOKIE = "cp_session"
VERSION = "0.2.0"


def _err(code: str, message: str, status: int):
    return jsonify({"error": {"code": code, "message": message}}), status


def _load_mfa_key(data_dir: Path) -> bytes:
    """2단계 인증 비밀키 암호화용 키(data/mfa.key, 권한 600). 없으면 생성한다. DB 백업과 함께 보관해야 복구 가능"""
    from cryptography.fernet import Fernet
    path = data_dir / "mfa.key"
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(Fernet.generate_key())
    return path.read_bytes().strip()


def _bootstrap_admin(cfg, store, auth, audit) -> None:
    """최초 관리자 생성. 이미 있으면 건드리지 않고, CERTPILOT_ADMIN_RESET_PASSWORD=1 일 때만 환경변수
    비밀번호로 복구(재설정·잠금 해제)한다. 실패해도 서버는 뜨고 원인만 stderr 에 남긴다(비밀번호 값 미기록)."""
    import sys
    user, password = cfg["ADMIN_USER"], cfg["ADMIN_PASSWORD"]
    if not user or not password:
        print("경고: CERTPILOT_ADMIN_USER / CERTPILOT_ADMIN_PASSWORD 가 설정되지 않았습니다.",
              file=sys.stderr, flush=True)
        return
    try:
        existing = store.get_user(user)
        if existing is None:
            auth.create_user(user, password, ADMIN)
            print(f"알림: 최초 관리자 '{user}' 를 생성했습니다.", file=sys.stderr, flush=True)
        elif cfg["ADMIN_RESET"]:
            auth.reset_password(user, password)
            audit.write({"event_type": "admin_password_reset", "description": user,
                         "details": {"actor": "env", "security": True}})
            print(f"알림: 관리자 '{user}' 의 비밀번호를 환경변수 값으로 재설정했습니다. "
                  "복구 후 CERTPILOT_ADMIN_RESET_PASSWORD 를 제거하세요.", file=sys.stderr, flush=True)
        else:
            print(f"알림: 관리자 '{user}' 는 이미 존재합니다(환경변수 비밀번호는 무시됨). "
                  "비밀번호를 잊었다면 CERTPILOT_ADMIN_RESET_PASSWORD=1 로 재배포하세요.",
                  file=sys.stderr, flush=True)
    except AuthError as e:
        print(f"오류: 관리자 생성/재설정 실패 — {e.message} (CERTPILOT_ADMIN_USER/PASSWORD 를 확인하세요)",
              file=sys.stderr, flush=True)


def create_app(config: Optional[dict] = None, executor_factory: Optional[Callable] = None,
               probe=None, clock: Callable = utcnow, sleep: Optional[Callable] = None) -> Flask:
    cfg = {
        "DATA_DIR": os.environ.get("CERTPILOT_DATA_DIR", "./data"),
        "AUDIT_DIR": os.environ.get("CERTPILOT_AUDIT_DIR"),
        "ADMIN_USER": os.environ.get("CERTPILOT_ADMIN_USER"),
        "ADMIN_PASSWORD": os.environ.get("CERTPILOT_ADMIN_PASSWORD"),
        "ADMIN_RESET": os.environ.get("CERTPILOT_ADMIN_RESET_PASSWORD") == "1",
        "CERTDEPLOY_CONFIG": os.environ.get("CERTDEPLOY_CONFIG"),      # 설정하면 관리자 화면에서 certdeploy 설정(메일·개인키 보호)을 다룬다
        "SECURE_COOKIE": os.environ.get("CERTPILOT_SECURE_COOKIE", "1") == "1",
        "IDLE_MINUTES": int(os.environ.get("CERTPILOT_IDLE_MINUTES", "30")),
        "REQUIRE_MFA": os.environ.get("CERTPILOT_REQUIRE_MFA") == "1",     # 1 이면 2단계 인증을 등록하기 전에는 다른 기능을 쓸 수 없다
        **(config or {}),
    }
    data_dir = Path(cfg["DATA_DIR"])
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        probe_file = data_dir / ".write-test"
        probe_file.write_text("ok")
        probe_file.unlink()
    except OSError as e:
        raise RuntimeError(
            f"데이터 디렉터리({data_dir})에 쓸 수 없습니다: {e}. "
            "서비스 계정(certdeploy)이 쓸 수 있도록 폴더 소유권·권한을 확인하세요(설치 매뉴얼 7-5).") from e
    store = Store(cfg.get("DB_PATH") or str(data_dir / "certpilot.db"))
    audit = AuditLogWriter(cfg["AUDIT_DIR"] or str(data_dir / "audit"), log_type="certpilot")
    kw = {"sleep": sleep} if sleep else {}
    scanner = Scanner(executor_factory or default_executor_factory(store), probe=probe, clock=clock, **kw)
    service = CertPilotService(store, audit, scanner, clock=clock)
    auth = AuthService(store, clock=clock, idle_minutes=cfg["IDLE_MINUTES"], secret_key=_load_mfa_key(data_dir),
                       **{k: cfg[k] for k in ("max_failures", "lock_minutes", "max_sessions") if k in cfg})

    _bootstrap_admin(cfg, store, auth, audit)

    app = Flask(__name__, static_folder=None)
    app.extensions["certpilot"] = {"store": store, "audit": audit, "service": service, "auth": auth}

    trace.configure_from_env()

    # ---------------------------------------------------------------- 공통
    @app.before_request
    def _begin():
        g.req_id = request.headers.get("X-Request-Id", "")[:32] or uuid.uuid4().hex[:8]
        g.t0 = time.monotonic()
        g.run_token = trace.run_id_var.set(f"req-{g.req_id}")

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Request-Id"] = getattr(g, "req_id", "-")
        if request.path != "/health" and not request.path.startswith(("/static/", "/debug")) and request.path != "/":
            trace.event("api", "request", "warning" if resp.status_code >= 400 else "info", method=request.method,
                        path=request.path, status=resp.status_code, user=(getattr(g, "user", None) or {}).get("username"),
                        ms=round((time.monotonic() - getattr(g, "t0", time.monotonic())) * 1000))
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        # 외부 CDN 없이 모든 자산을 /static/vendor 에서 제공하므로 self 만 허용한다.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "font-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        if request.path not in ("/",) and not request.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.teardown_request
    def _end(_exc):
        tok = g.pop("run_token", None)
        if tok is not None:
            try:
                trace.run_id_var.reset(tok)
            except ValueError:
                pass

    def token_from_request() -> Optional[str]:
        h = request.headers.get("Authorization", "")
        return h[7:] if h.startswith("Bearer ") else request.cookies.get(COOKIE)

    def require(*roles):
        def deco(fn):
            @wraps(fn)
            def wrapper(*a, **k):
                user = auth.authenticate(token_from_request())
                if not user:
                    return _err("unauthenticated", "로그인이 필요합니다.", 401)
                if user["role"] not in roles:
                    return _err("forbidden", "권한이 없습니다.", 403)
                if cfg["REQUIRE_MFA"] and not user["mfa"] and not request.path.startswith("/auth/"):
                    return _err("mfa_enrollment_required", "보안 정책상 2단계 인증을 먼저 등록해야 합니다.", 403)
                g.user = user
                return fn(*a, **k)
            return wrapper
        return deco

    both = (ADMIN, OPERATOR)

    @app.errorhandler(ValidationError)
    def _v(e):
        return _err("validation", str(e), 422)

    @app.errorhandler(NotFound)
    def _nf(e):
        return _err("not_found", str(e), 404)

    @app.errorhandler(Conflict)
    def _c(e):
        return _err("conflict", str(e), 409)

    @app.errorhandler(AuthError)
    def _a(e):
        status = {"invalid": 401, "invalid_mfa": 401, "locked": 423, "exists": 409, "mfa_unavailable": 503}.get(e.code, 422)
        return _err(e.code, e.message, status)

    @app.errorhandler(Exception)
    def _unexpected(e):
        if isinstance(e, HTTPException):
            return e
        import traceback
        trace.event("api", "unhandled_exception", "error", path=request.path, error=type(e).__name__, message=str(e),
                    traceback=traceback.format_exc()[-1500:])
        resp = _err("internal", f"서버 내부 오류입니다. 요청 ID {g.get('req_id', '-')} 로 관리자 화면 '진단'에서 원인을 확인하세요.", 500)
        return resp

    def body() -> dict:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ValidationError("JSON 본문이 필요합니다.")
        return data

    # ---------------------------------------------------------------- 화면/상태
    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "certpilot-api", "version": VERSION})

    @app.get("/")
    def index():
        return send_from_directory(FRONTEND_DIR / "templates", "index.html")

    @app.get("/static/<path:filename>")
    def static_files(filename):
        return send_from_directory(FRONTEND_DIR, filename)

    # ---------------------------------------------------------------- 인증
    @app.post("/auth/login")
    def login():
        data = body()
        username = str(data.get("username", ""))
        try:
            token = auth.login(username, str(data.get("password", "")), str(data.get("code", "")) or None)
        except AuthError as e:
            if e.code == "mfa_required":          # 비밀번호는 맞았고 인증 코드를 기다리는 중 — 실패가 아니다
                return _err(e.code, e.message, 401)
            audit.write({"event_type": "login_failed", "description": username[:64],
                         "details": {"actor": username[:64], "code": e.code}})
            return _err(e.code, e.message, 423 if e.code == "locked" else 401)
        user = store.get_user(username)
        audit.write({"event_type": "login", "description": username,
                     "details": {"actor": username}})
        resp = jsonify({"username": username, "role": user["role"], "token": token})
        resp.set_cookie(COOKIE, token, httponly=True, samesite="Strict",
                        secure=cfg["SECURE_COOKIE"], max_age=cfg["IDLE_MINUTES"] * 60)
        return resp

    @app.post("/auth/logout")
    def logout():
        auth.logout(token_from_request())
        resp = jsonify({"status": "ok"})
        resp.delete_cookie(COOKIE)
        return resp

    @app.get("/auth/me")
    @require(*both)
    def me():
        return jsonify(g.user)

    @app.post("/auth/password")
    @require(*both)
    def change_password():
        d = body()
        auth.change_password(g.user["username"], str(d.get("old_password", "")), str(d.get("new_password", "")))
        audit.write({"event_type": "password_change", "description": g.user["username"],
                     "details": {"actor": g.user["username"]}})
        resp = jsonify({"status": "ok", "message": "비밀번호를 변경했습니다. 다시 로그인하세요."})
        resp.delete_cookie(COOKIE)
        return resp

    # ---------------------------------------------------------------- 2단계 인증(TOTP)
    @app.get("/auth/mfa")
    @require(*both)
    def mfa_status():
        return jsonify({"enabled": g.user["mfa"], "required": cfg["REQUIRE_MFA"],
                        "recovery_remaining": auth.recovery_remaining(g.user["username"])})

    @app.post("/auth/mfa/setup")
    @require(*both)
    def mfa_setup():
        info = auth.mfa_begin(g.user["username"], str(body().get("password", "")))
        return jsonify(info)

    @app.post("/auth/mfa/enable")
    @require(*both)
    def mfa_enable():
        codes = auth.mfa_enable(g.user["username"], str(body().get("code", "")))
        audit.write({"event_type": "mfa_enable", "description": g.user["username"],
                     "details": {"actor": g.user["username"], "security": True}})
        return jsonify({"status": "ok", "recovery_codes": codes,
                        "message": "복구 코드는 지금 한 번만 표시됩니다. 안전한 곳에 보관하세요."})

    @app.post("/auth/mfa/disable")
    @require(*both)
    def mfa_disable():
        if cfg["REQUIRE_MFA"]:
            return _err("forbidden", "보안 정책상 2단계 인증을 해제할 수 없습니다.", 403)
        d = body()
        auth.mfa_disable(g.user["username"], str(d.get("password", "")), str(d.get("code", "")))
        audit.write({"event_type": "mfa_disable", "description": g.user["username"],
                     "details": {"actor": g.user["username"], "security": True}})
        return jsonify({"status": "ok"})

    @app.post("/users/<username>/mfa/reset")
    @require(ADMIN)
    def mfa_reset(username):
        if not store.get_user(username):
            raise NotFound("사용자를 찾을 수 없습니다.")
        auth.mfa_reset(username)
        audit.write({"event_type": "mfa_reset", "description": username,
                     "details": {"actor": g.user["username"], "security": True}})
        return jsonify({"status": "ok"})

    # ---------------------------------------------------------------- 사용자 (관리자)
    @app.get("/users")
    @require(ADMIN)
    def users():
        return jsonify({"users": store.list_users()})

    @app.post("/users")
    @require(ADMIN)
    def add_user():
        d = body()
        auth.create_user(str(d.get("username", "")), str(d.get("password", "")), str(d.get("role", "")))
        audit.write({"event_type": "user_add", "description": d.get("username"),
                     "details": {"actor": g.user["username"], "role": d.get("role")}})
        return jsonify({"status": "ok"}), 201

    @app.delete("/users/<username>")
    @require(ADMIN)
    def del_user(username):
        if username == g.user["username"]:
            raise ValidationError("자기 자신은 삭제할 수 없습니다.")
        if not store.delete_user(username):
            raise NotFound("사용자를 찾을 수 없습니다.")
        audit.write({"event_type": "user_delete", "description": username,
                     "details": {"actor": g.user["username"]}})
        return jsonify({"status": "ok"})

    @app.post("/users/<username>/unlock")
    @require(ADMIN)
    def unlock(username):
        if not store.get_user(username):
            raise NotFound("사용자를 찾을 수 없습니다.")
        auth.unlock(username)
        audit.write({"event_type": "user_unlock", "description": username,
                     "details": {"actor": g.user["username"]}})
        return jsonify({"status": "ok"})

    # ---------------------------------------------------------------- 서버/조회
    @app.get("/servers")
    @require(*both)
    def list_servers():
        return jsonify({"servers": service.overview(request.args.get("status"), request.args.get("group"))})

    @app.post("/servers")
    @require(ADMIN)
    def add_server():
        return jsonify({"server": service.add_server(body(), g.user["username"])}), 201

    @app.get("/os-profiles")
    @require(*both)
    def os_profiles():
        """등록 화면의 OS 선택지와 계열별 자동 조회 경로"""
        return jsonify({"profiles": list_profiles()})

    @app.post("/servers/probe")
    @require(ADMIN)
    def probe_server():
        """등록 전 연결 테스트 + 경로 탐지. 서버를 저장하지 않는다."""
        return jsonify(service.probe_server(body(), g.user["username"]))

    @app.delete("/servers/<server_id>")
    @require(ADMIN)
    def del_server(server_id):
        service.delete_server(server_id, g.user["username"])
        return jsonify({"status": "ok"})

    @app.get("/servers/<server_id>/certificates")
    @require(*both)
    def certificates(server_id):
        return jsonify(service.certificates(server_id))

    @app.post("/servers/<server_id>/scan")
    @require(*both)
    def scan_one(server_id):
        return jsonify(service.scan_server(server_id, g.user["username"]))

    @app.post("/scan")
    @require(*both)
    def scan_all():
        results = service.scan_all(g.user["username"])
        return jsonify({"scanned": len(results), "servers": service.overview()})

    @app.post("/servers/<server_id>/hostkey/reset")
    @require(ADMIN)
    def hostkey_reset(server_id):
        service.reset_hostkey(server_id, g.user["username"])
        return jsonify({"status": "ok"})

    @app.get("/export.csv")
    @require(*both)
    def export_csv():
        audit.write({"event_type": "export_csv", "description": "csv",
                     "details": {"actor": g.user["username"]}})
        return Response(service.export_csv(), mimetype="text/csv; charset=utf-8",
                        headers={"Content-Disposition": "attachment; filename=certpilot.csv"})

    # ---------------------------------------------------------------- 감사 로그 (관리자)
    @app.get("/audit-logs")
    @require(ADMIN)
    def audit_logs():
        limit = max(1, min(request.args.get("limit", 100, type=int), 1000))
        logs = list(reversed(audit.read_logs(limit)))
        return jsonify({"logs": logs})

    @app.get("/audit-logs/verify")
    @require(ADMIN)
    def audit_verify():
        return jsonify(audit.verify_integrity())

    # ---------------------------------------------------------------- 설정·운영 (관리자) — certdeploy 와 같은 서버에서 쓰는 설정 화면
    def cd_call(fn, *a, **k):
        if not cfg.get("CERTDEPLOY_CONFIG"):
            return _err("certdeploy", "이 서버에는 certdeploy 연동이 설정되어 있지 않습니다(환경변수 CERTDEPLOY_CONFIG). 설치 매뉴얼의 '관리자 화면' 절을 참고하세요.", 409)
        try:
            from certdeploy import adminapi        # 지연 임포트: certdeploy 가 없는 환경(개발·시험)에서도 앱은 정상 기동
        except ImportError:
            return _err("certdeploy", "certdeploy 패키지가 설치되어 있지 않습니다", 409)
        try:
            return fn(adminapi, *a, **k)
        except adminapi.AdminError as e:
            return _err("certdeploy", str(e), e.status)

    @app.get("/certdeploy/overview")
    @require(ADMIN)
    def cd_overview():
        r = cd_call(lambda m: m.overview(cfg.get("CERTDEPLOY_CONFIG")))
        return r if isinstance(r, tuple) else jsonify(r)

    @app.put("/certdeploy/settings")
    @require(ADMIN)
    def cd_save():
        payload = body()
        r = cd_call(lambda m: m.save(cfg.get("CERTDEPLOY_CONFIG"), payload, g.user["username"]))
        if isinstance(r, tuple):
            return r
        audit.write({"event_type": "certdeploy_settings_update", "description": ", ".join(r["changed"]) or "(변경 없음)",
                     "details": {"actor": g.user["username"], "changed": r["changed"], "messages": r["messages"]}})     # 비밀번호·암호는 기록하지 않는다
        return jsonify(r)

    @app.get("/certdeploy/backup")
    @require(ADMIN)
    def cd_backup():
        r = cd_call(lambda m: m.backup_overview(cfg.get("CERTDEPLOY_CONFIG")))
        return r if isinstance(r, tuple) else jsonify(r)

    @app.get("/certdeploy/approvals")
    @require(ADMIN)
    def cd_approvals():
        r = cd_call(lambda m: m.approvals(cfg.get("CERTDEPLOY_CONFIG")))
        return r if isinstance(r, tuple) else jsonify(r)

    @app.post("/certdeploy/approvals/<req_id>/<decision>")
    @require(ADMIN)
    def cd_decide(req_id, decision):
        d = body()
        r = cd_call(lambda m: m.decide(cfg.get("CERTDEPLOY_CONFIG"), req_id, decision, g.user["username"], str(d.get("comment", ""))[:200]))
        if isinstance(r, tuple):
            return r
        audit.write({"event_type": f"approval_{decision}d" if decision == "approve" else "approval_rejected", "description": f"{r['cert']}/{req_id}",
                     "details": {"actor": g.user["username"], "cert": r["cert"], "status": r["request"]["status"], "security": True}})
        return jsonify(r)

    @app.post("/certdeploy/webhook-test")
    @require(ADMIN)
    def cd_webhook_test():
        d = request.get_json(silent=True)
        r = cd_call(lambda m: m.webhook_test(cfg.get("CERTDEPLOY_CONFIG"), d if isinstance(d, dict) and d else None))
        if isinstance(r, tuple):
            return r
        audit.write({"event_type": "certdeploy_webhook_test", "description": "ok" if r["ok"] else "failed",
                     "details": {"actor": g.user["username"], "ok": r["ok"], "message": r["message"]}})
        return jsonify(r)

    @app.post("/certdeploy/itsm-test")
    @require(ADMIN)
    def cd_itsm_test():
        d = request.get_json(silent=True)
        r = cd_call(lambda m: m.itsm_test(cfg.get("CERTDEPLOY_CONFIG"), d if isinstance(d, dict) and d else None))
        if isinstance(r, tuple):
            return r
        audit.write({"event_type": "certdeploy_itsm_test", "description": "ok" if r["ok"] else "failed",
                     "details": {"actor": g.user["username"], "ok": r["ok"], "message": r["message"]}})
        return jsonify(r)

    @app.post("/certdeploy/mail-test")
    @require(ADMIN)
    def cd_mail_test():
        d = request.get_json(silent=True)
        r = cd_call(lambda m: m.mail_test(cfg.get("CERTDEPLOY_CONFIG"), d if isinstance(d, dict) and d else None))
        if isinstance(r, tuple):
            return r
        audit.write({"event_type": "certdeploy_mail_test", "description": "ok" if r["ok"] else "failed",
                     "details": {"actor": g.user["username"], "ok": r["ok"], "message": r["message"]}})
        return jsonify(r)

    # ---------------------------------------------------------------- 진단 (관리자)
    def self_checks() -> list:
        c = []
        try:
            store.list_servers()
            c.append(diag.check("db", True, "읽기 가능"))
        except Exception as e:   # noqa: BLE001
            c.append(diag.check("db", False, f"{type(e).__name__}: {e}", "데이터 디렉터리·디스크 권한 확인"))
        c.append(diag.check("data_dir_writable", os.access(data_dir, os.W_OK), str(data_dir), "디스크 마운트·소유권 확인"))
        v = audit.verify_integrity()
        c.append(diag.check("audit_chain", bool(v.get("integrity_valid")), json.dumps(v, ensure_ascii=False)[:200], "감사 로그 변조·손상 여부 확인"))
        c.append(diag.check("admin_exists", any(u["role"] == ADMIN for u in store.list_users()), "", "CERTPILOT_ADMIN_* 설정 확인"))
        has_key = bool(os.environ.get("CERTPILOT_SSH_PRIVATE_KEY") or os.environ.get("CERTPILOT_SSH_PRIVATE_KEY_B64"))
        c.append(diag.check("ssh_agent", bool(os.environ.get("SSH_AUTH_SOCK")) or not has_key,
                            "SSH_AUTH_SOCK 설정됨" if os.environ.get("SSH_AUTH_SOCK") else "에이전트 없음",
                            "CERTPILOT_SSH_PRIVATE_KEY[_B64] 형식 확인(시작 로그 참조)"))
        return c

    @app.get("/debug/events")
    @require(ADMIN)
    def debug_events():
        evs = trace.TRACER.events(limit=max(1, min(request.args.get("limit", 200, type=int), 1000)),
                                  component=request.args.get("component"), level=request.args.get("level"),
                                  run_id=request.args.get("run_id"), since_seq=request.args.get("since", 0, type=int))
        return jsonify({"events": evs})

    @app.get("/debug/selfcheck")
    @require(ADMIN)
    def debug_selfcheck():
        checks = self_checks()
        return jsonify({"checks": checks, **diag.summarize(checks)})

    @app.get("/debug/bundle")
    @require(ADMIN)
    def debug_bundle():
        checks = self_checks()
        servers = [{k: s.get(k) for k in ("name", "hostname", "port", "account", "os_type", "status", "status_label",
                                         "cause_label", "last_scanned_at", "certificate_count")} for s in service.overview()]
        audit.write({"event_type": "debug_bundle", "description": "download", "details": {"actor": g.user["username"]}})
        payload = {"version": VERSION, "environment": diag.environment_info(), "checks": checks, "servers": servers,
                   "events": trace.TRACER.events(limit=500)}
        return Response(diag.dumps(payload), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=certpilot-debug.json"})

    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT") or os.environ.get("CERTPILOT_API_PORT") or 8080)
    create_app().run(host="0.0.0.0", port=port, debug=False)  # nosec B104 — 개발용 진입점(운영은 gunicorn + nginx)
