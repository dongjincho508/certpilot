"""CertPilot REST API (Flask).  create_app() 팩토리로 설정·의존성을 주입한다."""
import os
from functools import wraps
from pathlib import Path
from typing import Callable, Optional

from flask import Flask, Response, g, jsonify, request, send_from_directory

from certpilot_core.audit_storage import AuditLogWriter
from certpilot_core.auth import ADMIN, OPERATOR, AuthError, AuthService
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


def create_app(config: Optional[dict] = None, executor_factory: Optional[Callable] = None,
               probe=None, clock: Callable = utcnow, sleep: Optional[Callable] = None) -> Flask:
    cfg = {
        "DATA_DIR": os.environ.get("CERTPILOT_DATA_DIR", "./data"),
        "AUDIT_DIR": os.environ.get("CERTPILOT_AUDIT_DIR"),
        "ADMIN_USER": os.environ.get("CERTPILOT_ADMIN_USER"),
        "ADMIN_PASSWORD": os.environ.get("CERTPILOT_ADMIN_PASSWORD"),
        "SECURE_COOKIE": os.environ.get("CERTPILOT_SECURE_COOKIE", "1") == "1",
        "IDLE_MINUTES": int(os.environ.get("CERTPILOT_IDLE_MINUTES", "30")),
        **(config or {}),
    }
    data_dir = Path(cfg["DATA_DIR"])
    data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(cfg.get("DB_PATH") or str(data_dir / "certpilot.db"))
    audit = AuditLogWriter(cfg["AUDIT_DIR"] or str(data_dir / "audit"), log_type="certpilot")
    kw = {"sleep": sleep} if sleep else {}
    scanner = Scanner(executor_factory or default_executor_factory(store), probe=probe, clock=clock, **kw)
    service = CertPilotService(store, audit, scanner, clock=clock)
    auth = AuthService(store, clock=clock, idle_minutes=cfg["IDLE_MINUTES"],
                       **{k: cfg[k] for k in ("max_failures", "lock_minutes", "max_sessions") if k in cfg})

    if cfg["ADMIN_USER"] and cfg["ADMIN_PASSWORD"] and not store.get_user(cfg["ADMIN_USER"]):
        auth.create_user(cfg["ADMIN_USER"], cfg["ADMIN_PASSWORD"], ADMIN)

    app = Flask(__name__, static_folder=None)
    app.extensions["certpilot"] = {"store": store, "audit": audit, "service": service, "auth": auth}

    # ---------------------------------------------------------------- 공통
    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
            "https://cdnjs.cloudflare.com; script-src 'self' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:")
        if request.path not in ("/",) and not request.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

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
        status = {"invalid": 401, "locked": 423, "exists": 409}.get(e.code, 422)
        return _err(e.code, e.message, status)

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
            token = auth.login(username, str(data.get("password", "")))
        except AuthError as e:
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

    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT") or os.environ.get("CERTPILOT_API_PORT") or 8080)
    create_app().run(host="0.0.0.0", port=port, debug=False)
