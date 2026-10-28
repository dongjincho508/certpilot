"""인증·권한 (PRD S-6, Q-RBAC): 관리자/운영자 2역할, 비밀번호 정책, 계정 잠금, 세션 정책"""
import hashlib
import re
import secrets
from datetime import datetime, timedelta
from typing import Callable, Optional

from werkzeug.security import check_password_hash, generate_password_hash

from .status import iso_z, utcnow
from .store import Store

ADMIN, OPERATOR = "admin", "operator"
ROLES = (ADMIN, OPERATOR)


class AuthError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def validate_password(username: str, password: str, min_length: int = 12) -> None:
    if len(password) < min_length:
        raise AuthError("weak_password", f"비밀번호는 {min_length}자 이상이어야 합니다.")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]"))
    if classes < 3:
        raise AuthError("weak_password", "대문자·소문자·숫자·특수문자 중 3종 이상을 포함해야 합니다.")
    if username.lower() in password.lower():
        raise AuthError("weak_password", "비밀번호에 계정명을 포함할 수 없습니다.")


def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class AuthService:
    def __init__(self, store: Store, clock: Callable[[], datetime] = utcnow,
                 max_failures: int = 5, lock_minutes: int = 15,
                 idle_minutes: int = 30, max_sessions: int = 3, min_length: int = 12):
        self.store, self.clock = store, clock
        self.max_failures, self.lock_minutes = max_failures, lock_minutes
        self.idle_minutes, self.max_sessions, self.min_length = idle_minutes, max_sessions, min_length

    def create_user(self, username: str, password: str, role: str) -> None:
        if role not in ROLES:
            raise AuthError("bad_role", "역할은 admin 또는 operator 여야 합니다.")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username or ""):
            raise AuthError("bad_username", "계정명은 영문·숫자·._- 3~64자여야 합니다.")
        validate_password(username, password, self.min_length)
        if self.store.get_user(username):
            raise AuthError("exists", "이미 존재하는 계정입니다.")
        self.store.add_user(username, generate_password_hash(password), role, iso_z(self.clock()))

    def login(self, username: str, password: str) -> str:
        now = self.clock()
        user = self.store.get_user(username or "")
        if user and user["locked_until"] and now < datetime.strptime(user["locked_until"], "%Y-%m-%dT%H:%M:%SZ"):
            raise AuthError("locked", "계정이 잠겼습니다. 잠시 후 다시 시도하거나 관리자에게 문의하세요.")
        if not user or not check_password_hash(user["password_hash"], password or ""):
            if user:
                failed = user["failed_count"] + 1
                fields = {"failed_count": failed}
                if failed >= self.max_failures:
                    fields = {"failed_count": 0,
                              "locked_until": iso_z(now + timedelta(minutes=self.lock_minutes))}
                self.store.update_user(username, **fields)
            raise AuthError("invalid", "계정 또는 비밀번호가 올바르지 않습니다.")
        self.store.update_user(username, failed_count=0, locked_until=None)
        sessions = self.store.user_sessions(username)
        for old in sessions[: max(0, len(sessions) - self.max_sessions + 1)]:  # 동시 세션 제한
            self.store.delete_session(old["token_hash"])
        token = secrets.token_urlsafe(32)
        self.store.add_session(_th(token), username, iso_z(now))
        return token

    def authenticate(self, token: Optional[str]) -> Optional[dict]:
        """유효한 세션이면 {'username','role'} 를 반환하고 활동 시각을 갱신, 아니면 None"""
        if not token:
            return None
        sess = self.store.get_session(_th(token))
        if not sess:
            return None
        now = self.clock()
        last = datetime.strptime(sess["last_seen"], "%Y-%m-%dT%H:%M:%SZ")
        if now - last > timedelta(minutes=self.idle_minutes):  # 유휴 종료
            self.store.delete_session(_th(token))
            return None
        user = self.store.get_user(sess["username"])
        if not user:
            return None
        self.store.touch_session(_th(token), iso_z(now))
        return {"username": user["username"], "role": user["role"]}

    def logout(self, token: Optional[str]) -> None:
        if token:
            self.store.delete_session(_th(token))

    def unlock(self, username: str) -> None:
        self.store.update_user(username, failed_count=0, locked_until=None)
