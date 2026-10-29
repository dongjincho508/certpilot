"""인증·권한 (PRD S-6, Q-RBAC): 관리자/운영자 2역할, 비밀번호 정책, 계정 잠금, 세션 정책"""
import hashlib
import json
import re
import secrets
import hmac
from datetime import datetime, timedelta, timezone
from typing import Callable, List, Optional

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash

from . import totp
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


def hmac_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class AuthService:
    def __init__(self, store: Store, clock: Callable[[], datetime] = utcnow,
                 max_failures: int = 5, lock_minutes: int = 15,
                 idle_minutes: int = 30, max_sessions: int = 3, min_length: int = 12,
                 secret_key: Optional[bytes] = None):
        self.store, self.clock = store, clock
        self._fernet = Fernet(secret_key) if secret_key else None
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

    def _fail(self, username: str, user: Optional[dict], code: str, message: str) -> None:
        """실패 1회 기록(5회 누적 시 잠금) 후 오류를 낸다. 비밀번호·인증 코드 실패에 공통 적용"""
        if user:
            now = self.clock()
            failed = user["failed_count"] + 1
            fields = {"failed_count": failed}
            if failed >= self.max_failures:
                fields = {"failed_count": 0, "locked_until": iso_z(now + timedelta(minutes=self.lock_minutes))}
            self.store.update_user(username, **fields)
        raise AuthError(code, message)

    def login(self, username: str, password: str, code: Optional[str] = None) -> str:
        now = self.clock()
        user = self.store.get_user(username or "")
        if user and user["locked_until"] and now < datetime.strptime(user["locked_until"], "%Y-%m-%dT%H:%M:%SZ"):
            raise AuthError("locked", "계정이 잠겼습니다. 잠시 후 다시 시도하거나 관리자에게 문의하세요.")
        if not user or not check_password_hash(user["password_hash"], password or ""):
            self._fail(username, user, "invalid", "계정 또는 비밀번호가 올바르지 않습니다.")
        if user["totp_enabled"]:
            if not (code or "").strip():
                raise AuthError("mfa_required", "인증 앱의 6자리 코드(또는 복구 코드)를 입력하세요.")
            if not self._check_second_factor(user, code):
                self._fail(username, user, "invalid_mfa", "인증 코드가 올바르지 않습니다.")
        self.store.update_user(username, failed_count=0, locked_until=None)
        sessions = self.store.user_sessions(username)
        for old in sessions[: max(0, len(sessions) - self.max_sessions + 1)]:  # 동시 세션 제한
            self.store.delete_session(old["token_hash"])
        token = secrets.token_urlsafe(32)
        self.store.add_session(_th(token), username, iso_z(now))
        return token

    # ---- 2단계 인증(TOTP)
    def _box(self) -> Fernet:
        if not self._fernet:
            raise AuthError("mfa_unavailable", "2단계 인증 비밀키 저장소가 준비되지 않았습니다.")
        return self._fernet

    def _secret_of(self, user: dict) -> str:
        try:
            return self._box().decrypt(user["totp_secret"].encode()).decode()
        except (InvalidToken, AttributeError):
            raise AuthError("mfa_unavailable", "2단계 인증 비밀키를 읽을 수 없습니다(data/mfa.key 가 바뀌었는지 확인).")

    def _check_second_factor(self, user: dict, code: str) -> bool:
        """TOTP 코드(재사용 불가) 또는 1회용 복구 코드. 성공 시 사용 기록을 저장한다."""
        if totp.looks_like_recovery(code):
            hashes = json.loads(user["recovery_hashes"] or "[]")
            h = totp.hash_recovery(code)
            hit = next((x for x in hashes if hmac_eq(x, h)), None)
            if hit is None:
                return False
            hashes.remove(hit)
            self.store.update_user(user["username"], recovery_hashes=json.dumps(hashes))
            return True
        counter = totp.verify(self._secret_of(user), code, self.clock().replace(tzinfo=timezone.utc).timestamp(),
                              user["totp_last_counter"])
        if counter is None:
            return False
        self.store.update_user(user["username"], totp_last_counter=counter)
        return True

    def mfa_begin(self, username: str, password: str) -> dict:
        """등록 시작: 비밀번호 재확인 후 새 비밀키 발급(코드 확인 전까지는 로그인에 사용되지 않음)"""
        user = self._verified(username, password)
        if user["totp_enabled"]:
            raise AuthError("mfa_already", "이미 2단계 인증이 켜져 있습니다. 먼저 해제하세요.")
        secret = totp.new_secret()
        self.store.update_user(username, totp_secret=self._box().encrypt(secret.encode()).decode(), totp_last_counter=-1)
        return {"secret": secret, "uri": totp.otpauth_uri(secret, username)}

    def mfa_enable(self, username: str, code: str) -> List[str]:
        user = self.store.get_user(username)
        if not user or not user["totp_secret"]:
            raise AuthError("mfa_not_started", "먼저 등록을 시작하세요.")
        if user["totp_enabled"]:
            raise AuthError("mfa_already", "이미 2단계 인증이 켜져 있습니다.")
        counter = totp.verify(self._secret_of(user), code, self.clock().replace(tzinfo=timezone.utc).timestamp())
        if counter is None:
            raise AuthError("invalid_mfa", "인증 코드가 올바르지 않습니다. 앱에 표시된 현재 6자리를 입력하세요.")
        codes = totp.new_recovery_codes()
        self.store.update_user(username, totp_enabled=1, totp_last_counter=counter,
                               recovery_hashes=json.dumps([totp.hash_recovery(c) for c in codes]))
        return codes

    def mfa_disable(self, username: str, password: str, code: str) -> None:
        user = self._verified(username, password)
        if not user["totp_enabled"]:
            raise AuthError("mfa_not_enabled", "2단계 인증이 켜져 있지 않습니다.")
        if not self._check_second_factor(user, code):
            raise AuthError("invalid_mfa", "인증 코드가 올바르지 않습니다.")
        self.mfa_reset(username, keep_sessions=True)

    def mfa_reset(self, username: str, keep_sessions: bool = False) -> None:
        """관리자 복구/해제: 비밀키·복구 코드 삭제. 관리자가 초기화한 경우 해당 계정 세션도 모두 폐기"""
        if not self.store.get_user(username):
            raise AuthError("not_found", "사용자를 찾을 수 없습니다.")
        self.store.update_user(username, totp_secret=None, totp_enabled=0, totp_last_counter=-1, recovery_hashes="[]")
        if not keep_sessions:
            for sess in self.store.user_sessions(username):
                self.store.delete_session(sess["token_hash"])

    def recovery_remaining(self, username: str) -> int:
        user = self.store.get_user(username)
        return len(json.loads(user["recovery_hashes"] or "[]")) if user else 0

    def _verified(self, username: str, password: str) -> dict:
        user = self.store.get_user(username)
        if not user or not check_password_hash(user["password_hash"], password or ""):
            raise AuthError("invalid", "비밀번호가 올바르지 않습니다.")
        return user

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
        return {"username": user["username"], "role": user["role"], "mfa": bool(user["totp_enabled"])}

    def logout(self, token: Optional[str]) -> None:
        if token:
            self.store.delete_session(_th(token))

    def unlock(self, username: str) -> None:
        self.store.update_user(username, failed_count=0, locked_until=None)

    def change_password(self, username: str, old: str, new: str) -> None:
        """본인 비밀번호 변경: 현재 비밀번호 확인 + 정책 검증 + 기존 세션 전부 폐기"""
        user = self.store.get_user(username)
        if not user or not check_password_hash(user["password_hash"], old or ""):
            raise AuthError("invalid", "현재 비밀번호가 올바르지 않습니다.")
        validate_password(username, new, self.min_length)
        if check_password_hash(user["password_hash"], new):
            raise AuthError("weak_password", "이전과 다른 비밀번호를 사용해야 합니다.")
        self.store.update_user(username, password_hash=generate_password_hash(new))
        for sess in self.store.user_sessions(username):
            self.store.delete_session(sess["token_hash"])

    def reset_password(self, username: str, new: str) -> None:
        """운영자 복구용: 현재 비밀번호 확인 없이 재설정(정책 검증 적용), 잠금 해제, 기존 세션 폐기"""
        if not self.store.get_user(username):
            raise AuthError("not_found", "사용자를 찾을 수 없습니다.")
        validate_password(username, new, self.min_length)
        self.store.update_user(username, password_hash=generate_password_hash(new),
                               failed_count=0, locked_until=None)
        for sess in self.store.user_sessions(username):
            self.store.delete_session(sess["token_hash"])
