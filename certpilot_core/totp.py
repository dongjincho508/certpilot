"""TOTP(RFC 6238) 2단계 인증: 외부 라이브러리 없이 HMAC-SHA1, 6자리, 30초. 복구 코드 포함."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse
from typing import List, Optional

PERIOD = 30
DIGITS = 6
RECOVERY_COUNT = 10


def new_secret() -> str:
    """160비트 비밀키(Base32, 인증 앱에 입력하는 값)"""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return str((struct.unpack(">I", d[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** DIGITS).zfill(DIGITS)


def code_at(secret: str, t: float) -> str:
    return _hotp(secret, int(t // PERIOD))


def verify(secret: str, code: str, now: Optional[float] = None, last_counter: int = -1, window: int = 1) -> Optional[int]:
    """맞으면 사용된 카운터를, 틀리거나 이미 쓴 코드(재사용)이면 None 을 반환한다. 앞뒤 `window`*30초 시계 오차 허용."""
    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    cur = int((time.time() if now is None else now) // PERIOD)
    hit = None
    for c in range(cur - window, cur + window + 1):          # 상수 시간 비교, 모든 후보를 끝까지 확인
        if hmac.compare_digest(_hotp(secret, c), code) and c > last_counter:
            hit = c
    return hit


def otpauth_uri(secret: str, account: str, issuer: str = "CertPilot") -> str:
    label = urllib.parse.quote(f"{issuer}:{account}", safe="")
    return f"otpauth://totp/{label}?" + urllib.parse.urlencode(
        {"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": DIGITS, "period": PERIOD})


def new_recovery_codes(n: int = RECOVERY_COUNT) -> List[str]:
    """복구 코드(1회용). 혼동되는 문자(0/O, 1/I) 제외, 5-5 형식"""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return ["".join(secrets.choice(alphabet) for _ in range(5)) + "-" + "".join(secrets.choice(alphabet) for _ in range(5))
            for _ in range(n)]


def hash_recovery(code: str) -> str:
    return hashlib.sha256(code.strip().upper().replace(" ", "").encode()).hexdigest()


def looks_like_recovery(code: str) -> bool:
    c = (code or "").strip().upper()
    return len(c) == 11 and c[5] == "-"
