"""상태 분류 (PRD §3.1.5, §5): 시각을 인자로 받는 순수 함수만 둔다."""
import math
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Iterable, Optional

DEFAULT_WARN_DAYS = 30


class Status(str, Enum):
    OK = "OK"
    WARN = "WARN"
    EXPIRED = "EXPIRED"
    CHAIN_RISK = "CHAIN_RISK"
    NOT_YET = "NOT_YET"
    FETCH_FAIL = "FETCH_FAIL"
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = "UNKNOWN"


LABELS = {
    Status.OK: "정상", Status.WARN: "만료 임박", Status.EXPIRED: "만료",
    Status.CHAIN_RISK: "체인 위험", Status.NOT_YET: "유효 전(미발급)",
    Status.FETCH_FAIL: "조회 실패", Status.NOT_FOUND: "인증서 미발견",
    Status.UNKNOWN: "확인 필요",
}

# 위험 순 (§3.1.6 정렬 순서이자 §5 서버 요약 집계의 '최악 우선' 순서)
SEVERITY_ORDER = [
    Status.EXPIRED, Status.CHAIN_RISK, Status.NOT_YET, Status.WARN,
    Status.NOT_FOUND, Status.UNKNOWN, Status.FETCH_FAIL, Status.OK,
]


def utcnow() -> datetime:
    """UTC naive 현재 시각 (모듈 내 모든 시각은 UTC naive 로 통일)"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso_z(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def remaining_days(not_after: datetime, now: datetime) -> int:
    """표시용 잔여 일수: floor((notAfter-now)/86400), 음수는 0 (Q-DAYCALC)"""
    return max(0, math.floor((not_after - now).total_seconds() / 86400))


def classify(not_before: datetime, not_after: datetime, now: datetime,
             warn_days: int = DEFAULT_WARN_DAYS) -> Status:
    """시간 기준 판정(B-2): now<notBefore → NOT_YET, now>=notAfter → EXPIRED,
    now>=notAfter-T → WARN, 그 외 OK. 경계는 포함."""
    if now < not_before:
        return Status.NOT_YET
    if now >= not_after:
        return Status.EXPIRED
    if now >= not_after - timedelta(days=warn_days):
        return Status.WARN
    return Status.OK


def classify_chain_member(not_before: datetime, not_after: datetime, now: datetime,
                          warn_days: int = DEFAULT_WARN_DAYS) -> Status:
    """중간CA/루트: 만료·만료 임박·유효 전이면 CHAIN_RISK, 아니면 OK (Q-CHAIN)"""
    return Status.OK if classify(not_before, not_after, now, warn_days) == Status.OK \
        else Status.CHAIN_RISK


def worst(statuses: Iterable[Status]) -> Status:
    """서버 요약 상태: 최악 우선 (Q-AGG). 빈 입력은 NOT_FOUND."""
    present = set(statuses)
    for s in SEVERITY_ORDER:
        if s in present:
            return s
    return Status.NOT_FOUND


def sort_key(status: Status) -> int:
    return SEVERITY_ORDER.index(status)
