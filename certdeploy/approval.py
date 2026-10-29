"""배포 승인 단계: 새(갱신된) 인증서를 서버에 배포하기 전에 담당자 승인(1인 또는 2인)을 요구한다.

- 요청은 인증서 지문에 묶인다: 승인은 그 인증서에만 유효하고, 다른 인증서가 오면 새 승인이 필요하다.
- 승인 요청은 `<state_dir>/approvals.json` 에 남고(이력 포함) 유효 시간이 지나면 만료된다.
- 롤백·`--dry-run` 은 승인 대상이 아니다. 긴급 우회(`deploy --emergency`)는 사유를 남기고 알림을 보낸다.
"""
import fcntl
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from cryptography.hazmat.primitives import serialization

SYSTEM = "system"
NAME_RE = re.compile(r"^[A-Za-z0-9가-힣_.@-]{1,64}$")
KEEP_HISTORY = 50
DEFAULTS = {"required": False, "approvers": 1, "ttl_hours": 72, "self_approval": False}


class ApprovalError(Exception):
    pass


def parse_policy(raw, label: str, problems: List[str]) -> Optional[dict]:
    """설정 검증. 승인이 필요 없으면 None."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        problems.append(f"{label} approval 은 매핑이어야 합니다")
        return None
    unknown = set(raw) - set(DEFAULTS)
    if unknown:
        problems.append(f"{label} approval 의 알 수 없는 키: {', '.join(sorted(unknown))}")
    p = {**DEFAULTS, **{k: v for k, v in raw.items() if k in DEFAULTS}}
    if not isinstance(p["required"], bool) or not isinstance(p["self_approval"], bool):
        problems.append(f"{label} approval.required / self_approval 은 true/false 여야 합니다")
    for k, lo, hi in (("approvers", 1, 3), ("ttl_hours", 1, 720)):
        if not isinstance(p[k], int) or isinstance(p[k], bool) or not lo <= p[k] <= hi:
            problems.append(f"{label} approval.{k} 는 {lo}~{hi} 정수여야 합니다")
    return p if p["required"] is True else None


def fingerprint(bundle) -> str:
    return hashlib.sha256(bundle.leaf.public_bytes(serialization.Encoding.DER)).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class Store:
    def __init__(self, state_dir: str):
        self.dir = state_dir
        self.path = os.path.join(state_dir, "approvals.json")

    def load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return {"requests": []}
        except (OSError, ValueError):
            raise ApprovalError(f"승인 파일을 읽을 수 없습니다: {self.path}")
        data.setdefault("requests", [])
        return data

    def save(self, data: dict) -> None:
        data["requests"] = data["requests"][-KEEP_HISTORY:]
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".approvals-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o640)
        os.replace(tmp, self.path)

    @contextmanager
    def locked(self):
        """CLI(타이머)와 관리자 화면이 동시에 쓰지 않도록 배타 잠금"""
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        fd = os.open(os.path.join(self.dir, "approvals.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)


@dataclass
class Gate:
    status: str                      # not_required | approved | pending | rejected
    request: Optional[dict] = None
    created: bool = False            # 이번 호출에서 새 요청이 만들어짐(알림 대상)


def _expire(data: dict, now: datetime) -> None:
    for r in data["requests"]:
        if r["status"] in ("pending", "approved") and _parse(r["expires_at"]) < now:
            r["status"] = "expired"


def _public(r: dict) -> dict:
    return dict(r)


def gate(cert: str, state_dir: str, policy: Optional[dict], bundle, targets: List[str], action: str,
         requested_by: str = SYSTEM, now: Optional[datetime] = None, reopen: bool = False, create: bool = True) -> Gate:
    """이 인증서를 지금 배포해도 되는지 판단하고, 필요하면 승인 요청을 만든다."""
    if not policy:
        return Gate("not_required")
    now = now or _now()
    fp = fingerprint(bundle)
    st = Store(state_dir)
    with st.locked():
        data = st.load()
        _expire(data, now)
        mine = [r for r in data["requests"] if r["fingerprint"] == fp]
        live = next((r for r in reversed(mine) if r["status"] in ("pending", "approved")), None)
        if live:
            st.save(data)
            if len(live["approvals"]) >= live["needed"]:
                live["status"] = "approved"
                st.save(data)
                return Gate("approved", live)
            return Gate("pending", live)
        last = mine[-1] if mine else None
        if last and last["status"] == "rejected" and not reopen:
            st.save(data)
            return Gate("rejected", last)
        if last and last["status"] == "applied" and not reopen:
            st.save(data)
            return Gate("approved", last)             # 이미 승인·적용된 인증서(멱등 재실행)
        if not create:                                # 계획 확인(--dry-run): 요청을 만들지 않고 '승인 필요'만 알린다
            st.save(data)
            return Gate("pending", None)
        for r in data["requests"]:                    # 이전 인증서의 대기 요청은 새 인증서로 대체
            if r["status"] in ("pending", "approved") and r["fingerprint"] != fp:
                r["status"] = "superseded"
        base = f"{cert}-" + f"{bundle.serial:x}"[-10:]
        n = sum(1 for r in data["requests"] if r["id"].startswith(base))
        req = {"id": base + (f"-{n + 1}" if n else ""), "cert": cert, "fingerprint": fp,
               "serial": f"{bundle.serial:x}", "not_after": _iso(bundle.not_after), "names": list(bundle.names), "action": action,
               "targets": targets, "requested_by": requested_by, "requested_at": _iso(now),
               "expires_at": _iso(now + timedelta(hours=policy["ttl_hours"])), "needed": policy["approvers"],
               "self_approval": policy["self_approval"], "status": "pending", "approvals": [], "rejection": None}
        data["requests"].append(req)
        st.save(data)
        return Gate("pending", req, created=True)


def _find(data: dict, req_id: str) -> dict:
    r = next((x for x in data["requests"] if x["id"] == req_id), None)
    if not r:
        raise ApprovalError(f"승인 요청을 찾을 수 없습니다: {req_id}")
    return r


def _who(by: str) -> str:
    by = (by or "").strip()
    if not NAME_RE.match(by):
        raise ApprovalError("승인자 이름이 올바르지 않습니다(영문·숫자·한글·._@- 64자 이내)")
    return by


def approve(state_dir: str, req_id: str, by: str, comment: str = "", now: Optional[datetime] = None) -> dict:
    by, now = _who(by), now or _now()
    st = Store(state_dir)
    with st.locked():
        data = st.load()
        _expire(data, now)
        r = _find(data, req_id)
        if r["status"] != "pending":
            st.save(data)
            raise ApprovalError(f"승인할 수 없는 상태입니다: {_LABEL.get(r['status'], r['status'])}")
        if any(a["by"] == by for a in r["approvals"]):
            raise ApprovalError(f"{by} 님은 이미 승인했습니다 — 다른 승인자가 필요합니다")
        if by == r["requested_by"] and r["requested_by"] != SYSTEM and not r["self_approval"]:
            raise ApprovalError("요청한 사람은 직접 승인할 수 없습니다(다른 담당자가 승인)")
        r["approvals"].append({"by": by, "at": _iso(now), "comment": (comment or "")[:200]})
        if len(r["approvals"]) >= r["needed"]:
            r["status"] = "approved"
        st.save(data)
        return _public(r)


def reject(state_dir: str, req_id: str, by: str, reason: str = "", now: Optional[datetime] = None) -> dict:
    by, now = _who(by), now or _now()
    st = Store(state_dir)
    with st.locked():
        data = st.load()
        r = _find(data, req_id)
        if r["status"] not in ("pending", "approved"):
            raise ApprovalError(f"반려할 수 없는 상태입니다: {_LABEL.get(r['status'], r['status'])}")
        r["status"] = "rejected"
        r["rejection"] = {"by": by, "at": _iso(now), "reason": (reason or "")[:200]}
        st.save(data)
        return _public(r)


def mark_applied(state_dir: str, req_id: str, now: Optional[datetime] = None) -> None:
    st = Store(state_dir)
    with st.locked():
        data = st.load()
        r = next((x for x in data["requests"] if x["id"] == req_id), None)
        if r and r["status"] == "approved":
            r["status"] = "applied"
            r["applied_at"] = _iso(now or _now())
            st.save(data)


def record_bypass(state_dir: str, cert: str, bundle, reason: str, by: str, now: Optional[datetime] = None) -> dict:
    """긴급 우회 기록(승인 없이 배포). 감사·알림용으로 요청 이력에 남긴다."""
    now = now or _now()
    st = Store(state_dir)
    with st.locked():
        data = st.load()
        rec = {"id": f"{cert}-" + f"{bundle.serial:x}"[-10:] + "-emergency", "cert": cert, "fingerprint": fingerprint(bundle),
               "serial": f"{bundle.serial:x}", "status": "bypassed", "requested_by": by, "requested_at": _iso(now),
               "bypass_reason": reason[:200], "approvals": [], "needed": 0}
        data["requests"].append(rec)
        st.save(data)
        return rec


def list_requests(state_dir: str, include_closed: bool = False, now: Optional[datetime] = None) -> List[dict]:
    st = Store(state_dir)
    with st.locked():
        data = st.load()
        _expire(data, now or _now())
        st.save(data)
    rows = data["requests"]
    return rows if include_closed else [r for r in rows if r["status"] in ("pending", "approved")]


_LABEL = {"pending": "승인 대기", "approved": "승인됨(배포 대기)", "applied": "배포 완료", "rejected": "반려", "expired": "만료",
          "superseded": "새 인증서로 대체", "bypassed": "긴급 우회"}


def label(status: str) -> str:
    return _LABEL.get(status, status)


def metrics_text(cert: str, state_dir: str, now: Optional[datetime] = None) -> str:
    """Pushgateway 용 지표: 대기 중 요청 수와 가장 오래된 대기 시작 시각"""
    reqs = list_requests(state_dir, now=now)
    pend = [r for r in reqs if r["status"] == "pending"]
    waiting = [r for r in reqs if r["status"] == "approved"]
    since = min((_parse(r["requested_at"]).timestamp() for r in pend), default=0)
    c = cert.replace("\\", "\\\\").replace('"', '\\"')
    return ("# HELP certdeploy_approval_pending 승인 대기 중인 배포 요청 수.\n# TYPE certdeploy_approval_pending gauge\n"
            f'certdeploy_approval_pending{{cert="{c}"}} {len(pend)}\n'
            "# HELP certdeploy_approval_pending_since_timestamp_seconds 가장 오래된 승인 대기 요청 시각(없으면 0).\n"
            "# TYPE certdeploy_approval_pending_since_timestamp_seconds gauge\n"
            f'certdeploy_approval_pending_since_timestamp_seconds{{cert="{c}"}} {int(since)}\n'
            "# HELP certdeploy_approval_approved_waiting 승인되었으나 아직 배포되지 않은 요청 수.\n"
            "# TYPE certdeploy_approval_approved_waiting gauge\n"
            f'certdeploy_approval_approved_waiting{{cert="{c}"}} {len(waiting)}\n')
