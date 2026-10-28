"""애플리케이션 서비스: 서버 등록·조회 실행·감사 기록을 조합한다 (API/CLI 공용)"""
import csv
import io
import posixpath
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional

from . import status as st
from .audit_storage import AuditLogWriter
from .remote import ParamikoExecutor, RemoteExecutor, is_safe_path
from .osprofiles import AUTO, VALID_OS_TYPES
from .scanner import Scanner, Target
from .store import Store
from . import trace

MAX_PARALLEL = 20  # Q-PERF: 동시 조회 상한 (초과분은 풀 큐에서 대기, 거부하지 않음)


class ValidationError(Exception):
    pass


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


def default_executor_factory(store: Store) -> Callable[[Target], RemoteExecutor]:
    def factory(t: Target) -> RemoteExecutor:
        return ParamikoExecutor(t.hostname, t.port, t.account, store).connect()
    return factory


def validate_server(data: dict) -> dict:
    name = (data.get("name") or "").strip()
    hostname = (data.get("hostname") or "").strip()
    account = (data.get("account") or data.get("username") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
        raise ValidationError("서버명은 영문·숫자·._- 64자 이내여야 합니다.")
    if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", hostname):
        raise ValidationError("호스트명 또는 IP 형식이 올바르지 않습니다.")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", account):
        raise ValidationError("접속 계정 형식이 올바르지 않습니다.")
    try:
        port = int(data.get("port", 22))
        warn_days = int(data.get("warn_days", st.DEFAULT_WARN_DAYS))
        tls_ports = [int(p) for p in data.get("tls_ports", [])]
    except (TypeError, ValueError):
        raise ValidationError("포트와 경고 기준은 숫자여야 합니다.")
    if not 1 <= port <= 65535 or any(not 1 <= p <= 65535 for p in tls_ports):
        raise ValidationError("포트 범위는 1~65535 입니다.")
    if not 1 <= warn_days <= 365:
        raise ValidationError("경고 기준은 1~365일이어야 합니다.")
    os_type = (data.get("os_type") or AUTO)
    if os_type not in VALID_OS_TYPES:
        raise ValidationError("지원하지 않는 OS 선택입니다.")
    paths = []
    for p in data.get("paths", []):
        if not is_safe_path(p):
            raise ValidationError("조회 경로가 올바르지 않습니다: 절대 경로만 허용합니다.")
        paths.append(posixpath.normpath(p))
    return {"name": name, "hostname": hostname, "port": port, "account": account,
            "paths": paths, "tls_ports": tls_ports, "warn_days": warn_days, "os_type": os_type,
            "group": (data.get("group") or None), "memo": (data.get("memo") or None)}


def validate_connection(data: dict) -> Target:
    """연결 테스트용 최소 검증(서버명 불필요). 저장하지 않는다."""
    v = validate_server({"name": "probe", **{k: data.get(k) for k in
                         ("hostname", "port", "account", "username", "tls_ports", "paths", "os_type") if k in data}})
    return Target(server_id="probe", name="probe", hostname=v["hostname"], port=v["port"],
                  account=v["account"], paths=v["paths"], tls_ports=v["tls_ports"], os_type=v["os_type"])


class CertPilotService:
    def __init__(self, store: Store, audit: AuditLogWriter, scanner: Scanner,
                 clock: Callable = st.utcnow):
        self.store, self.audit, self.scanner, self.clock = store, audit, scanner, clock

    # ---- 서버
    def add_server(self, data: dict, actor: str) -> dict:
        v = validate_server(data)
        if any(s["name"] == v["name"] for s in self.store.list_servers()):
            raise Conflict("이미 등록된 서버명입니다.")  # Q-IDENT
        server = {**v, "id": uuid.uuid4().hex[:12], "created_at": st.iso_z(self.clock())}
        self.store.add_server(server)
        self.audit.write({"event_type": "server_add", "description": v["name"],
                          "details": {"actor": actor, "server_id": server["id"]}})
        return server

    def delete_server(self, server_id: str, actor: str) -> None:
        server = self._server(server_id)
        self.store.delete_server(server_id)
        self.audit.write({"event_type": "server_delete", "description": server["name"],
                          "details": {"actor": actor, "server_id": server_id}})

    def _server(self, server_id: str) -> dict:
        s = self.store.get_server(server_id)
        if not s:
            raise NotFound("서버를 찾을 수 없습니다.")
        return s

    def reset_hostkey(self, server_id: str, actor: str) -> None:
        """담당자의 명시적 재확인: 저장된 호스트 키를 지우면 다음 조회에서 새 키를 신뢰한다"""
        s = self._server(server_id)
        self.store.forget_hostkey(f"{s['hostname']}:{s['port']}")
        self.audit.write({"event_type": "hostkey_reset", "description": s["name"],
                          "details": {"actor": actor, "server_id": server_id, "security": True}})

    # ---- 조회
    def scan_server(self, server_id: str, actor: str) -> dict:
        s = self._server(server_id)
        prev = self.store.get_scan(server_id)
        target = Target(server_id=s["id"], name=s["name"], hostname=s["hostname"], port=s["port"],
                        account=s["account"], paths=s["paths"], tls_ports=s["tls_ports"],
                        warn_days=s["warn_days"], os_type=s.get("os_type", AUTO))
        with trace.run("scan"), trace.span("scan", "scan_server", server=s["name"], host=f"{s['hostname']}:{s['port']}") as ctx:
            res = self.scanner.scan(target, prev["file_hashes"] if prev else None)
            out = res.to_dict()
            ctx.update(result=out["status"], cause=out["cause"], certs=len(out["certificates"]), raw_error=res.cause_detail)
        self.store.save_scan(server_id, out["scanned_at"], out["status"], out, res.file_hashes)
        # 원문 오류(cause_detail)는 감사 로그에만 기록한다 (S-8)
        self.audit.write({
            "event_type": "scan", "description": f"{s['name']} → {out['status']}",
            "details": {"actor": actor, "server_id": server_id, "result": out["status"],
                        "cause": out["cause"], "raw_error": res.cause_detail,
                        "fingerprints": [c["fingerprint_sha256"] for c in out["certificates"]
                                         if c["fingerprint_sha256"]],
                        "hostkey_blocked": res.hostkey_blocked,
                        "changed": [c["sources"] for c in out["certificates"] if c["changed"]]}})
        if res.hostkey_blocked:
            self.audit.write({"event_type": "security_hostkey_changed", "description": s["name"],
                              "details": {"actor": actor, "server_id": server_id}})
        return out

    def scan_all(self, actor: str) -> List[dict]:
        ids = [s["id"] for s in self.store.list_servers()]
        with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
            return list(pool.map(lambda i: self.scan_server(i, actor), ids))

    def probe_server(self, data: dict, actor: str) -> dict:
        """서버를 저장하지 않고 연결 가능 여부와 조회 가능한 경로를 확인한다(등록 전 점검)."""
        target = validate_connection(data)
        with trace.run("probe"), trace.span("probe", "check_connection", host=f"{target.hostname}:{target.port}",
                                            account=target.account, os_type=target.os_type) as ctx:
            out, raw = self.scanner.check_connection(target)
            ctx.update(connected=out["connected"], cause=out["cause"], raw_error=raw, os=(out.get("os") or {}).get("detected"),
                       standard_paths=len(out["standard_paths"]), suggested=len(out["suggested_paths"]),
                       tls=[(t["port"], t["ok"]) for t in out["tls"]])
        self.audit.write({"event_type": "server_probe", "description": f"{target.hostname}:{target.port}",
                          "details": {"actor": actor, "connected": out["connected"], "cause": out["cause"],
                                      "raw_error": raw}})
        return out

    # ---- 현황
    def overview(self, status: Optional[str] = None, group: Optional[str] = None) -> List[dict]:
        """서버별 요약. 기본 정렬: 상태(위험 순) → 서버명 (Q-UX)"""
        rows = []
        for s in self.store.list_servers():
            if group and s["group"] != group:
                continue
            scan = self.store.get_scan(s["id"])
            r = scan["result"] if scan else None
            row = {**s, "status": r["status"] if r else None,
                   "status_label": r["status_label"] if r else "미조회",
                   "last_scanned_at": r["scanned_at"] if r else None,
                   "cause_label": r["cause_label"] if r else None,
                   "action": r["action"] if r else None,
                   "hostkey_blocked": r["hostkey_blocked"] if r else False,
                   "certificate_count": len(r["certificates"]) if r else 0}
            if status and row["status"] != status:
                continue
            rows.append(row)
        rows.sort(key=lambda x: (st.sort_key(st.Status(x["status"])) if x["status"] else 99, x["name"]))
        return rows

    def certificates(self, server_id: str) -> dict:
        self._server(server_id)
        scan = self.store.get_scan(server_id)
        return scan["result"] if scan else {"server_id": server_id, "certificates": [],
                                            "status": None, "scanned_at": None}

    def export_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["server", "hostname", "server_status", "last_scanned_at", "role", "cert_status",
                    "subject", "issuer", "san", "not_before", "not_after", "remaining_days", "sources"])
        for s in self.store.list_servers():
            scan = self.store.get_scan(s["id"])
            if not scan:
                w.writerow([s["name"], s["hostname"], "미조회"])
                continue
            r = scan["result"]
            if not r["certificates"]:
                w.writerow([s["name"], s["hostname"], r["status_label"], r["scanned_at"]])
            for c in r["certificates"]:
                w.writerow([s["name"], s["hostname"], r["status_label"], r["scanned_at"], c["role"],
                            c["status_label"], _csv_safe(c["subject"]), _csv_safe(c["issuer"]),
                            _csv_safe(" ".join(c["san"])), c["not_before"], c["not_after"],
                            c["remaining_days"], _csv_safe(" ".join(c["sources"]))])
        return buf.getvalue()


def _csv_safe(v):
    """CSV 인젝션 방지: 수식 시작 문자 앞에 따옴표를 붙인다"""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@"):
        return "'" + v
    return v
