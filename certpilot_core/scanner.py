"""서버 스캐너 (PRD §3.1.1~§3.1.5)

디스크 파일(표준 경로 후보 + 서버별 예외 경로) 과 실행 중 서비스(TLS 포트) 를 함께 조회하고,
리프 단위 상태를 판정해 ScanResult 로 돌려준다. 시각·대기·네트워크는 모두 주입 가능하다.
"""
import hashlib
import posixpath
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from . import status as st
from .cert_parser import (CertificateInfo, extract_pem_certs, parse_der_certificate,
                          parse_pem_blocks)
from .remote import (CAUSE_INFO, RETRYABLE, FailureCause, PolicyExecutor, PolicyViolation,
                     RemoteError, RemoteExecutor, is_key_path, is_safe_path, parse_openssh_version,
                     path_allowed)
from .osprofiles import (AUTO, GENERIC, OS_RELEASE, PROFILES, SYSTEM_CA_FILES, OSProfile,
                         detect_profile)
from .status import Status

# 표준 경로는 OS 계열별 프로필(osprofiles)에서 가져온다. 미리 정의된 후보의 존재 여부만 확인하며 find/전체 탐색은 하지 않는다 (B-6)
CERT_EXT = (".crt", ".pem", ".cer", ".cert")
KEYSTORE_EXT = (".p12", ".pfx", ".jks")
MAX_FILE_BYTES = 262144
MAX_ENTRIES = 200
MAX_DEPTH = 2
MIN_OPENSSH = (7, 0)
_WEBCFG_RE = re.compile(r"^\s*(?:ssl_certificate|SSLCertificateFile|SSLCertificateChainFile)\s+([^\s;]+)",
                        re.MULTILINE)


@dataclass
class Target:
    """스캔 대상 서버 설정 (저장소의 서버 레코드에서 만든다)"""
    server_id: str
    name: str
    hostname: str
    port: int = 22
    account: str = ""
    paths: List[str] = field(default_factory=list)       # 서버별 예외 경로 (파일 또는 디렉터리)
    tls_ports: List[int] = field(default_factory=list)   # 실행 중 서비스 조회 포트
    warn_days: int = st.DEFAULT_WARN_DAYS
    os_type: str = AUTO                                  # auto | debian | rhel | suse | alpine | generic


@dataclass
class CertRecord:
    status: Status
    sources: List[str] = field(default_factory=list)  # "file:/path" 또는 "port:443"
    role: str = "leaf"                               # leaf | intermediate | root
    info: Optional[CertificateInfo] = None
    note: str = ""                                   # 분류된 사유 (원문 아님)
    cause: Optional[FailureCause] = None
    changed: bool = False                            # S-4: 이전 조회와 원문 해시가 다름

    def to_dict(self, now) -> dict:
        i = self.info
        return {
            "status": self.status.value, "status_label": st.LABELS[self.status],
            "role": self.role, "sources": self.sources, "note": self.note,
            "cause": self.cause.value if self.cause else None,
            "cause_label": CAUSE_INFO[self.cause][0] if self.cause else None,
            "action": CAUSE_INFO[self.cause][1] if self.cause else None,
            "changed": self.changed,
            "fingerprint_sha256": i.fingerprint_sha256 if i else None,
            "subject": i.subject if i else None, "issuer": i.issuer if i else None,
            "serial": i.serial if i else None, "san": i.subject_alt_name if i else [],
            "not_before": st.iso_z(i.not_before) if i else None,
            "not_after": st.iso_z(i.not_after) if i else None,
            "remaining_days": st.remaining_days(i.not_after, now) if i and self.status not in
            (Status.NOT_YET,) else None,
        }


@dataclass
class ScanResult:
    server_id: str
    scanned_at: object
    status: Status
    records: List[CertRecord] = field(default_factory=list)
    cause: Optional[FailureCause] = None
    cause_detail: str = ""        # 원문 — 감사 로그 전용, 화면 비노출 (S-8)
    suggested_paths: List[str] = field(default_factory=list)
    file_hashes: Dict[str, str] = field(default_factory=dict)  # path -> sha256 (S-4)
    hostkey_blocked: bool = False
    os_info: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        now = self.scanned_at
        return {
            "server_id": self.server_id, "scanned_at": st.iso_z(now),
            "status": self.status.value, "status_label": st.LABELS[self.status],
            "cause": self.cause.value if self.cause else None,
            "cause_label": CAUSE_INFO[self.cause][0] if self.cause else None,
            "action": CAUSE_INFO[self.cause][1] if self.cause else None,
            "hostkey_blocked": self.hostkey_blocked,
            "os": self.os_info,
            "suggested_paths": self.suggested_paths,
            "certificates": [r.to_dict(now) for r in sorted(
                self.records, key=lambda r: (st.sort_key(r.status), r.sources))],
        }


# ------------------------------------------------------------------ TLS 포트 조회
class TlsProbe:
    """관리 서버가 직접 TLS 핸드셰이크를 수행해 서버 인증서(DER)를 가져온다."""

    def fetch(self, host: str, port: int, sni: Optional[str] = None, timeout: int = 10) -> bytes:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # 검증이 아니라 조회 목적
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni or host) as tls:
                    return tls.getpeercert(binary_form=True)
        except socket.gaierror as e:
            raise RemoteError(FailureCause.DNS, str(e))
        except (socket.timeout, TimeoutError, ConnectionError) as e:
            raise RemoteError(FailureCause.TIMEOUT, str(e))
        except ssl.SSLError as e:
            raise RemoteError(FailureCause.COMMAND, f"TLS handshake: {e}")
        except OSError as e:
            raise RemoteError(FailureCause.TIMEOUT, str(e))


# ------------------------------------------------------------------ 스캐너
def _is_hostkey(e: RemoteError) -> bool:
    return e.cause == FailureCause.HOSTKEY


class Scanner:
    def __init__(self, executor_factory: Callable[[Target], RemoteExecutor],
                 probe: Optional[TlsProbe] = None,
                 clock: Callable = st.utcnow,
                 sleep: Callable[[float], None] = time.sleep,
                 retries: int = 2, backoff: float = 1.0):
        self.executor_factory = executor_factory
        self.probe = probe or TlsProbe()
        self.clock = clock
        self.sleep = sleep
        self.retries = retries
        self.backoff = backoff

    # --- OS 프로필
    @staticmethod
    def _whitelist(target: Target, extra: Sequence[str]) -> List[str]:
        """명시한 OS 는 그 계열 경로만, 자동 감지는 접속 전이라 모든 계열의 합집합을 허용한다(조회는 감지 후 계열 경로만)."""
        prof = PROFILES.get(target.os_type, GENERIC)
        return prof.whitelist() + list(extra)

    @staticmethod
    def _read_os_release(ex) -> str:
        rc, out, _ = ex.run(["head", "-c", "4096", OS_RELEASE])
        return out if rc == 0 else ""

    def _resolve_profile(self, ex, target: Target):
        """(사용할 프로필, 화면용 OS 정보). 명시 선택이 있으면 그것을 쓰고, 감지된 OS 와 다르면 불일치를 표시한다."""
        detected_profile, detected_name = detect_profile(self._read_os_release(ex))
        if target.os_type in PROFILES:
            used, mode = PROFILES[target.os_type], "manual"
        else:
            used, mode = detected_profile, "auto"
        info = {"mode": mode, "profile": used.id, "label": used.label, "detected": detected_name,
                "detected_profile": detected_profile.id,
                "mismatch": mode == "manual" and detected_name is not None
                and detected_profile.id not in (used.id, "generic") and used.id != "generic"}
        return used, info

    # --- 공개 진입점
    def scan(self, target: Target, prev_hashes: Optional[Dict[str, str]] = None) -> ScanResult:
        now = self.clock()
        prev_hashes = prev_hashes or {}
        res = ScanResult(server_id=target.server_id, scanned_at=now, status=Status.NOT_FOUND)
        extra = [posixpath.normpath(p) for p in target.paths]
        whitelist = self._whitelist(target, extra)

        ex = None
        try:
            ex = self._connect(target, whitelist)
            profile, res.os_info = self._resolve_profile(ex, target)
            ver = parse_openssh_version(ex.server_version)
            if ver is not None and ver < MIN_OPENSSH:
                res.records.append(CertRecord(Status.UNKNOWN, ["ssh"],
                                              note="지원 범위 밖 OpenSSH 버전(7.0 미만): 조회하지 않음"))
            else:
                self._scan_files(ex, target, extra, now, prev_hashes, res, profile)
        except RemoteError as e:
            self._fail(res, ["ssh"], e)
            res.hostkey_blocked = _is_hostkey(e)
        finally:
            if ex is not None:
                ex.close()

        self._scan_ports(target, now, res)  # 포트 기반 조회는 SSH 와 독립적으로 수행
        self._merge_duplicates(res)
        self._finalize(res)
        return res

    @staticmethod
    def _fail(res: ScanResult, sources, e: RemoteError):
        res.records.append(CertRecord(Status.FETCH_FAIL, list(sources), cause=e.cause,
                                      note=CAUSE_INFO[e.cause][0]))
        res.cause = res.cause or e.cause
        res.cause_detail = res.cause_detail or e.detail

    # --- 등록 전 연결 테스트 + 경로 탐지 (저장하지 않음)
    def check_connection(self, target: Target):
        """(결과 dict, 원문 오류) 반환. 원문 오류는 감사 로그 전용이며 화면에 노출하지 않는다."""
        extra = [posixpath.normpath(p) for p in target.paths]
        out = {"connected": False, "ssh_version": None, "supported": None, "cause": None,
               "cause_label": None, "action": None, "hostkey_blocked": False,
               "os": None, "standard_paths": [], "suggested_paths": [], "tls": []}
        raw = ""
        ex = None
        try:
            ex = self._connect(target, self._whitelist(target, extra))
            out["connected"] = True
            profile, out["os"] = self._resolve_profile(ex, target)
            out["os"]["candidates"] = list(profile.candidates)
            ver = parse_openssh_version(ex.server_version)
            out["ssh_version"] = f"{ver[0]}.{ver[1]}" if ver else (ex.server_version or None)
            out["supported"] = ver is None or ver >= MIN_OPENSSH
            if out["supported"]:
                scanned = []
                for cand in list(profile.candidates) + extra:
                    files = self._expand(ex, cand, depth=0)
                    if files:
                        scanned += files
                        out["standard_paths"].append({"path": cand, "files": len(files), "sample": files[:3]})
                out["suggested_paths"] = self._suggest(ex, scanned, extra, profile)
        except RemoteError as e:
            out["cause"], out["cause_label"], out["action"] = e.cause.value, CAUSE_INFO[e.cause][0], CAUSE_INFO[e.cause][1]
            out["hostkey_blocked"] = e.cause == FailureCause.HOSTKEY
            raw = e.detail
        finally:
            if ex is not None:
                ex.close()
        for port in target.tls_ports:
            try:
                info = parse_der_certificate(self.probe.fetch(target.hostname, port, sni=target.hostname))
                out["tls"].append({"port": port, "ok": info is not None,
                                   "subject": info.subject if info else None,
                                   "not_after": st.iso_z(info.not_after) if info else None})
            except RemoteError as e:
                out["tls"].append({"port": port, "ok": False, "cause_label": CAUSE_INFO[e.cause][0],
                                   "action": CAUSE_INFO[e.cause][1]})
                raw = raw or e.detail
        return out, raw

    # --- 연결 + 재시도
    def _connect(self, target: Target, whitelist: Sequence[str]) -> RemoteExecutor:
        attempt = 0
        while True:
            try:
                return PolicyExecutor(self.executor_factory(target), whitelist)
            except RemoteError as e:
                if e.cause not in RETRYABLE or attempt >= self.retries:
                    raise
                self.sleep(self.backoff * (2 ** attempt))
                attempt += 1

    # --- 디스크 파일 기반
    def _scan_files(self, ex, target, extra, now, prev_hashes, res: ScanResult, profile: OSProfile):
        files: List[str] = []
        scanned_roots: List[str] = []
        for cand in list(profile.candidates) + extra:
            files += self._expand(ex, cand, depth=0)
            scanned_roots.append(cand)
        files = sorted(set(files))[:MAX_ENTRIES]

        for path in files:
            self._read_file(ex, path, target, now, prev_hashes, res)

        # 웹 서버 설정에서 인증서 경로 추출 → 등록 후보로만 제시 (확정은 사용자)
        for item in self._suggest(ex, files, extra, profile):
            if item["path"] not in res.suggested_paths:
                res.suggested_paths.append(item["path"])

    def _suggest(self, ex, scanned_files: Sequence[str], extra: Sequence[str], profile: OSProfile) -> List[dict]:
        """웹 설정에서 추출한 경로 중 아직 조회 대상이 아닌 것. 인증서 파일명 규칙을 지키고 개인키 이름은 제외한다.
        이 단계에서는 해당 경로를 읽지 않는다(등록 후에만 조회)."""
        covered = set(scanned_files)
        out = []
        for p in self._extract_webcfg(ex, profile):
            if p in covered or not is_safe_path(p) or not self._wanted(p):
                continue
            if any(path_allowed(p, [e]) for e in extra):
                continue  # 이미 등록된 경로 하위
            out.append({"path": p, "in_standard_root": any(path_allowed(p, [r]) for r in profile.roots)})
        return out

    def _expand(self, ex, path: str, depth: int) -> List[str]:
        """후보 경로가 파일이면 그대로, 디렉터리면 (깊이 제한) 인증서 후보 파일만 나열"""
        rc, out, err = ex.run(["ls", "-1", "-p", path])
        if rc != 0:
            if "Permission denied" in err:
                return [path]  # 읽기 시도에서 권한 거부로 기록되게 한다
            return []  # 후보가 없으면 조용히 건너뛴다
        lines = [l for l in out.splitlines() if l.strip()]
        if len(lines) == 1 and lines[0] == path:
            return [path] if self._wanted(path) else []
        found = []
        for name in lines:
            child = posixpath.join(path, name.rstrip("/"))
            if name.endswith("/"):
                if depth + 1 < MAX_DEPTH:
                    found += self._expand(ex, child, depth + 1)
            elif self._wanted(child):
                found.append(child)
        return found

    @staticmethod
    def _wanted(path: str) -> bool:
        base = posixpath.basename(path).lower()
        if is_key_path(path):
            return False  # 개인키 파일은 열지 않는다
        if base in SYSTEM_CA_FILES:
            return False  # OS 기본 CA 번들은 서버 인증서가 아니다
        return base.endswith(CERT_EXT + KEYSTORE_EXT)

    def _read_file(self, ex, path, target, now, prev_hashes, res: ScanResult):
        # 심볼릭 링크: 대상이 허용 범위 밖이면 조회하지 않고, 깨진 링크는 '확인 필요' (Q-SYMLINK)
        rc, out, _ = ex.run(["ls", "-l", path])
        if rc == 0 and out.startswith("l") and " -> " in out:
            link_target = out.strip().split(" -> ", 1)[1]
            if not link_target.startswith("/"):
                link_target = posixpath.join(posixpath.dirname(path), link_target)
            link_target = posixpath.normpath(link_target)
            try:
                ex.policy.validate(["cat", link_target])
            except PolicyViolation:
                res.records.append(CertRecord(Status.UNKNOWN, [f"file:{path}"],
                                              note="링크 대상이 허용 경로 밖이라 조회하지 않음"))
                return
            rc2, _, _ = ex.run(["ls", "-l", link_target])
            if rc2 != 0:
                res.records.append(CertRecord(Status.UNKNOWN, [f"file:{path}"], note="깨진 심볼릭 링크"))
                return
            path_to_read = link_target
        else:
            path_to_read = path

        if path.lower().endswith(KEYSTORE_EXT):
            res.records.append(CertRecord(
                Status.UNKNOWN, [f"file:{path}"],
                note="키스토어(PKCS#12/JKS): 개인키 비접근 정책(B-4)에 따라 내용 파싱 제외"))
            return

        rc, out, err = ex.run(["head", "-c", str(MAX_FILE_BYTES), path_to_read])
        if rc != 0:
            cause = FailureCause.PERMISSION if "Permission denied" in err else FailureCause.COMMAND
            res.records.append(CertRecord(Status.FETCH_FAIL, [f"file:{path}"], cause=cause,
                                          note=CAUSE_INFO[cause][0]))
            res.cause = res.cause or cause
            res.cause_detail = res.cause_detail or err
            return

        pem = extract_pem_certs(out)  # 인증서 블록 외(개인키 등)는 즉시 버린다
        if not pem:
            res.records.append(CertRecord(Status.UNKNOWN, [f"file:{path}"],
                                          note="PEM 인증서가 없음(형식 오류 또는 DER)"))
            return
        digest = hashlib.sha256(pem.encode()).hexdigest()
        res.file_hashes[path] = digest
        changed = path in prev_hashes and prev_hashes[path] != digest

        blocks = parse_pem_blocks(pem)
        parsed = [b for b in blocks if b is not None]
        for _ in range(len(blocks) - len(parsed)):
            res.records.append(CertRecord(Status.UNKNOWN, [f"file:{path}"], note="인증서 파싱 실패"))
        for rec in self._classify_bundle(parsed, f"file:{path}", target.warn_days, now):
            rec.changed = changed
            if changed:
                rec.status, rec.note = Status.UNKNOWN, "이전 조회와 인증서 원문이 달라 확인 필요 (S-4)"
            res.records.append(rec)

    @staticmethod
    def _classify_bundle(certs: List[CertificateInfo], source: str, warn_days: int, now) -> List[CertRecord]:
        """번들에서 리프를 찾아 상태 판정하고, 중간CA/루트는 체인 위험으로만 표시 (Q-CHAIN)"""
        if not certs:
            return []
        issuers = {c.issuer for c in certs if c.issuer != c.subject}
        leaves = [c for c in certs if c.subject not in issuers] or [certs[0]]
        out = []
        for c in certs:
            if c in leaves:
                out.append(CertRecord(st.classify(c.not_before, c.not_after, now, warn_days),
                                      [source], "leaf", c))
            else:
                role = "root" if c.issuer == c.subject else "intermediate"
                out.append(CertRecord(st.classify_chain_member(c.not_before, c.not_after, now, warn_days),
                                      [source], role, c))
        return out

    def _extract_webcfg(self, ex, profile: OSProfile) -> List[str]:
        confs = list(profile.webcfg_files)
        for d in profile.webcfg_dirs:
            rc, out, _ = ex.run(["ls", "-1", d])
            if rc == 0:
                confs += [posixpath.join(d, n) for n in out.split()[:20]]
        paths: List[str] = []
        for conf in confs:
            rc, out, _ = ex.run(["head", "-c", str(MAX_FILE_BYTES), conf])
            if rc == 0:
                for p in _WEBCFG_RE.findall(out):
                    p = posixpath.normpath(p)
                    if p.startswith("/") and p not in paths:
                        paths.append(p)
        return paths

    # --- 실행 중 서비스(포트) 기반
    def _scan_ports(self, target: Target, now, res: ScanResult):
        for port in target.tls_ports:
            src = f"port:{port}"
            last = None
            for attempt in range(self.retries + 1):
                try:
                    der = self.probe.fetch(target.hostname, port, sni=target.hostname)
                    info = parse_der_certificate(der)
                    if info is None:
                        res.records.append(CertRecord(Status.UNKNOWN, [src], note="인증서 파싱 실패"))
                    else:
                        res.records.append(CertRecord(
                            st.classify(info.not_before, info.not_after, now, target.warn_days),
                            [src], "leaf", info))
                    last = None
                    break
                except RemoteError as e:
                    last = e
                    if e.cause not in RETRYABLE:
                        break
                    if attempt < self.retries:
                        self.sleep(self.backoff * (2 ** attempt))
            if last is not None:
                self._fail(res, [src], last)

    @staticmethod
    def _merge_duplicates(res: ScanResult):
        """같은 지문(SHA-256)·같은 역할의 인증서는 하나로 합치고 발견 경로를 모은다"""
        merged: List[CertRecord] = []
        by_fp: Dict[tuple, CertRecord] = {}
        for r in res.records:
            if r.info is None:
                merged.append(r)
                continue
            key = (r.info.fingerprint_sha256, r.role)
            if key in by_fp:
                by_fp[key].sources += [s for s in r.sources if s not in by_fp[key].sources]
                by_fp[key].changed = by_fp[key].changed or r.changed
            else:
                by_fp[key] = r
                merged.append(r)
        res.records = merged

    @staticmethod
    def _finalize(res: ScanResult):
        res.status = st.worst(r.status for r in res.records)
