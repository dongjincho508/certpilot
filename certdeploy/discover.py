"""인증서 자동 탐색: 지정한 대역(CIDR)·호스트명 목록의 TLS 포트를 읽기 전용으로 조회해
감시 대상에 등록되지 않은 인증서와 위험(만료·자체서명·약한 키)을 찾는다. 서버에는 아무 것도 설치·변경하지 않는다."""
import concurrent.futures as cf
import glob
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.request
import warnings
from datetime import datetime, timezone
from typing import Callable, Iterable, List, Optional, Set, Tuple

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from certpilot_core import netutil

DEFAULT_PORTS = (443, 8443, 9443, 8444, 993, 636)
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$")
WEAK_SIG = {"md5", "sha1"}
EXPIRING_DAYS = 30


class DiscoverError(Exception):
    pass


# ------------------------------------------------------------------ 범위 계산
def parse_ports(spec: Iterable) -> List[int]:
    out: List[int] = []
    for item in spec:
        for part in str(item).split(","):
            part = part.strip()
            if not part:
                continue
            lo, _, hi = part.partition("-")
            try:
                a, b = int(lo), int(hi or lo)
            except ValueError:
                raise DiscoverError(f"포트 형식이 올바르지 않습니다: {part!r}")
            if not (1 <= a <= b <= 65535):
                raise DiscoverError(f"포트 범위는 1~65535 입니다: {part!r}")
            if b - a > 100:
                raise DiscoverError(f"포트 범위가 너무 넓습니다(최대 101개): {part!r}")
            out.extend(range(a, b + 1))
    return sorted(set(out)) or list(DEFAULT_PORTS)


def expand_scope(cidrs: Iterable[str], names: Iterable[str], max_hosts: int = 4096,
                 allow_public: bool = False) -> List[Tuple[str, Optional[str]]]:
    """(접속 주소, SNI 이름) 목록. CIDR 은 호스트 주소를 하나씩, 이름은 그대로(SNI=이름)."""
    out: List[Tuple[str, Optional[str]]] = []
    seen: Set[Tuple[str, Optional[str]]] = set()
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c.strip(), strict=False)
        except ValueError:
            raise DiscoverError(f"CIDR 형식이 올바르지 않습니다: {c!r}")
        if not allow_public and not (net.is_private or net.is_loopback):
            raise DiscoverError(f"사설 대역이 아닙니다: {c} — 외부 대역을 조사하려면 권한 확인 후 --allow-public 을 지정하세요")
        hosts = [net.network_address] if net.num_addresses == 1 else list(net.hosts())
        if len(out) + len(hosts) > max_hosts:
            raise DiscoverError(f"조사 대상이 {max_hosts}개를 넘습니다({c}). 대역을 나누거나 --max-hosts 를 올리세요")
        for h in hosts:
            item = (str(h), None)
            if item not in seen:
                seen.add(item)
                out.append(item)
    for n in names:
        n = n.strip().lower().rstrip(".")
        if not n or n.startswith("#"):
            continue
        if not HOST_RE.match(n):
            raise DiscoverError(f"호스트명 형식이 올바르지 않습니다: {n!r}")
        item = (n, n)
        if item not in seen:
            seen.add(item)
            out.append(item)
    if len(out) > max_hosts:
        raise DiscoverError(f"조사 대상이 {max_hosts}개를 넘습니다. --max-hosts 를 올리세요")
    return out


# ------------------------------------------------------------------ 인증서 해석
def _hash_name(cert: x509.Certificate) -> str:
    try:
        h = cert.signature_hash_algorithm
        return h.name if h else "none"
    except Exception:
        return "unknown"


def _key_info(cert: x509.Certificate) -> Tuple[str, int]:
    k = cert.public_key()
    if isinstance(k, rsa.RSAPublicKey):
        return "RSA", k.key_size
    if isinstance(k, ec.EllipticCurvePublicKey):
        return "EC", k.key_size
    if isinstance(k, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(k, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(k).__name__, 0


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


def parse_cert(der: bytes, now: Optional[datetime] = None) -> dict:
    now = now or datetime.now(timezone.utc)
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    alg, bits = _key_info(cert)
    na = cert.not_valid_after_utc
    return {
        "subject": _cn(cert.subject), "issuer": _cn(cert.issuer), "self_signed": cert.subject == cert.issuer,
        "san": list(san), "serial": f"{cert.serial_number:x}", "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"), "not_after": na.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days_left": round((na - now).total_seconds() / 86400, 1), "key": f"{alg}-{bits}", "key_bits": bits, "key_alg": alg,
        "sig_hash": _hash_name(cert),
    }


def name_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower(), host.lower()
    if pattern.startswith("*."):
        return host.count(".") == pattern.count(".") and host.endswith(pattern[1:])
    return pattern == host


# ------------------------------------------------------------------ 조회
def probe(addr: str, port: int, sni: Optional[str], timeout: float = 3.0) -> Optional[dict]:
    """TCP 연결 후 TLS 핸드셰이크로 인증서를 읽는다. 포트가 닫혔으면 None, 열려 있지만 TLS 가 아니면 {'tls': False}."""
    try:
        sock = socket.create_connection((addr, port), timeout=timeout)
    except OSError:
        return None
    try:
        sock.settimeout(timeout)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE        # 탐색 목적: 신뢰 여부와 무관하게 인증서를 읽는다(어떤 데이터도 보내지 않음)
        with warnings.catch_warnings():       # 구형 TLS 서버도 조사하기 위해 최소 버전을 낮춘다(탐색 전용)
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        try:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                der = tls.getpeercert(binary_form=True)
                ver = tls.version()
        except (ssl.SSLError, OSError):
            return {"tls": False}
        if not der:
            return {"tls": False}
        out = parse_cert(der)
        out.update(tls=True, tls_version=ver)
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


def reverse_name(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0].lower().rstrip(".")
    except (OSError, UnicodeError):
        return None


def resolve_all(host: str) -> Set[str]:
    try:
        return {a[4][0] for a in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)}
    except OSError:
        return set()


# ------------------------------------------------------------------ 기존 등록 대상
def load_known(patterns: Iterable[str]) -> Set[Tuple[str, int]]:
    """Prometheus file_sd(targets/*.yml)에서 (호스트, 포트) 집합을 읽는다."""
    known: Set[Tuple[str, int]] = set()
    for pat in patterns:
        for path in sorted(glob.glob(pat)):
            try:
                data = yaml.safe_load(open(path, encoding="utf-8")) or []
            except (OSError, yaml.YAMLError) as e:
                raise DiscoverError(f"감시 대상 파일을 읽을 수 없습니다: {path} ({e})")
            for grp in data if isinstance(data, list) else []:
                for t in (grp or {}).get("targets", []):
                    host, _, port = str(t).rpartition(":")
                    if host and port.isdigit():
                        known.add((host.strip("[]").lower(), int(port)))
    return known


# ------------------------------------------------------------------ 분류
def classify(rec: dict, known: Set[Tuple[str, int]], our_domains: Iterable[str],
             resolver: Callable[[str], Set[str]] = resolve_all) -> dict:
    flags: List[str] = []
    ports_known = {(h, p) for h, p in known if p == rec["port"]}
    names = {n for n in (rec.get("addr"), rec.get("sni"), rec.get("ptr")) if n}
    is_known = any(h in names for h, _ in ports_known) or any(rec["addr"] in resolver(h) for h, _ in ports_known)
    rec["registered"] = is_known
    if not is_known:
        flags.append("unregistered")
    if rec["days_left"] < 0:
        flags.append("expired")
    elif rec["days_left"] <= EXPIRING_DAYS:
        flags.append("expiring")
    if rec["self_signed"]:
        flags.append("self_signed")
    if (rec["key_alg"] == "RSA" and rec["key_bits"] < 2048) or (rec["key_alg"] == "EC" and rec["key_bits"] < 256):
        flags.append("weak_key")
    if rec["sig_hash"] in WEAK_SIG:
        flags.append("weak_signature")
    if rec.get("tls_version") in ("TLSv1", "TLSv1.1", "SSLv3"):
        flags.append("old_tls")
    if rec.get("sni") and rec["san"] and not any(name_matches(p, rec["sni"]) for p in rec["san"]):
        flags.append("name_mismatch")
    doms = [d.lower().lstrip(".") for d in our_domains]
    rec["our_domain"] = any(n == d or n.endswith("." + d) for n in rec["san"] + [rec["subject"]] for d in doms
                            for n in [n.lower().lstrip("*.")])
    rec["flags"] = flags
    return rec


def suggest_host(rec: dict) -> str:
    if rec.get("sni"):
        return rec["sni"]
    if rec.get("ptr"):
        return rec["ptr"]
    for n in rec["san"]:
        if not n.startswith("*."):
            return n
    return rec["addr"]


# ------------------------------------------------------------------ 실행
def scan(scope: List[Tuple[str, Optional[str]]], ports: List[int], known: Set[Tuple[str, int]], our_domains: Iterable[str],
         timeout: float = 3.0, concurrency: int = 64, reverse_dns: bool = True,
         prober: Callable[..., Optional[dict]] = probe, resolver: Callable[[str], Set[str]] = resolve_all,
         reverser: Callable[[str], Optional[str]] = reverse_name) -> dict:
    started = time.time()
    jobs = [(a, p, s) for a, s in scope for p in ports]
    found: List[dict] = []
    open_non_tls = 0

    def work(job):
        a, p, s = job
        return job, prober(a, p, s, timeout)

    with cf.ThreadPoolExecutor(max_workers=max(1, min(concurrency, 512))) as ex:
        for (a, p, s), res in ex.map(work, jobs):
            if res is None:
                continue
            if not res.get("tls"):
                open_non_tls += 1
                continue
            rec = dict(res, addr=a, port=p, sni=s)
            rec["ptr"] = reverser(a) if (reverse_dns and s is None) else None
            found.append(rec)
    for rec in found:
        classify(rec, known, our_domains, resolver)
    found.sort(key=lambda r: (r["days_left"], r["addr"], r["port"]))
    total = lambda f: sum(1 for r in found if f in r["flags"])  # noqa: E731
    return {
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "duration_s": round(time.time() - started, 1),
        "hosts": len(scope), "ports": ports, "probes": len(jobs), "open_non_tls": open_non_tls,
        "summary": {"tls_endpoints": len(found), "registered": sum(1 for r in found if r["registered"]),
                    "unregistered": total("unregistered"), "expired": total("expired"), "expiring": total("expiring"),
                    "self_signed": total("self_signed"), "weak": total("weak_key") + total("weak_signature"),
                    "old_tls": total("old_tls"), "name_mismatch": total("name_mismatch")},
        "endpoints": found,
    }


def diff_previous(result: dict, previous: Optional[dict]) -> dict:
    """이전 실행에서 없던 엔드포인트(새로 나타남)와 사라진 엔드포인트."""
    def keys(r):
        return {(e["addr"], e["port"], e["sni"] or "") : e for e in (r or {}).get("endpoints", [])}
    cur, prev = keys(result), keys(previous)
    return {"appeared": [cur[k] for k in cur if k not in prev] if previous else [],
            "disappeared": [prev[k] for k in prev if k not in cur] if previous else [],
            "changed": [cur[k] for k in cur if k in prev and cur[k]["sha256"] != prev[k]["sha256"]]}


# ------------------------------------------------------------------ 출력
def report_text(result: dict, delta: Optional[dict] = None) -> str:
    s = result["summary"]
    lines = [f"조사: 호스트 {result['hosts']}개 × 포트 {len(result['ports'])}개 = {result['probes']}회 ({result['duration_s']}초)",
             f"TLS 인증서 {s['tls_endpoints']}개 발견 — 등록됨 {s['registered']} / 미등록 {s['unregistered']}  "
             f"(만료 {s['expired']}, 30일 이내 {s['expiring']}, 자체서명 {s['self_signed']}, 약한 키/서명 {s['weak']}, 구형 TLS {s['old_tls']}, 이름 불일치 {s['name_mismatch']})"]
    label = {"unregistered": "미등록", "expired": "만료", "expiring": "임박", "self_signed": "자체서명", "weak_key": "약한키",
             "weak_signature": "약한서명", "old_tls": "구형TLS", "name_mismatch": "이름불일치"}
    risky = [r for r in result["endpoints"] if r["flags"]]
    if risky:
        lines.append("")
        lines.append(f"{'대상':<34}{'남은일':>7}  {'발급자':<22}{'키':<9}표시")
        for r in risky:
            who = f"{suggest_host(r)}:{r['port']}" + (f" ({r['addr']})" if suggest_host(r) != r["addr"] else "")
            lines.append(f"{who[:33]:<34}{r['days_left']:>7.0f}  {r['issuer'][:21]:<22}{r['key']:<9}{','.join(label[f] for f in r['flags'])}")
    if delta and (delta["appeared"] or delta["disappeared"] or delta["changed"]):
        lines.append("")
        lines.append(f"지난 조사 대비: 새로 나타남 {len(delta['appeared'])}, 사라짐 {len(delta['disappeared'])}, 인증서 교체 {len(delta['changed'])}")
        for r in delta["appeared"][:20]:
            lines.append(f"  + {suggest_host(r)}:{r['port']} ({r['addr']})")
    return "\n".join(lines)


def targets_yaml(result: dict) -> str:
    """미등록 엔드포인트를 감시 대상 파일 형식으로 출력(검토 후 targets/ 에 복사). 기존 파일은 건드리지 않는다."""
    seen: Set[str] = set()
    items = []
    for r in result["endpoints"]:
        if "unregistered" not in r["flags"]:
            continue
        t = f"{suggest_host(r)}:{r['port']}"
        if t in seen:
            continue
        seen.add(t)
        items.append({"targets": [t], "labels": {"group": "미등록-발견", "service": "unknown", "os": "other", "owner": "미확인",
                                                 "discovered": result["scanned_at"][:10]}})
    head = ("# certdeploy-discover 가 찾은 미등록 인증서 후보. 담당자·서비스를 확인해 레이블을 고친 뒤\n"
            "# prometheus/targets/servers.yml 에 옮기세요. IP 만 알려진 항목은 호스트명으로 바꿔야 올바른 인증서(SNI)가 조회됩니다.\n")
    return head + (yaml.safe_dump(items, allow_unicode=True, sort_keys=False) if items else "[]\n")


def metrics_text(result: dict) -> str:
    s = result["summary"]
    rows = [("certdeploy_discovery_endpoints", "발견한 TLS 엔드포인트 수", s["tls_endpoints"]),
            ("certdeploy_discovery_unregistered", "감시 대상에 없는 TLS 엔드포인트 수", s["unregistered"]),
            ("certdeploy_discovery_expired", "만료된 인증서를 쓰는 엔드포인트 수", s["expired"]),
            ("certdeploy_discovery_self_signed", "자체서명 인증서 엔드포인트 수", s["self_signed"]),
            ("certdeploy_discovery_weak", "약한 키/서명 엔드포인트 수", s["weak"]),
            ("certdeploy_discovery_last_run_timestamp_seconds", "마지막 탐색 시각", int(time.time()))]
    return "".join(f"# HELP {n} {h}\n# TYPE {n} gauge\n{n} {v}\n" for n, h, v in rows)


def push_metrics(url: str, text: str, timeout: float = 10.0) -> bool:
    req = urllib.request.Request(f"{url.rstrip('/')}/metrics/job/certdeploy_discovery", data=text.encode(), method="POST",
                                 headers={"Content-Type": "text/plain"})
    try:
        netutil.urlopen(req, timeout=timeout).read()
        return True
    except OSError:
        return False


def save_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def load_json(path: str) -> Optional[dict]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None
