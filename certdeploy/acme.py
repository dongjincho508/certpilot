"""내장 ACME 클라이언트(RFC 8555, DNS-01) — lego 없이 Let's Encrypt 등에서 인증서를 발급한다.

두 가지 DNS 방식
- 연동(infoblox): TXT 를 API 로 자동 등록 → 전파 확인 → 검증 → 발급 → TXT 삭제까지 한 번에.
- 수동(manual): 1단계에서 주문을 만들고 등록할 TXT 를 알려 준다(상태를 디스크에 보존). 사람이 DNS 에 TXT 를 넣은 뒤
  다시 실행하면 2단계가 TXT 가 공개 DNS 에 보이는지 확인하고 검증·발급한다(타이머로 반복 실행해도 안전).
개인키는 이 서버에서 만들어 대기 디렉터리(0600)에만 두고, 발급이 끝나면 설치 위치로 옮긴 뒤 삭제한다.
"""
import base64
import hashlib
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from certpilot_core import netutil, trace

from . import dnsquery
from .manual import ManualError, build_bundle, generate_csr, install_bundle

LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


class AcmeError(Exception):
    def __init__(self, message: str, problem: Optional[dict] = None):
        super().__init__(message)
        self.problem = problem or {}


class NotReady(Exception):
    """사람이 DNS 에 TXT 를 등록하기를 기다리는 중(오류가 아님)."""

    def __init__(self, missing: List[Tuple[str, str]], message: str):
        super().__init__(message)
        self.missing = missing


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_of(key: ec.EllipticCurvePrivateKey) -> dict:
    n = key.public_key().public_numbers()
    return {"crv": "P-256", "kty": "EC", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}


def thumbprint(jwk: dict) -> str:
    """RFC 7638: 필수 멤버만, 사전순 키, 공백 없는 JSON 의 SHA-256."""
    required = {"EC": ("crv", "kty", "x", "y"), "RSA": ("e", "kty", "n")}[jwk["kty"]]
    return b64u(hashlib.sha256(json.dumps({k: jwk[k] for k in required}, separators=(",", ":")).encode()).digest())


def dns01_value(token: str, jwk: dict) -> str:
    """_acme-challenge TXT 에 넣을 값 = b64url(SHA-256(token + '.' + thumbprint))."""
    return b64u(hashlib.sha256(f"{token}.{thumbprint(jwk)}".encode()).digest())


def txt_name(domain: str) -> str:
    return "_acme-challenge." + (domain[2:] if domain.startswith("*.") else domain)


def _default_http(method: str, url: str, headers: dict, body: Optional[bytes], timeout: float):
    netutil.http_url(url)
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:    # nosec B310 — 위에서 스킴 검증
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except OSError as e:
        raise AcmeError(f"ACME 서버 접속 실패: {type(e).__name__}: {e}") from None


class AcmeClient:
    def __init__(self, directory_url: str, account_key: ec.EllipticCurvePrivateKey, kid: Optional[str] = None,
                 http: Callable = _default_http, sleep: Callable[[float], None] = time.sleep, timeout: float = 30.0):
        self.directory_url, self.key, self.kid = directory_url, account_key, kid
        self.http, self.sleep, self.timeout = http, sleep, timeout
        self._dir: Optional[dict] = None
        self._nonce: Optional[str] = None
        self.jwk = jwk_of(account_key)

    # ---- 전송
    def _request(self, method, url, headers=None, body=None):
        return self.http(method, url, headers or {}, body, self.timeout)

    def directory(self) -> dict:
        if self._dir is None:
            st, _, body = self._request("GET", self.directory_url)
            if st != 200:
                raise AcmeError(f"ACME directory 를 읽을 수 없습니다(HTTP {st})")
            self._dir = json.loads(body)
        return self._dir

    def _new_nonce(self) -> str:
        st, h, _ = self._request("HEAD", self.directory()["newNonce"])
        n = {k.lower(): v for k, v in h.items()}.get("replay-nonce")
        if not n:
            raise AcmeError("ACME 서버가 nonce 를 주지 않았습니다")
        return n

    def _sign(self, url: str, payload: Optional[dict], nonce: str, use_jwk: bool) -> bytes:
        prot = {"alg": "ES256", "nonce": nonce, "url": url}
        prot.update({"jwk": self.jwk} if use_jwk else {"kid": self.kid})
        p64 = b64u(json.dumps(prot, separators=(",", ":")).encode())
        pl64 = "" if payload is None else b64u(json.dumps(payload, separators=(",", ":")).encode())   # None = POST-as-GET
        r, s = decode_dss_signature(self.key.sign(f"{p64}.{pl64}".encode(), ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return json.dumps({"protected": p64, "payload": pl64, "signature": b64u(sig)}).encode()

    def post(self, url: str, payload: Optional[dict], use_jwk: bool = False, accept: str = "application/json"):
        """JWS POST. badNonce 는 한 번 재시도한다. (상태, 헤더(소문자), 본문 바이트) 반환, 4xx/5xx 는 AcmeError."""
        for attempt in range(2):
            nonce = self._nonce or self._new_nonce()
            self._nonce = None
            st, h, body = self._request("POST", url, {"Content-Type": "application/jose+json", "Accept": accept},
                                        self._sign(url, payload, nonce, use_jwk))
            h = {k.lower(): v for k, v in h.items()}
            self._nonce = h.get("replay-nonce")
            if st < 400:
                return st, h, body
            try:
                problem = json.loads(body)
            except ValueError:
                problem = {"detail": body[:200].decode(errors="replace")}
            if problem.get("type", "").endswith(":badNonce") and attempt == 0:
                continue
            raise AcmeError(f"ACME 요청 실패(HTTP {st}): {problem.get('type', '')} {problem.get('detail', '')}".strip(), problem)
        raise AcmeError("ACME nonce 오류가 반복됩니다")

    # ---- 계정·주문
    def register(self, email: Optional[str]) -> str:
        payload = {"termsOfServiceAgreed": True}
        if email:
            payload["contact"] = [f"mailto:{email}"]
        _, h, _ = self.post(self.directory()["newAccount"], payload, use_jwk=True)
        self.kid = h["location"]
        return self.kid

    def new_order(self, domains: List[str]) -> Tuple[str, dict]:
        _, h, body = self.post(self.directory()["newOrder"], {"identifiers": [{"type": "dns", "value": d} for d in domains]})
        return h["location"], json.loads(body)

    def get(self, url: str) -> dict:
        return json.loads(self.post(url, None)[2])

    def poll(self, url: str, ok=("valid",), bad=("invalid",), tries: int = 30, interval: float = 2.0) -> dict:
        obj = {}
        for _ in range(tries):
            obj = self.get(url)
            if obj.get("status") in ok:
                return obj
            if obj.get("status") in bad:
                return obj
            self.sleep(interval)
        raise AcmeError(f"ACME 상태 확인 시간 초과(마지막 상태: {obj.get('status')})")

    def finalize(self, order: dict, csr_der: bytes) -> dict:
        _, _, body = self.post(order["finalize"], {"csr": b64u(csr_der)})
        return json.loads(body)

    def download(self, cert_url: str) -> bytes:
        return self.post(cert_url, None, accept="application/pem-certificate-chain")[2]


# ====================================================================== 상태·흐름
def _write_private(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_account(state_dir: str, directory_url: str, email: Optional[str], **client_kw) -> AcmeClient:
    """디렉터리별 계정 키를 만들거나 읽는다(계정 키·URL 은 state_dir/acme/, 0600)."""
    tag = hashlib.sha256(directory_url.encode()).hexdigest()[:10]
    kp, jp = os.path.join(state_dir, "acme", f"account-{tag}.key"), os.path.join(state_dir, "acme", f"account-{tag}.json")
    try:
        with open(kp, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), None)
        kid = json.load(open(jp, encoding="utf-8")).get("kid")
    except (OSError, ValueError):
        key, kid = ec.generate_private_key(ec.SECP256R1()), None
        _write_private(kp, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    client = AcmeClient(directory_url, key, kid, **client_kw)
    if not kid:
        with trace.span("acme", "register_account", directory=directory_url):
            kid = client.register(email)
        _write_private(jp, json.dumps({"kid": kid, "directory": directory_url}).encode())
    return client


def pending_paths(state_dir: str, name: str) -> Tuple[str, str]:
    d = os.path.join(state_dir, "acme", "pending")
    return os.path.join(d, f"{name}.json"), os.path.join(d, f"{name}.key")


def load_pending(state_dir: str, name: str) -> Optional[dict]:
    try:
        with open(pending_paths(state_dir, name)[0], encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def clear_pending(state_dir: str, name: str) -> None:
    for p in pending_paths(state_dir, name):
        try:
            os.remove(p)
        except OSError:
            pass


def start_order(client: AcmeClient, state_dir: str, name: str, domains: List[str], key_type: str = "rsa2048") -> dict:
    """주문을 만들고 DNS-01 챌린지 목록을 상태 파일에 저장한다. 반환: pending dict."""
    with trace.span("acme", "new_order", domains=domains):
        key_pem, csr_pem = generate_csr(domains, key_type)
        order_url, order = client.new_order(domains)
    challenges = []
    for authz_url in order["authorizations"]:
        az = client.get(authz_url)
        domain = ("*." if az.get("wildcard") else "") + az["identifier"]["value"]
        ch = next((c for c in az["challenges"] if c["type"] == "dns-01"), None)
        if az["status"] == "valid":
            challenges.append({"domain": domain, "authz": authz_url, "valid": True})
        elif ch is None:
            raise AcmeError(f"{domain}: CA 가 dns-01 챌린지를 제공하지 않습니다")
        else:
            challenges.append({"domain": domain, "authz": authz_url, "chal": ch["url"], "token": ch["token"], "valid": False,
                               "txt_name": txt_name(domain), "txt_value": dns01_value(ch["token"], client.jwk)})
    pend = {"name": name, "domains": domains, "order_url": order_url, "finalize": order["finalize"], "challenges": challenges,
            "created_at": datetime.now(timezone.utc).isoformat(), "directory": client.directory_url,
            "csr_der_b64": b64u(x509.load_pem_x509_csr(csr_pem).public_bytes(serialization.Encoding.DER))}
    jp, kp = pending_paths(state_dir, name)
    _write_private(kp, key_pem)
    _write_private(jp, json.dumps(pend, ensure_ascii=False).encode())
    trace.event("acme", "order_started", name=name, txt=[(c["txt_name"]) for c in challenges if not c["valid"]])
    return pend


def txt_records(pend: dict) -> List[Tuple[str, str]]:
    return [(c["txt_name"], c["txt_value"]) for c in pend["challenges"] if not c.get("valid")]


def instructions(pend: dict) -> str:
    lines = ["DNS 에 아래 TXT 레코드를 등록하세요(같은 이름에 값이 둘이면 둘 다 등록, 기존 값은 지우지 않음):"]
    lines += [f"  이름: {n}   종류: TXT   값: {v}" for n, v in txt_records(pend)]
    lines.append("  (TTL 은 짧게(60~300초). 등록 후 같은 명령(issue/renew)을 다시 실행하면 확인 후 발급을 진행합니다)")
    return "\n".join(lines)


def wait_visible(records: List[Tuple[str, str]], resolvers: List[str], timeout: float, interval: float = 10.0,
                 sleep: Callable[[float], None] = time.sleep, check=dnsquery.txt_visible) -> List[Tuple[str, str]]:
    """모든 TXT 가 보일 때까지 timeout 초 동안 반복 확인. 안 보이는 (이름, 값) 목록을 반환(빈 목록 = 모두 보임)."""
    waited = 0.0
    while True:
        missing = [(n, v) for n, v in records if not check(n, v, resolvers)]
        if not missing or waited >= timeout:
            return missing
        sleep(interval)
        waited += interval


def complete_order(client: AcmeClient, pend: dict, state_dir: str) -> Tuple[bytes, bytes]:
    """챌린지 응답 → 검증 대기 → finalize → 인증서 다운로드. (키 PEM, 인증서 체인 PEM) 반환."""
    for c in pend["challenges"]:
        if c.get("valid"):
            continue
        with trace.span("acme", "challenge", domain=c["domain"]):
            client.post(c["chal"], {})
            az = client.poll(c["authz"])
            if az.get("status") != "valid":
                err = next((x.get("error") for x in az.get("challenges", []) if x.get("error")), {}) or {}
                raise AcmeError(f"{c['domain']} 검증 실패: {err.get('detail') or az.get('status')}", err)
    with trace.span("acme", "finalize", domains=pend["domains"]):
        ready = client.poll(pend["order_url"], ok=("ready", "valid"), bad=("invalid",))     # 모든 authz 가 valid 가 되면 ready
        if ready.get("status") == "invalid":
            raise AcmeError(f"주문이 거부되었습니다: {ready.get('error', {}).get('detail', 'invalid')}", ready.get("error"))
        client.finalize({"finalize": pend["finalize"]}, b64u_dec(pend["csr_der_b64"]))
        order = client.poll(pend["order_url"], ok=("valid",), bad=("invalid",))
        if order.get("status") != "valid":
            raise AcmeError(f"주문이 실패했습니다: {order.get('error', {}).get('detail', order.get('status'))}", order.get("error"))
        chain = client.download(order["certificate"])
    with open(pending_paths(state_dir, pend["name"])[1], "rb") as f:
        key_pem = f.read()
    return key_pem, chain


def install_issued(key_pem: bytes, chain_pem: bytes, cert_file: str, key_file: str) -> Tuple[object, List[str]]:
    """발급된 체인과 키를 검증해 설정된 위치에 설치한다(manual.build_bundle/install_bundle 재사용)."""
    certs = x509.load_pem_x509_certificates(chain_pem)
    key = serialization.load_pem_private_key(key_pem, None)
    bundle, _ = build_bundle(certs, key)
    os.makedirs(os.path.dirname(cert_file), mode=0o700, exist_ok=True)
    os.makedirs(os.path.dirname(key_file), mode=0o700, exist_ok=True)
    return bundle, install_bundle(cert_file, key_file, bundle)


def issue_with_provider(client: AcmeClient, provider, state_dir: str, name: str, domains: List[str], key_type: str,
                        resolvers: List[str], propagation_timeout: float, sleep=time.sleep,
                        check=dnsquery.txt_visible) -> Tuple[bytes, bytes]:
    """연동 모드: TXT 등록 → 전파 확인 → 검증·발급 → (성공·실패와 무관하게) 등록한 TXT 정리."""
    pend = start_order(client, state_dir, name, domains, key_type)
    recs = txt_records(pend)
    try:
        for n, v in recs:
            provider.present(n, v)
        if resolvers:
            missing = wait_visible(recs, resolvers, propagation_timeout, sleep=sleep, check=check)
            if missing:
                raise AcmeError("TXT 가 DNS 에 전파되지 않았습니다: " + ", ".join(n for n, _ in missing))
        return complete_order(client, pend, state_dir)
    finally:
        for n, v in recs:
            try:
                provider.cleanup(n, v)
            except Exception as e:   # noqa: BLE001 — 정리 실패가 발급 결과를 가리지 않게 기록만 한다
                trace.event("acme", "dns_cleanup", "error", fqdn=n, error=type(e).__name__, message=str(e))
