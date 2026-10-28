"""ACME DNS-01 용 DNS 제공자. present/cleanup 은 TXT 레코드를 만들고 지운다. dns.mode 로 선택한다.

| mode | 용도 |
|---|---|
| manual | API 없이 사람이 DNS 관리 화면에서 등록(안내는 호출부가 출력) |
| infoblox | Infoblox WAPI(record:txt) — 실제 장비로는 검증하지 못했다 |
| rfc2136 | 표준 동적 갱신(+TSIG): BIND, PowerDNS, Windows DNS, Infoblox DDNS 등 |
| cloudflare | Cloudflare DNS API(Bearer 토큰) |
| powerdns | PowerDNS Authoritative HTTP API |
| webhook | 임의 HTTP 엔드포인트로 {action, fqdn, value} JSON 전달(사내 DNS 관리 시스템 연동) |
| exec | 사용자 스크립트 호출 `<cmd> present|cleanup <fqdn> <value>` — 어떤 DNS 업체든 스크립트로 연결 |
※ 100여 개 업체 API 는 lego(설정의 `lego:` 엔진)가 지원한다. 여기에 없는 업체는 exec/webhook 또는 lego 를 쓴다.
"""
import base64
import json
import os
import shlex
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from certpilot_core import netutil, trace


class DnsProviderError(Exception):
    pass


class ManualProvider:
    name = "manual"
    automatic = False

    def present(self, fqdn: str, value: str) -> None:
        trace.event("acme", "dns_manual_present", fqdn=fqdn, value=value)

    def cleanup(self, fqdn: str, value: str) -> None:
        trace.event("acme", "dns_manual_cleanup", fqdn=fqdn, value=value)


class InfobloxProvider:
    name = "infoblox"
    automatic = True

    def __init__(self, host: str, user: str, password: str, wapi_version: str = "v2.12", view: Optional[str] = None,
                 ca_file: Optional[str] = None, verify: bool = True, ttl: Optional[int] = None, timeout: float = 20.0,
                 scheme: str = "https"):
        self.base = f"{scheme}://{host}/wapi/{wapi_version}"
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.view, self.ttl, self.timeout = view, ttl, timeout
        self.ctx = None
        if scheme == "https":
            self.ctx = ssl.create_default_context(cafile=ca_file) if verify else ssl._create_unverified_context()  # nosec B323 — 운영자가 verify:false 를 명시한 경우만

    def _call(self, method: str, path: str, body: Optional[dict] = None):
        req = urllib.request.Request(f"{self.base}/{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": self.auth, "Content-Type": "application/json"})
        netutil.http_url(req.full_url)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:   # nosec B310 — 위에서 스킴 검증
                raw = r.read().decode()
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            raise DnsProviderError(f"Infoblox {method} {path.split('?')[0]} 실패: HTTP {e.code} {detail}") from None
        except OSError as e:
            raise DnsProviderError(f"Infoblox 접속 실패: {type(e).__name__}: {e}") from None
        return json.loads(raw) if raw else None

    def _find(self, fqdn: str, value: str):
        q = {"name": fqdn.rstrip("."), "text": value}
        if self.view:
            q["view"] = self.view
        return self._call("GET", "record:txt?" + urllib.parse.urlencode(q)) or []

    def present(self, fqdn: str, value: str) -> None:
        fqdn = fqdn.rstrip(".")
        if self._find(fqdn, value):                                   # 재시도 시 중복 생성 방지
            trace.event("acme", "dns_present_exists", fqdn=fqdn)
            return
        body = {"name": fqdn, "text": value}
        if self.view:
            body["view"] = self.view
        if self.ttl:
            body.update(ttl=self.ttl, use_ttl=True)
        ref = self._call("POST", "record:txt", body)
        trace.event("acme", "dns_present", provider="infoblox", fqdn=fqdn, ref=ref)

    def cleanup(self, fqdn: str, value: str) -> None:
        """우리가 만든 (이름, 값) 레코드만 지운다. 같은 이름의 다른 TXT(와일드카드·루트의 두 번째 값)는 건드리지 않는다."""
        for rec in self._find(fqdn.rstrip("."), value):
            self._call("DELETE", rec["_ref"])
            trace.event("acme", "dns_cleanup", provider="infoblox", fqdn=fqdn, ref=rec["_ref"])


def _http_json(method, url, headers=None, body=None, timeout=20.0, ctx=None, label="HTTP"):
    """JSON 요청 공용(http/https 만). (상태코드, 파싱된 본문) 반환, 4xx/5xx 는 DnsProviderError."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    netutil.http_url(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:      # nosec B310 — 위에서 스킴 검증
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else None)
    except urllib.error.HTTPError as e:
        raise DnsProviderError(f"{label} {method} {url.split('?')[0].split('://', 1)[-1].split('/', 1)[-1]} 실패: HTTP {e.code} {e.read().decode(errors='replace')[:300]}") from None
    except (OSError, ValueError) as e:
        raise DnsProviderError(f"{label} 요청 실패: {type(e).__name__}: {e}") from None


def _zone_of(fqdn: str, zone: Optional[str]) -> str:
    return zone.rstrip(".") if zone else fqdn.rstrip(".").split(".", 1)[1]


class ExecProvider:
    """`<cmd> present|cleanup <fqdn> <value>` 호출(셸 없이 argv). 환경변수로도 전달: ACME_ACTION/ACME_FQDN/ACME_VALUE. 종료 코드 0 이어야 성공."""
    name, automatic = "exec", True

    def __init__(self, cmd: str, timeout: int = 120, env_pass=(), environ=os.environ):
        self.argv = shlex.split(cmd)
        if not self.argv:
            raise DnsProviderError("dns.exec.cmd 가 비어 있습니다")
        self.timeout = timeout
        self.base_env = {k: environ[k] for k in ("PATH", "HOME", "LANG") if k in environ}
        self.base_env.update({k: environ[k] for k in env_pass if k in environ})     # 스크립트에 필요한 변수만 명시적으로 허용

    def _run(self, action, fqdn, value):
        env = {**self.base_env, "ACME_ACTION": action, "ACME_FQDN": fqdn, "ACME_VALUE": value}
        try:
            r = subprocess.run(self.argv + [action, fqdn, value], env=env, capture_output=True, text=True, timeout=self.timeout)   # nosec B603 — 운영자가 지정한 명령, 셸 미사용
        except (OSError, subprocess.TimeoutExpired) as e:
            raise DnsProviderError(f"exec 훅 실행 실패({action}): {type(e).__name__}: {e}") from None
        trace.event("acme", "dns_exec", action=action, fqdn=fqdn, rc=r.returncode, output=(r.stdout + r.stderr)[-300:])
        if r.returncode != 0:
            raise DnsProviderError(f"exec 훅 실패({action}, 종료 코드 {r.returncode}): {(r.stderr or r.stdout).strip()[-200:]}")

    def present(self, fqdn, value):
        self._run("present", fqdn.rstrip("."), value)

    def cleanup(self, fqdn, value):
        self._run("cleanup", fqdn.rstrip("."), value)


class WebhookProvider:
    """POST {url} {"action": "present"|"cleanup", "fqdn": ..., "value": ...}. 2xx 면 성공. 인증 헤더는 환경변수에서(이름:값 형식)."""
    name, automatic = "webhook", True

    def __init__(self, url: str, auth_header: Optional[str] = None, timeout: float = 30.0, ctx=None):
        self.url, self.timeout, self.ctx = url, timeout, ctx
        self.headers = {}
        if auth_header:
            k, _, v = auth_header.partition(":")
            self.headers[k.strip()] = v.strip()

    def _post(self, action, fqdn, value):
        _http_json("POST", self.url, self.headers, {"action": action, "fqdn": fqdn.rstrip("."), "value": value}, self.timeout, self.ctx, "webhook")
        trace.event("acme", "dns_webhook", action=action, fqdn=fqdn)

    def present(self, fqdn, value):
        self._post("present", fqdn, value)

    def cleanup(self, fqdn, value):
        self._post("cleanup", fqdn, value)


class CloudflareProvider:
    name, automatic = "cloudflare", True

    def __init__(self, token: str, zone: Optional[str] = None, zone_id: Optional[str] = None, api_base: str = "https://api.cloudflare.com/client/v4",
                 ttl: int = 60, timeout: float = 20.0):
        self.h, self.base, self.zone, self.zone_id, self.ttl, self.timeout = {"Authorization": f"Bearer {token}"}, api_base.rstrip("/"), zone, zone_id, ttl, timeout

    def _api(self, method, path, body=None):
        return _http_json(method, f"{self.base}/{path}", self.h, body, self.timeout, None, "Cloudflare")[1] or {}

    def _zone_id(self, fqdn):
        if self.zone_id:
            return self.zone_id
        labels = fqdn.rstrip(".").split(".")
        for i in range(len(labels) - 1):                                   # 가장 긴 접미사부터 영역 탐색
            cand = ".".join(labels[i:])
            res = self._api("GET", "zones?" + urllib.parse.urlencode({"name": self.zone or cand})).get("result") or []
            if res:
                return res[0]["id"]
            if self.zone:
                break
        raise DnsProviderError(f"Cloudflare 에서 {fqdn} 의 영역(zone)을 찾지 못했습니다")

    def present(self, fqdn, value):
        zid = self._zone_id(fqdn)
        out = self._api("POST", f"zones/{zid}/dns_records", {"type": "TXT", "name": fqdn.rstrip("."), "content": value, "ttl": self.ttl})
        if not out.get("success", True):
            raise DnsProviderError(f"Cloudflare TXT 생성 실패: {out.get('errors')}")
        trace.event("acme", "dns_present", provider="cloudflare", fqdn=fqdn)

    def cleanup(self, fqdn, value):
        zid = self._zone_id(fqdn)
        q = urllib.parse.urlencode({"type": "TXT", "name": fqdn.rstrip("."), "content": value})
        for rec in self._api("GET", f"zones/{zid}/dns_records?{q}").get("result") or []:
            self._api("DELETE", f"zones/{zid}/dns_records/{rec['id']}")
            trace.event("acme", "dns_cleanup", provider="cloudflare", fqdn=fqdn, id=rec["id"])


class PowerDnsProvider:
    name, automatic = "powerdns", True

    def __init__(self, api_url: str, api_key: str, zone: str, server_id: str = "localhost", ttl: int = 60, timeout: float = 20.0, ctx=None):
        self.base = f"{api_url.rstrip('/')}/api/v1/servers/{server_id}/zones/{zone.rstrip('.')}."
        self.h, self.ttl, self.timeout, self.ctx = {"X-API-Key": api_key}, ttl, timeout, ctx

    def _rrset(self, fqdn):
        z = _http_json("GET", self.base, self.h, None, self.timeout, self.ctx, "PowerDNS")[1] or {}
        name = fqdn.rstrip(".") + "."
        for rr in z.get("rrsets", []):
            if rr["name"].lower() == name.lower() and rr["type"] == "TXT":
                return name, [r["content"] for r in rr["records"]]
        return name, []

    def _replace(self, name, contents):
        rrset = ({"name": name, "type": "TXT", "changetype": "DELETE"} if not contents else
                 {"name": name, "type": "TXT", "ttl": self.ttl, "changetype": "REPLACE", "records": [{"content": c, "disabled": False} for c in contents]})
        _http_json("PATCH", self.base, self.h, {"rrsets": [rrset]}, self.timeout, self.ctx, "PowerDNS")

    def present(self, fqdn, value):
        name, cur = self._rrset(fqdn)
        q = f'"{value}"'
        if q not in cur:
            self._replace(name, cur + [q])                              # 같은 이름의 기존 TXT 는 보존
        trace.event("acme", "dns_present", provider="powerdns", fqdn=fqdn)

    def cleanup(self, fqdn, value):
        name, cur = self._rrset(fqdn)
        q = f'"{value}"'
        if q in cur:
            self._replace(name, [c for c in cur if c != q])
        trace.event("acme", "dns_cleanup", provider="powerdns", fqdn=fqdn)


class Rfc2136Provider:
    name, automatic = "rfc2136", True

    def __init__(self, server: str, zone: str, key_name: Optional[str] = None, secret_b64: Optional[str] = None,
                 algorithm: str = "hmac-sha256", ttl: int = 60):
        self.server, self.zone, self.key_name, self.secret, self.algo, self.ttl = server, zone.rstrip("."), key_name, secret_b64, algorithm, ttl

    def _do(self, fqdn, value, add):
        from . import dnsupdate
        try:
            dnsupdate.update_txt(self.server, self.zone, fqdn.rstrip("."), value, add, self.key_name, self.secret, self.algo, self.ttl)
        except dnsupdate.DnsError as e:
            raise DnsProviderError(str(e)) from None
        trace.event("acme", "dns_present" if add else "dns_cleanup", provider="rfc2136", fqdn=fqdn, zone=self.zone)

    def present(self, fqdn, value):
        self._do(fqdn, value, True)

    def cleanup(self, fqdn, value):
        self._do(fqdn, value, False)


# 필수 설정 키(설정 검증과 안내 메시지에 사용)
PROVIDER_REQUIRED = {
    "manual": (), "infoblox": ("host", "user_env", "password_env"), "exec": ("cmd",), "webhook": ("url_env",),
    "rfc2136": ("server", "zone"), "cloudflare": ("token_env",), "powerdns": ("api_url", "api_key_env", "zone"),
}


def _env(environ, name, what):
    v = environ.get(name or "")
    if not v:
        raise DnsProviderError(f"환경변수 {name} 가 설정되지 않았습니다({what})")
    return v


def build_provider(dns_cfg: dict, environ=os.environ):
    mode = dns_cfg.get("mode", "manual")
    c = dns_cfg.get(mode) or {}
    if mode == "manual":
        return ManualProvider()
    if mode == "infoblox":
        user, pw = environ.get(c.get("user_env", "")), environ.get(c.get("password_env", ""))
        if not user or not pw:
            raise DnsProviderError(f"환경변수 {c.get('user_env')} / {c.get('password_env')} 가 설정되지 않았습니다")
        return InfobloxProvider(c["host"], user, pw, c.get("wapi_version", "v2.12"), c.get("view"), c.get("ca_file"),
                                bool(c.get("verify", True)), c.get("ttl"), scheme=c.get("scheme", "https"))
    if mode == "exec":
        return ExecProvider(c["cmd"], int(c.get("timeout", 120)), c.get("env_pass") or (), environ)
    if mode == "webhook":
        return WebhookProvider(_env(environ, c["url_env"], "웹훅 URL"), environ.get(c.get("auth_header_env") or "") or None)
    if mode == "cloudflare":
        return CloudflareProvider(_env(environ, c["token_env"], "API 토큰"), c.get("zone"), c.get("zone_id"),
                                  c.get("api_base", "https://api.cloudflare.com/client/v4"), int(c.get("ttl", 60)))
    if mode == "powerdns":
        return PowerDnsProvider(c["api_url"], _env(environ, c["api_key_env"], "API 키"), c["zone"], c.get("server_id", "localhost"), int(c.get("ttl", 60)))
    if mode == "rfc2136":
        secret = _env(environ, c["tsig_secret_env"], "TSIG 비밀") if c.get("tsig_secret_env") else None
        return Rfc2136Provider(c["server"], c["zone"], c.get("tsig_key_name"), secret, c.get("tsig_algorithm", "hmac-sha256"), int(c.get("ttl", 60)))
    raise DnsProviderError(f"알 수 없는 dns.mode: {mode} (사용 가능: {', '.join(PROVIDER_REQUIRED)})")
