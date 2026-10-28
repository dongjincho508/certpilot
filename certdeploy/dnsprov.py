"""ACME DNS-01 용 DNS 제공자. present/cleanup 은 TXT 레코드를 만들고 지운다.

- InfobloxProvider: Infoblox WAPI 로 TXT 를 자동 등록·삭제(연동 모드).  ※ 엔드포인트는 WAPI 문서 기준이며 실제 장비로는 검증하지 못했다.
- ManualProvider: API 없이 사람이 DNS 관리 화면에서 TXT 를 등록하는 모드. present 는 아무것도 하지 않는다(안내는 호출부가 출력).
"""
import base64
import json
import os
import ssl
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


def build_provider(dns_cfg: dict, environ=os.environ):
    mode = dns_cfg.get("mode", "manual")
    if mode == "manual":
        return ManualProvider()
    if mode == "infoblox":
        i = dns_cfg.get("infoblox") or {}
        user, pw = environ.get(i.get("user_env", "")), environ.get(i.get("password_env", ""))
        if not user or not pw:
            raise DnsProviderError(f"환경변수 {i.get('user_env')} / {i.get('password_env')} 가 설정되지 않았습니다")
        return InfobloxProvider(i["host"], user, pw, i.get("wapi_version", "v2.12"), i.get("view"), i.get("ca_file"),
                                bool(i.get("verify", True)), i.get("ttl"), scheme=i.get("scheme", "https"))
    raise DnsProviderError(f"알 수 없는 dns.mode: {mode}")
