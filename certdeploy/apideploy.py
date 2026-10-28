"""HTTP API 배포(웹방화벽·로드밸런서·어플라이언스): 제품마다 다른 관리 API 를 설정(steps)으로 기술해 인증서를 올린다.

`type: http_api` 대상은 파일을 복사하는 대신 설정에 적은 HTTP 요청 순서(로그인 → 인증서 업로드 → 적용 …)를 실행한다.
- 자리표시자: {cert_pem} {chain_pem} {fullchain_pem} {key_pem} {pfx_b64} {pfx_password} {serial} {not_after} {name},
  이전 배포본 {prev_*}(rollback_steps 에서), 환경변수 {env:이름}, 설정 vars, 앞 단계에서 추출한 값.
- 본문: json(객체) | form(객체) | body(문자열) | multipart(fields, files). 세션 쿠키는 단계 사이에 유지된다.
- 단계 옵션 wait(초): 성공 후 대기(예: '적용' 뒤 장비가 반영될 시간).
- 성공 판정: expect_status(기본 2xx) + expect_body(정규식) + expect_json({"$.code": 0}). 추출: extract {변수: "$.a.b" | "header:이름" | "regex:패턴"}.
- 실패하면 rollback_steps 를 이전 배포본으로 실행하고, finally_steps(예: 로그아웃)는 항상 실행한다.
요청 본문(개인키 포함)은 트레이스·로그에 남기지 않는다.
"""
import http.cookiejar
import json
import os
import re
import shutil
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Dict, List, Optional

from certpilot_core import trace

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
BUILTIN = {"cert_pem", "chain_pem", "fullchain_pem", "key_pem", "pfx_b64", "pfx_password", "serial", "not_after", "name"}
TOKEN = re.compile(r"\{(env:)?([A-Za-z_][A-Za-z0-9_]*)\}")
STEP_KEYS = {"name", "method", "url", "headers", "json", "form", "body", "multipart", "expect_status", "expect_body", "expect_json", "extract", "timeout", "wait"}
SECRET_VARS = {"key_pem", "pfx_b64", "pfx_password"}


class ApiError(Exception):
    pass


def referenced(obj) -> List[tuple]:
    """구조 안의 모든 자리표시자 [(is_env, name)]."""
    out = []
    if isinstance(obj, str):
        out += [(bool(m.group(1)), m.group(2)) for m in TOKEN.finditer(obj)]
    elif isinstance(obj, dict):
        for v in obj.values():
            out += referenced(v)
    elif isinstance(obj, list):
        for v in obj:
            out += referenced(v)
    return out


def validate_api(api, label: str, problems: List[str]) -> Optional[dict]:
    """설정 검증. 알 수 없는 자리표시자·누락 항목을 찾는다(실행 중 오류를 설정 단계에서 막는다)."""
    if not isinstance(api, dict):
        problems.append(f"{label}: api 설정이 필요합니다")
        return None
    base = str(api.get("base_url", ""))
    if base and not base.startswith(("http://", "https://")):
        problems.append(f"{label}: api.base_url 은 http(s):// 로 시작해야 합니다")
    steps = api.get("steps")
    if not steps or not isinstance(steps, list):
        problems.append(f"{label}: api.steps 가 필요합니다")
        return None
    known = set(BUILTIN) | {f"prev_{n}" for n in BUILTIN if n not in ("pfx_password", "name")} | set((api.get("vars") or {}).keys())
    ok = True
    for group in ("steps", "rollback_steps", "finally_steps"):
        local = set(known)
        for i, st in enumerate(api.get(group) or [], start=1):
            tag = f"{label} api.{group}[{i}]"
            if not isinstance(st, dict) or not st.get("name"):
                problems.append(f"{tag}: name 이 필요합니다"); ok = False; continue
            extra = set(st) - STEP_KEYS
            if extra:
                problems.append(f"{tag}: 알 수 없는 항목 {sorted(extra)}"); ok = False
            if str(st.get("method", "")).upper() not in METHODS:
                problems.append(f"{tag}: method 는 {', '.join(METHODS)} 중 하나여야 합니다"); ok = False
            url = str(st.get("url", ""))
            if not url or not (url.startswith(("http://", "https://")) or (base and url.startswith("/"))):
                problems.append(f"{tag}: url 은 절대 URL 이거나 base_url 이 있을 때 '/' 로 시작해야 합니다"); ok = False
            if sum(k in st for k in ("json", "form", "body", "multipart")) > 1:
                problems.append(f"{tag}: json/form/body/multipart 는 하나만 쓸 수 있습니다"); ok = False
            for is_env, name in referenced({k: v for k, v in st.items() if k != "extract"}):
                if not is_env and name not in local:
                    problems.append(f"{tag}: 알 수 없는 자리표시자 {{{name}}} (앞 단계 extract 나 vars 에 정의하세요)"); ok = False
                if not is_env and name.startswith("prev_") and group == "steps":
                    problems.append(f"{tag}: {{{name}}} 는 rollback_steps 에서만 쓸 수 있습니다"); ok = False
            local |= set((st.get("extract") or {}).keys())
        if group == "steps":
            known |= local - known
    if {"pfx_b64", "pfx_password"} & {n for _, n in referenced(api)} and not api.get("pfx_password_env"):
        problems.append(f"{label}: pfx_b64/pfx_password 를 쓰려면 api.pfx_password_env 가 필요합니다")
        ok = False
    return api if ok else None


def jsonpath(obj, path: str):
    """`$.a.b[0].c` 만 지원하는 최소 경로 조회. 없으면 None."""
    cur = obj
    for key, idx in re.findall(r"\.([A-Za-z0-9_\-]+)|\[(\d+)\]", path[1:] if path.startswith("$") else path):
        try:
            cur = cur[int(idx)] if idx != "" else cur[key]
        except (KeyError, IndexError, TypeError):
            return None
    return cur


def _multipart(fields: dict, files: dict):
    boundary = "----certdeploy" + uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    for k, f in files.items():
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; filename="{f.get("filename", k)}"\r\n'
                      f'Content-Type: {f.get("content_type", "application/octet-stream")}\r\n\r\n').encode() + str(f["content"]).encode() + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


class ApiRunner:
    def __init__(self, api: dict, name: str, environ=os.environ, sleep=time.sleep):
        self.api, self.name, self.env, self.sleep = api, name, environ, sleep
        self.timeout = float(api.get("timeout", 30))
        ctx = ssl.create_default_context(cafile=api.get("ca_file")) if api.get("ca_file") else ssl.create_default_context()
        if api.get("verify_tls") is False:
            ctx = ssl._create_unverified_context()            # nosec B323 — 관리 인터페이스의 자체 서명 인증서를 운영자가 명시적으로 허용한 경우만
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(self.jar))
        self.vars: Dict[str, str] = {}

    # ---- 변수
    def bundle_vars(self, bundle, prefix: str = "") -> Dict[str, str]:
        v = {"cert_pem": bundle.cert_pem().decode(), "chain_pem": bundle.chain_pem().decode(), "fullchain_pem": bundle.fullchain_pem().decode(),
             "key_pem": bundle.key_pem().decode(), "serial": f"{bundle.serial:x}", "not_after": bundle.not_after.isoformat()}
        pw = self.env.get(self.api.get("pfx_password_env") or "")
        if pw:
            import base64
            v["pfx_password"] = pw
            v["pfx_b64"] = base64.b64encode(bundle.pkcs12(pw, self.api.get("pfx_alias", "waf"))).decode()
        return {prefix + k: x for k, x in v.items()}

    def render(self, obj):
        if isinstance(obj, str):
            def sub(m):
                if m.group(1):
                    val = self.env.get(m.group(2))
                    if val is None:
                        raise ApiError(f"환경변수 {m.group(2)} 가 설정되지 않았습니다")
                    return val
                if m.group(2) not in self.vars:
                    raise ApiError(f"변수 {m.group(2)} 를 알 수 없습니다")
                return str(self.vars[m.group(2)])
            return TOKEN.sub(sub, obj)
        if isinstance(obj, dict):
            return {k: self.render(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.render(v) for v in obj]
        return obj

    # ---- 실행
    def _url(self, step) -> str:
        u = self.render(step["url"])
        return u if u.startswith(("http://", "https://")) else self.api["base_url"].rstrip("/") + u

    def run_step(self, step: dict) -> None:
        method, url = step["method"].upper(), self._url(step)
        headers = {k: str(v) for k, v in self.render(step.get("headers") or {}).items()}
        data = None
        if "json" in step:
            data = json.dumps(self.render(step["json"])).encode()
            headers.setdefault("Content-Type", "application/json")
        elif "form" in step:
            data = urllib.parse.urlencode(self.render(step["form"])).encode()
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif "body" in step:
            data = self.render(step["body"]).encode()
        elif "multipart" in step:
            mp = self.render(step["multipart"])
            data, ctype = _multipart(mp.get("fields") or {}, mp.get("files") or {})
            headers["Content-Type"] = ctype
        shown = url.split("?", 1)[0]
        t0 = time.monotonic()
        try:
            with self.opener.open(urllib.request.Request(url, data=data, method=method, headers=headers), timeout=float(step.get("timeout", self.timeout))) as r:
                status, rheaders, body = r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            status, rheaders, body = e.code, dict(e.headers), e.read()
        except (OSError, ValueError) as e:
            trace.event("api", step["name"], "error", method=method, url=shown, error=type(e).__name__, message=str(e))
            raise ApiError(f"[{step['name']}] 요청 실패: {type(e).__name__}: {e}") from None
        text = body.decode("utf-8", "replace")
        problem = self._check(step, status, text)
        trace.event("api", step["name"], "error" if problem else "info", method=method, url=shown, status=status,
                    ms=round((time.monotonic() - t0) * 1000), **({"response": text[:300]} if problem else {}))
        if problem:
            raise ApiError(f"[{step['name']}] {problem} (HTTP {status}): {text.strip()[:200]}")
        parsed = None
        for var, how in (step.get("extract") or {}).items():
            if how.startswith("header:"):
                val = {k.lower(): v for k, v in rheaders.items()}.get(how[7:].lower())
            elif how.startswith("regex:"):
                m = re.search(how[6:], text)
                val = m.group(1) if m and m.groups() else (m.group(0) if m else None)
            else:
                try:
                    parsed = parsed if parsed is not None else json.loads(text)
                except ValueError:
                    parsed = {}
                val = jsonpath(parsed, how)
            if val is None:
                raise ApiError(f"[{step['name']}] 응답에서 {var} 를 추출하지 못했습니다({how})")
            self.vars[var] = str(val)
        if step.get("wait"):                                   # 적용 후 장비가 반영될 시간(초)을 기다린 뒤 다음 단계/확인으로
            self.sleep(float(step["wait"]))

    @staticmethod
    def _check(step, status, text) -> Optional[str]:
        if status not in (step.get("expect_status") or (200, 201, 202, 204)):
            return "예상하지 않은 응답"
        if step.get("expect_body") and not re.search(step["expect_body"], text):
            return f"응답 본문에 /{step['expect_body']}/ 가 없음"
        if step.get("expect_json"):
            try:
                doc = json.loads(text)
            except ValueError:
                return "JSON 응답이 아님"
            for path, want in step["expect_json"].items():
                if jsonpath(doc, path) != want:
                    return f"{path} 가 {want!r} 이 아님(실제 {jsonpath(doc, path)!r})"
        return None

    def run(self, steps: List[dict]) -> None:
        for st in steps:
            self.run_step(st)


# ---- 배포본 보관(롤백용): current = 장비에 올라가 있는 마지막 성공 배포본, previous = 그 이전 배포본
def prev_dir(state_dir: str, target: str, which: str = "current") -> str:
    return os.path.join(state_dir, "api-bundles", target, which)


def _write_bundle(d: str, bundle) -> None:
    os.makedirs(d, mode=0o700, exist_ok=True)
    for fname, data in (("fullchain.pem", bundle.fullchain_pem()), ("key.pem", bundle.key_pem())):
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, os.path.join(d, fname))


def save_prev(state_dir: str, target: str, bundle) -> None:
    """성공한 배포본을 current 로 저장하고, 기존 current 는 previous 로 넘긴다."""
    cur, prev = prev_dir(state_dir, target, "current"), prev_dir(state_dir, target, "previous")
    if os.path.isdir(cur):
        shutil.rmtree(prev, ignore_errors=True)
        os.replace(cur, prev)
    _write_bundle(cur, bundle)


def load_prev(state_dir: str, target: str, which: str = "current"):
    from .bundle import BundleError, load_bundle
    d = prev_dir(state_dir, target, which)
    try:
        return load_bundle(os.path.join(d, "fullchain.pem"), os.path.join(d, "key.pem"), None)
    except (BundleError, OSError):
        return None


def promote_previous(state_dir: str, target: str) -> None:
    """수동 롤백 성공 후: previous 가 장비의 현재 인증서가 된다."""
    cur, prev = prev_dir(state_dir, target, "current"), prev_dir(state_dir, target, "previous")
    shutil.rmtree(cur, ignore_errors=True)
    if os.path.isdir(prev):
        os.replace(prev, cur)


def plan_lines(api: dict) -> List[str]:
    out = [f"    API 단계(본문·비밀은 표시하지 않음), 기준 주소 {api.get('base_url', '(단계별 절대 URL)')}"]
    for group, label in (("steps", "실행"), ("rollback_steps", "실패 시 롤백"), ("finally_steps", "항상")):
        for st in api.get(group) or []:
            out.append(f"      [{label}] {st['name']}: {st['method'].upper()} {str(st['url']).split('?')[0]}")
    return out
