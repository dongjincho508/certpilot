"""설정 파일(YAML) 로드와 검증. 비밀번호·토큰은 설정에 쓰지 않고 환경변수 이름/파일 경로로만 참조한다.

구조: 단일 인증서(최상위 certificate/lego/targets)이거나, `certificates:` 목록으로 여러 인증서를 각각 관리.
"""
import copy
import re
from dataclasses import dataclass, field
from typing import List, Optional

import yaml

from .handlers import FileSpec, SpecError, build_files, default_check, default_reload

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
PATH_BAD = re.compile(r"[\x00-\x1f\n]")
WEBHOOK_FORMATS = ("generic", "slack", "teams", "googlechat", "discord")
SEVERITIES = ("info", "warning", "critical")
ITSM_FORMATS = ("servicenow", "jira", "generic")


class ConfigError(Exception):
    def __init__(self, problems: List[str]):
        super().__init__("설정 오류:\n- " + "\n- ".join(problems))
        self.problems = problems


@dataclass
class Verify:
    host: str
    port: int = 443
    sni: Optional[str] = None
    strict: bool = False              # True: 신뢰 저장소로 체인·호스트명까지 검증
    ca_file: Optional[str] = None     # 사설 CA 인 경우 신뢰할 CA 번들
    lenient_x509: bool = False        # 구형 사설 CA 인증서(확장 누락)용: RFC 5280 엄격 검사만 완화


@dataclass
class Health:
    url: str
    expect: int = 200
    timeout: float = 10.0
    insecure: bool = False            # True: 인증서 검증 없이 확인(내부 주소 등)


@dataclass
class Target:
    name: str
    type: str
    transport: dict
    files: List[FileSpec]
    check_cmd: Optional[str]
    reload_cmd: Optional[str]
    verify: Optional[Verify]
    order: int = 100
    canary: bool = False
    health: Optional[Health] = None
    pre_cmd: Optional[str] = None     # certdeploy 서버에서 실행(실패하면 이 대상은 변경 없이 중단)
    post_cmd: Optional[str] = None    # 성공·롤백 뒤 실행(결과는 환경변수 CERTDEPLOY_STATUS)
    soak_seconds: int = 0             # 배포 후 이 시간 동안 새 인증서가 유지되는지 반복 확인
    soak_interval: int = 10
    hook_env: List[str] = field(default_factory=list)   # 훅에 전달할 환경변수 이름(그 밖의 비밀은 전달하지 않는다)
    api: Optional[dict] = None        # type: http_api (웹방화벽·어플라이언스) 전용: HTTP 요청 단계 설정
    manual: Optional[dict] = None     # type: manual (자동화할 수 없는 장비) 전용: 교체용 파일 준비·안내·확인 설정
    iis: Optional[dict] = None        # type: iis (Windows IIS; SSH+PowerShell) 전용: 바인딩·저장소 설정


@dataclass
class Options:
    verify_attempts: int = 6
    verify_interval: float = 5.0
    keep_backups: int = 3
    min_days: float = 1.0
    command_timeout: int = 60
    lego_backoff_minutes: int = 60    # 발급 실패 후 다음 시도까지 최소 대기(속도 제한 보호)


@dataclass
class SmtpCfg:
    host: str
    sender: str
    to: List[str]
    port: int = 587
    starttls: bool = True
    username: Optional[str] = None
    password_env: Optional[str] = None
    password_file: Optional[str] = None
    on_success: bool = True
    password: Optional[str] = None    # 관리자 화면(settings.json)에서 입력한 비밀번호(YAML 에는 쓰지 않는다)
    min_severity: str = "info"        # 이 심각도 이상만 보낸다(info < warning < critical)


@dataclass
class WebhookCfg:
    url_env: Optional[str] = None
    url_file: Optional[str] = None
    format: str = "generic"
    on_success: bool = False
    url: Optional[str] = None         # 관리자 화면(settings.json)에서 입력한 주소(토큰 포함; YAML 에는 쓰지 않는다)
    min_severity: str = "info"


@dataclass
class ItsmCfg:
    """티켓 시스템(ITSM) 연동: 장애 알림이 생기면 티켓을 만들고, 해소되면 닫는다(같은 대상은 중복 생성하지 않음)."""
    format: str                       # servicenow | jira | generic
    url: str                          # servicenow: 인스턴스 주소 / jira: 서버 주소 / generic: 티켓 생성 POST 주소
    auth: str = "basic"               # basic | bearer
    username: Optional[str] = None
    password: Optional[str] = None    # 관리자 화면에서 입력한 값(YAML 은 password_env)
    password_env: Optional[str] = None
    token: Optional[str] = None       # bearer 토큰(관리자 화면) — YAML 은 token_env
    token_env: Optional[str] = None
    min_severity: str = "warning"
    project: Optional[str] = None     # jira 프로젝트 키
    issue_type: str = "Task"          # jira 이슈 유형
    priority_map: Optional[dict] = None   # {critical: "High", ...}  (jira priority 이름 / servicenow urgency 값)
    assignment_group: Optional[str] = None   # servicenow
    category: Optional[str] = None           # servicenow
    resolve_transition_id: Optional[str] = None   # jira: 해소 시 적용할 전환 ID(없으면 댓글만)
    verify_tls: bool = True
    ca_file: Optional[str] = None


@dataclass
class NotifyCfg:
    alertmanager_url: Optional[str] = None
    smtp: Optional[SmtpCfg] = None
    webhook: Optional[WebhookCfg] = None
    pushgateway_url: Optional[str] = None
    pushgateway_user: Optional[str] = None
    pushgateway_password_env: Optional[str] = None
    metrics_file: Optional[str] = None
    itsm: Optional[ItsmCfg] = None
    repeat_hours: int = 0             # 같은 대상·같은 알림을 이 시간 안에는 다시 보내지 않음(0=항상 보냄)
    state_dir: Optional[str] = None   # 반복 억제·티켓 기록을 두는 곳(parse_config 가 채움)


@dataclass
class CertSet:
    name: str
    cert_file: str
    key_file: str
    key_password_env: Optional[str]
    targets: List[Target]
    options: Options
    notify: NotifyCfg
    lego: Optional[dict]
    state_dir: str                    # 이 인증서의 상태 디렉터리
    audit_dir: Optional[str] = None
    acme: Optional[dict] = None       # 내장 ACME 클라이언트 설정(검증·기본값 적용 후)
    key_encryption: str = "none"      # none: 평문(권한 600) | passphrase: 저장본 개인키를 암호(key_password_env)로 보호
    key_passphrase: Optional[str] = None   # 관리자 화면(settings.json)에서 입력한 암호(있으면 환경변수보다 후순위)
    approval: Optional[dict] = None   # 배포 승인 정책(approval.required 가 true 일 때만 설정됨)


@dataclass
class Config:
    state_dir: str
    certs: List[CertSet]
    options: Options = field(default_factory=Options)
    notify: NotifyCfg = field(default_factory=NotifyCfg)
    audit_dir: Optional[str] = None
    applied: List[str] = field(default_factory=list)      # 관리자 화면(settings.json)에서 적용된 항목
    backup: Optional[dict] = None                         # 백업 자동화 설정(backupjob.parse_backup 로 검증됨)

    def __getattr__(self, name):
        """인증서가 하나일 때 cfg.targets, cfg.cert_file 같은 접근을 그 인증서로 위임(하위 호환)."""
        if name == "certs":      # copy/pickle 중 속성이 아직 없을 때의 무한 재귀 방지
            raise AttributeError(name)
        if name in ("cert_file", "key_file", "key_password_env", "targets", "lego", "acme", "name", "key_encryption", "key_passphrase", "approval") and len(self.certs) == 1:
            return getattr(self.certs[0], name)
        raise AttributeError(name)

    @property
    def alertmanager_url(self):
        return self.notify.alertmanager_url

    def select(self, name: Optional[str]) -> List[CertSet]:
        if not name:
            return self.certs
        found = [c for c in self.certs if c.name == name]
        if not found:
            raise ConfigError([f"알 수 없는 인증서 이름: {name} (사용 가능: {', '.join(c.name for c in self.certs)})"])
        return found


def _abs(path, what, problems):
    if not isinstance(path, str) or not path.startswith("/") or PATH_BAD.search(path):
        problems.append(f"{what}: 절대 경로여야 합니다: {path!r}")


def _merge_defaults(raw: dict, defaults: dict) -> dict:
    out = copy.deepcopy(defaults)
    for k, v in raw.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = {**out[k], **v}
        else:
            out[k] = v
    return out


def _parse_options(data, problems) -> Options:
    opts = Options()
    for k, v in (data or {}).items():
        if not hasattr(opts, k):
            problems.append(f"options.{k}: 알 수 없는 옵션")
        else:
            try:
                setattr(opts, k, type(getattr(opts, k))(v))
            except (TypeError, ValueError):
                problems.append(f"options.{k}: 값이 올바르지 않습니다: {v!r}")
    return opts


def _parse_notify(data, problems) -> NotifyCfg:
    n = NotifyCfg()
    data = data or {}
    n.alertmanager_url = data.get("alertmanager_url")
    n.pushgateway_url = data.get("pushgateway_url")
    n.pushgateway_user = data.get("pushgateway_user")
    n.pushgateway_password_env = data.get("pushgateway_password_env")
    n.metrics_file = data.get("metrics_file")
    if n.metrics_file:
        _abs(n.metrics_file, "notify.metrics_file", problems)
    rh = data.get("repeat_hours", 0)
    if not isinstance(rh, int) or isinstance(rh, bool) or not 0 <= rh <= 720:
        problems.append("notify.repeat_hours 는 0~720 정수여야 합니다")
    else:
        n.repeat_hours = rh
    s = data.get("smtp")
    if s:
        if not s.get("host") or not s.get("from") or not s.get("to"):
            problems.append("notify.smtp: host, from, to 가 필요합니다")
        else:
            to = s["to"] if isinstance(s["to"], list) else [x.strip() for x in str(s["to"]).split(",") if x.strip()]
            n.smtp = SmtpCfg(s["host"], s["from"], to, int(s.get("port", 587)), bool(s.get("starttls", True)),
                             s.get("username"), s.get("password_env"), s.get("password_file"),
                             bool(s.get("on_success", True)), None, _sev(s.get("min_severity", "info"), "notify.smtp", problems))
    w = data.get("webhook")
    if w:
        if not (w.get("url_env") or w.get("url_file")):
            problems.append("notify.webhook: url_env 또는 url_file 이 필요합니다(URL 의 토큰을 설정 파일에 쓰지 않는다)")
        elif w.get("format", "generic") not in WEBHOOK_FORMATS:
            problems.append(f"notify.webhook.format 은 {', '.join(WEBHOOK_FORMATS)} 중 하나여야 합니다")
        else:
            n.webhook = WebhookCfg(w.get("url_env"), w.get("url_file"), w.get("format", "generic"),
                                   bool(w.get("on_success", False)), None, _sev(w.get("min_severity", "info"), "notify.webhook", problems))
    if data.get("itsm"):
        n.itsm = _parse_itsm(data["itsm"], problems)
    return n


def _sev(v, label, problems) -> str:
    if v not in SEVERITIES:
        problems.append(f"{label}.min_severity 는 {', '.join(SEVERITIES)} 중 하나여야 합니다")
        return "info"
    return v


_ITSM_KEYS = {"format", "url", "auth", "username", "password_env", "token_env", "min_severity", "project", "issue_type", "priority_map",
              "assignment_group", "category", "resolve_transition_id", "verify_tls", "ca_file"}


def _parse_itsm(i, problems) -> Optional[ItsmCfg]:
    if not isinstance(i, dict):
        problems.append("notify.itsm 은 매핑이어야 합니다")
        return None
    bad = set(i) - _ITSM_KEYS
    if bad:
        problems.append(f"notify.itsm 의 알 수 없는 키: {', '.join(sorted(bad))}")
    n0 = len(problems)
    fmt = i.get("format")
    if fmt not in ITSM_FORMATS:
        problems.append(f"notify.itsm.format 은 {', '.join(ITSM_FORMATS)} 중 하나여야 합니다")
    url = str(i.get("url", ""))
    if not url.startswith(("http://", "https://")):
        problems.append("notify.itsm.url 은 http(s):// 로 시작해야 합니다")
    auth = i.get("auth", "basic")
    if auth not in ("basic", "bearer"):
        problems.append("notify.itsm.auth 는 basic 또는 bearer 여야 합니다")
    elif auth == "basic" and not (i.get("username") and i.get("password_env")):
        problems.append("notify.itsm: basic 인증에는 username 과 password_env 가 필요합니다(비밀번호를 설정 파일에 쓰지 않는다)")
    elif auth == "bearer" and not i.get("token_env"):
        problems.append("notify.itsm: bearer 인증에는 token_env 가 필요합니다")
    if fmt == "jira" and not i.get("project"):
        problems.append("notify.itsm: jira 에는 project(프로젝트 키)가 필요합니다")
    if i.get("ca_file"):
        _abs(i["ca_file"], "notify.itsm.ca_file", problems)
    pm = i.get("priority_map")
    if pm is not None and (not isinstance(pm, dict) or set(pm) - set(SEVERITIES)):
        problems.append("notify.itsm.priority_map 은 info/warning/critical 키를 가진 매핑이어야 합니다")
    sev = _sev(i.get("min_severity", "warning"), "notify.itsm", problems)
    if len(problems) > n0:
        return None
    return ItsmCfg(fmt, url, auth, i.get("username"), None, i.get("password_env"), None, i.get("token_env"), sev, i.get("project"),
                   str(i.get("issue_type", "Task")), pm, i.get("assignment_group"), i.get("category"),
                   str(i["resolve_transition_id"]) if i.get("resolve_transition_id") is not None else None,
                   bool(i.get("verify_tls", True)), i.get("ca_file"))


def _parse_target(raw, defaults, label_prefix, problems, seen) -> Optional[Target]:
    name = raw.get("name", "") if isinstance(raw, dict) else ""
    if not isinstance(raw, dict) or not NAME_RE.match(str(name)):
        problems.append(f"{label_prefix}: name 은 영문·숫자·._- 64자 이내여야 합니다")
        return None
    raw = _merge_defaults(raw, defaults)
    label = f"target {name}"
    if name in seen:
        problems.append(f"{label}: 이름이 중복됩니다")
    seen.add(name)
    if raw.get("type") == "manual":
        m = raw.get("manual") or {}
        fmts = [str(x) for x in (m.get("formats") or ["pem"])]
        if not set(fmts) <= {"pem", "pfx"}:
            problems.append(f"{label}: manual.formats 는 pem, pfx 만 가능합니다")
        if "pfx" in fmts and not m.get("pfx_password_env"):
            problems.append(f"{label}: manual.formats 에 pfx 가 있으면 pfx_password_env 가 필요합니다")
        if m.get("export_dir"):
            _abs(m["export_dir"], f"{label} manual.export_dir", problems)
        verify = None
        if raw.get("verify"):
            v = raw["verify"]
            if not v.get("host"):
                problems.append(f"{label}: verify.host 가 필요합니다")
            else:
                verify = Verify(v["host"], int(v.get("port", 443)), v.get("sni"), bool(v.get("strict", False)), v.get("ca_file"), bool(v.get("lenient_x509", False)))
        manual = {"instructions": str(m.get("instructions") or ""), "export_dir": m.get("export_dir"), "formats": fmts,
                  "pfx_password_env": m.get("pfx_password_env"), "pfx_alias": m.get("pfx_alias", "server"), "remind_days": int(m.get("remind_days", 3))}
        return Target(name, "manual", {"kind": "manual"}, [], None, None, verify, int(raw.get("order", 100)), bool(raw.get("canary", False)),
                      None, None, None, 0, 10, [], None, manual)
    if raw.get("type") == "http_api":
        from .apideploy import validate_api
        api = validate_api(raw.get("api"), label, problems)
        verify = None
        if raw.get("verify"):
            v = raw["verify"]
            if not v.get("host"):
                problems.append(f"{label}: verify.host 가 필요합니다")
            else:
                verify = Verify(v["host"], int(v.get("port", 443)), v.get("sni"), bool(v.get("strict", False)), v.get("ca_file"), bool(v.get("lenient_x509", False)))
        if not api:
            return None
        return Target(name, "http_api", {"kind": "api"}, [], None, None, verify, int(raw.get("order", 100)), bool(raw.get("canary", False)),
                      None, raw.get("pre_cmd"), raw.get("post_cmd"), 0, 10, [str(x) for x in (raw.get("hook_env") or [])], api)
    if raw.get("type") == "iis":
        from .iisdeploy import validate_iis
        iis = validate_iis(raw.get("iis"), label, problems)
        tr = raw.get("transport") or {}
        if tr.get("kind") != "ssh" or not tr.get("host") or not HOST_RE.match(str(tr.get("host", ""))) or not tr.get("user"):
            problems.append(f"{label}: type: iis 는 ssh transport(host, user; Windows OpenSSH)가 필요합니다")
        verify = None
        if raw.get("verify"):
            v = raw["verify"]
            if not v.get("host"):
                problems.append(f"{label}: verify.host 가 필요합니다")
            else:
                verify = Verify(v["host"], int(v.get("port", 443)), v.get("sni"), bool(v.get("strict", False)), v.get("ca_file"), bool(v.get("lenient_x509", False)))
        if not iis:
            return None
        return Target(name, "iis", tr, [], None, None, verify, int(raw.get("order", 100)), bool(raw.get("canary", False)),
                      None, raw.get("pre_cmd"), raw.get("post_cmd"), 0, 10, [str(x) for x in (raw.get("hook_env") or [])], None, None, iis)
    tr = raw.get("transport") or {"kind": "local"}
    kind = tr.get("kind")
    if kind == "ssh":
        if not tr.get("host") or not HOST_RE.match(str(tr.get("host", ""))) or not tr.get("user"):
            problems.append(f"{label}: ssh transport 에는 host, user 가 필요합니다")
    elif kind != "local":
        problems.append(f"{label}: transport.kind 는 local 또는 ssh 여야 합니다")
    try:
        files = build_files(raw)
    except SpecError as e:
        problems.append(f"{label}: {e}")
        return None
    for f in files:
        _abs(f.dest, f"{label} 파일 경로", problems)
    check = raw.get("check_cmd", default_check(raw))
    reload_cmd = raw.get("reload_cmd", default_reload(raw))
    if raw["type"] in ("nodejs", "tomcat", "webtob", "jeus", "generic") and "reload_cmd" not in raw:
        problems.append(f"{label}: reload_cmd 가 필요합니다(없으면 'none' 으로 명시)")
    if str(reload_cmd).lower() == "none":
        reload_cmd = None
    if str(check).lower() == "none":
        check = None
    verify = None
    if raw.get("verify"):
        v = raw["verify"]
        if not v.get("host"):
            problems.append(f"{label}: verify.host 가 필요합니다")
        else:
            verify = Verify(v["host"], int(v.get("port", 443)), v.get("sni"), bool(v.get("strict", False)), v.get("ca_file"), bool(v.get("lenient_x509", False)))
            if verify.ca_file:
                _abs(verify.ca_file, f"{label} verify.ca_file", problems)
    health = None
    if raw.get("health"):
        h = raw["health"]
        if not str(h.get("url", "")).startswith(("http://", "https://")):
            problems.append(f"{label}: health.url 은 http(s):// 로 시작해야 합니다")
        else:
            health = Health(h["url"], int(h.get("expect", 200)), float(h.get("timeout", 10)), bool(h.get("insecure", False)))
    soak = int(raw.get("soak_seconds", 0))
    if soak and not verify:
        problems.append(f"{label}: soak_seconds 를 쓰려면 verify 가 필요합니다")
    return Target(name, raw["type"], tr, files, check, reload_cmd, verify, int(raw.get("order", 100)),
                  bool(raw.get("canary", False)), health, raw.get("pre_cmd"), raw.get("post_cmd"), soak,
                  int(raw.get("soak_interval", 10)), [str(x) for x in (raw.get("hook_env") or [])])


def _parse_acme(a, label, problems) -> Optional[dict]:
    if not isinstance(a, dict):
        problems.append(f"{label} acme 는 매핑이어야 합니다")
        return None
    out = {"directory": a.get("directory", "https://acme-v02.api.letsencrypt.org/directory"), "email": a.get("email"),
           "domains": [str(d).strip() for d in (a.get("domains") or [])], "key_type": a.get("key_type", "rsa2048"),
           "renew_days": int(a.get("renew_days", 30))}
    if not out["domains"]:
        problems.append(f"{label} acme.domains 가 필요합니다")
    for d in out["domains"]:
        if " " in d or "/" in d or d.count("*") > 1 or ("*" in d and not d.startswith("*.")):
            problems.append(f"{label} acme.domains 형식이 올바르지 않습니다: {d!r}")
    if out["key_type"] not in ("rsa2048", "rsa3072", "rsa4096", "ec256", "ec384"):
        problems.append(f"{label} acme.key_type 이 올바르지 않습니다: {out['key_type']!r}")
    if not (out["directory"].startswith("https://") or out["directory"].startswith("http://127.0.0.1")):
        problems.append(f"{label} acme.directory 는 https:// 여야 합니다")
    dns = a.get("dns") or {}
    mode = dns.get("mode", "manual")
    out["dns"] = {"mode": mode, "check_resolvers": [str(x) for x in (dns.get("check_resolvers") or [])],
                  "propagation_timeout": int(dns.get("propagation_timeout", 300))}
    from .dnsprov import PROVIDER_REQUIRED
    if mode not in PROVIDER_REQUIRED:
        problems.append(f"{label} acme.dns.mode 는 {', '.join(PROVIDER_REQUIRED)} 중 하나여야 합니다")
    elif mode != "manual":
        c = dns.get(mode) or {}
        for k in PROVIDER_REQUIRED[mode]:
            if not c.get(k):
                problems.append(f"{label} acme.dns.{mode}.{k} 가 필요합니다")
        if mode == "rfc2136" and bool(c.get("tsig_key_name")) != bool(c.get("tsig_secret_env")):
            problems.append(f"{label} acme.dns.rfc2136 의 tsig_key_name 과 tsig_secret_env 는 함께 지정해야 합니다")
        out["dns"][mode] = c
    return out


def _parse_certset(spec, name, defaults, state_dir, options, notify, audit_dir, problems, multi, approval_default=None) -> Optional[CertSet]:
    cert = spec.get("certificate") or {}
    lego = spec.get("lego")
    cert_file, key_file = cert.get("cert_file"), cert.get("key_file")
    acme = _parse_acme(spec["acme"], f"[{name}]", problems) if spec.get("acme") else None
    if acme and lego:
        problems.append(f"[{name}] acme 와 lego 를 함께 쓸 수 없습니다")
    cert_state = f"{state_dir.rstrip('/')}/{name}" if multi else state_dir
    if acme and acme["domains"] and not (cert_file and key_file):
        base = acme["domains"][0].replace("*", "_")
        cert_file, key_file = f"{cert_state}/managed/{base}.crt", f"{cert_state}/managed/{base}.key"
    if lego and not (cert_file and key_file):
        if not lego.get("domains"):
            problems.append(f"[{name}] lego.domains 가 필요합니다")
        else:
            from .issuer import lego_output_paths
            cert_file, key_file = lego_output_paths(lego)
    if not cert_file or not key_file:
        problems.append(f"[{name}] certificate.cert_file / key_file 가 필요합니다(또는 lego 설정)")
    else:
        _abs(cert_file, f"[{name}] certificate.cert_file", problems)
        _abs(key_file, f"[{name}] certificate.key_file", problems)
    key_enc = cert.get("key_encryption", "none")
    if key_enc not in ("none", "passphrase"):
        problems.append(f"[{name}] certificate.key_encryption 은 none 또는 passphrase 여야 합니다")
    elif key_enc == "passphrase":
        if not cert.get("key_password_env"):
            problems.append(f"[{name}] key_encryption: passphrase 에는 certificate.key_password_env(암호가 든 환경변수 이름)가 필요합니다")
        if lego:
            problems.append(f"[{name}] lego 엔진은 개인키를 평문으로 저장하므로 key_encryption: passphrase 와 함께 쓸 수 없습니다(내장 acme 또는 수동 import 사용)")
    from .approval import parse_policy
    approval = parse_policy(spec["approval"] if "approval" in spec else approval_default, f"[{name}]", problems)
    targets, seen = [], set()
    for i, raw in enumerate(spec.get("targets") or [], start=1):
        t = _parse_target(raw, defaults, f"[{name}] targets[{i}]", problems, seen)
        if t:
            targets.append(t)
    if not spec.get("targets"):
        problems.append(f"[{name}] targets 가 비어 있습니다")
    return CertSet(name, cert_file or "", key_file or "", cert.get("key_password_env"), targets, options, notify,
                   lego, cert_state, audit_dir, acme, key_enc if key_enc in ("none", "passphrase") else "none", approval=approval)


def parse_config(data: dict) -> Config:
    problems: List[str] = []
    if not isinstance(data, dict):
        raise ConfigError(["최상위가 매핑이 아닙니다"])
    state_dir = data.get("state_dir", "/var/lib/certdeploy")
    _abs(state_dir, "state_dir", problems)
    options = _parse_options(data.get("options"), problems)
    notify = _parse_notify(data.get("notify"), problems)
    audit_dir = data.get("audit_log")
    if audit_dir:
        _abs(audit_dir, "audit_log", problems)
    defaults = data.get("defaults") or {}
    if not isinstance(defaults, dict):
        problems.append("defaults 는 매핑이어야 합니다")
        defaults = {}

    from .backupjob import parse_backup
    backup = parse_backup(data.get("backup"), problems)
    certs: List[CertSet] = []
    if data.get("certificates"):
        if data.get("targets") or data.get("certificate") or data.get("lego") or data.get("acme"):
            problems.append("certificates 와 최상위 targets/certificate/lego/acme 를 함께 쓸 수 없습니다")
        names = set()
        for i, spec in enumerate(data["certificates"], start=1):
            name = spec.get("name", "") if isinstance(spec, dict) else ""
            if not NAME_RE.match(str(name)):
                problems.append(f"certificates[{i}]: name 은 영문·숫자·._- 64자 이내여야 합니다")
                continue
            if name in names:
                problems.append(f"certificates: 이름이 중복됩니다: {name}")
            names.add(name)
            cs = _parse_certset(spec, name, defaults, state_dir, options, notify, audit_dir, problems, True, data.get("approval"))
            if cs:
                certs.append(cs)
    else:
        cs = _parse_certset(data, "default", defaults, state_dir, options, notify, audit_dir, problems, False, data.get("approval"))
        if cs:
            certs.append(cs)
    if problems:
        raise ConfigError(problems)
    notify.state_dir = state_dir
    return Config(state_dir, certs, options, notify, audit_dir, backup=backup)


def load_config(path: str) -> Config:
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except OSError as e:
        raise ConfigError([f"설정 파일을 읽을 수 없습니다: {e}"])
    except yaml.YAMLError as e:
        raise ConfigError([f"YAML 문법 오류: {e}"])
    cfg = parse_config(data)
    from . import settings as _st
    try:
        cfg.applied = _st.apply(cfg, _st.load(cfg.state_dir))
    except _st.SettingsError as e:
        raise ConfigError([str(e)])
    except (KeyError, TypeError, ValueError) as e:       # 손으로 고친 settings.json 의 필수 항목 누락 등
        raise ConfigError([f"관리자 화면 설정 파일(settings.json) 내용이 올바르지 않습니다: {type(e).__name__} {e}"])
    return cfg
