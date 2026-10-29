"""관리자 화면에서 입력한 설정(메일, 인증서별 개인키 보호) — `<state_dir>/settings.json`(0600).

YAML 설정 파일보다 **우선**한다(관리자 화면 값이 있으면 그 값 사용). 파일이 없으면 YAML 그대로 동작하므로
CLI 만으로 운영하는 환경에는 영향이 없다. 비밀번호·암호는 응답/로그에 노출하지 않고(`mask`), 파일은 0600 으로 원자적 기록한다.
"""
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from typing import List, Optional

FILE = "settings.json"
EMAIL = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")
HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
MIN_PASSPHRASE = 12
SEVERITIES = ("info", "warning", "critical")
WEBHOOK_FORMATS = ("generic", "slack", "teams", "googlechat", "discord")
ITSM_FORMATS = ("servicenow", "jira", "generic")
URL_RE = re.compile(r"^https?://[^\s<>\"']+$")


class SettingsError(Exception):
    def __init__(self, problems):
        self.problems = problems if isinstance(problems, list) else [problems]
        super().__init__("; ".join(self.problems))


def path(state_dir: str) -> str:
    return os.path.join(state_dir, FILE)


def load(state_dir: str) -> dict:
    try:
        with open(path(state_dir), encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise SettingsError(f"설정 화면 파일을 읽을 수 없습니다({path(state_dir)}): {type(e).__name__}")
    if not isinstance(data, dict):
        raise SettingsError("설정 화면 파일 형식이 올바르지 않습니다")
    return data


def save(state_dir: str, data: dict, actor: str = "") -> None:
    data = {**data, "version": 1, "updated_at": datetime.now(timezone.utc).isoformat(), "updated_by": actor}
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=state_dir, prefix=".tmp-settings-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path(state_dir))


def normalize_mail(m: dict, previous: Optional[dict] = None) -> dict:
    """입력 검증·정리. 비밀번호가 비어 있으면 기존 값을 유지한다(화면에서 '변경 안 함')."""
    problems = []
    previous = previous or {}
    out = {"enabled": bool(m.get("enabled", True))}
    host = str(m.get("host", "")).strip()
    if out["enabled"]:
        if not host or not HOST.match(host):
            problems.append("SMTP 서버 주소가 올바르지 않습니다")
    try:
        port = int(m.get("port", 587))
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        problems.append("포트는 1~65535 숫자여야 합니다")
        port = 587
    sender = str(m.get("from", "")).strip()
    to_raw = m.get("to", [])
    to = [x.strip() for x in (re.split(r"[,\n;]", to_raw) if isinstance(to_raw, str) else to_raw) if str(x).strip()]
    if out["enabled"]:
        if not EMAIL.match(sender):
            problems.append("발신 주소 형식이 올바르지 않습니다")
        if not to:
            problems.append("수신 주소가 하나 이상 필요합니다")
        bad = [x for x in to if not EMAIL.match(x)]
        if bad:
            problems.append("수신 주소 형식이 올바르지 않습니다: " + ", ".join(bad[:3]))
        if len(to) > 20:
            problems.append("수신 주소는 20개까지 가능합니다")
    username = str(m.get("username", "")).strip()
    pw = m.get("password")
    if pw in (None, ""):
        pw = previous.get("password") if (username and username == previous.get("username")) else None   # 비워 두면 유지(계정이 바뀌면 재입력 필요)
    if "\n" in str(pw or "") or "\r" in str(pw or ""):
        problems.append("비밀번호에 줄바꿈을 넣을 수 없습니다")
    if problems:
        raise SettingsError(problems)
    out.update(host=host, port=port, starttls=bool(m.get("starttls", True)), **{"from": sender}, to=to, username=username or None,
               password=pw or None, on_success=bool(m.get("on_success", True)), min_severity=_sev(m.get("min_severity", previous.get("min_severity", "info"))))
    return out


def _sev(v) -> str:
    if v not in SEVERITIES:
        raise SettingsError("심각도는 info, warning, critical 중 하나여야 합니다")
    return v


def _check_url(u: str, what: str, problems: list) -> None:
    if not URL_RE.match(u) or len(u) > 2000:
        problems.append(f"{what} 주소는 http:// 또는 https:// 로 시작하는 올바른 주소여야 합니다")


def normalize_webhook(w: dict, previous: Optional[dict] = None) -> dict:
    """메신저 웹훅(Teams·Slack·Mattermost·Google Chat·Discord·일반). 주소(토큰 포함)가 비어 있으면 기존 값을 유지."""
    previous = previous or {}
    problems = []
    out = {"enabled": bool(w.get("enabled", True))}
    fmt = w.get("format", previous.get("format", "teams"))
    if fmt not in WEBHOOK_FORMATS:
        problems.append("웹훅 형식은 " + ", ".join(WEBHOOK_FORMATS) + " 중 하나여야 합니다")
    url = str(w.get("url") or "").strip() or previous.get("url") or ""
    if out["enabled"]:
        if not url:
            problems.append("웹훅 주소가 필요합니다")
        else:
            _check_url(url, "웹훅", problems)
    try:
        sev = _sev(w.get("min_severity", previous.get("min_severity", "info")))
    except SettingsError as e:
        problems += e.problems
        sev = "info"
    if problems:
        raise SettingsError(problems)
    out.update(format=fmt, url=url or None, on_success=bool(w.get("on_success", False)), min_severity=sev)
    return out


def normalize_itsm(i: dict, previous: Optional[dict] = None) -> dict:
    """티켓 시스템(ServiceNow·Jira·일반). 비밀번호·토큰이 비어 있으면 기존 값을 유지(계정/방식이 바뀌면 재입력)."""
    previous = previous or {}
    problems = []
    out = {"enabled": bool(i.get("enabled", True))}
    fmt = i.get("format", previous.get("format", "servicenow"))
    if fmt not in ITSM_FORMATS:
        problems.append("티켓 형식은 " + ", ".join(ITSM_FORMATS) + " 중 하나여야 합니다")
    url = str(i.get("url") or "").strip().rstrip("/")
    auth = i.get("auth", previous.get("auth", "basic"))
    if auth not in ("basic", "bearer"):
        problems.append("인증 방식은 basic 또는 bearer 여야 합니다")
    username = str(i.get("username") or "").strip()
    pw, token = i.get("password"), i.get("token")
    if pw in (None, ""):
        pw = previous.get("password") if (auth == "basic" and username and username == previous.get("username")) else None
    if token in (None, ""):
        token = previous.get("token") if auth == "bearer" else None
    for secret in (pw, token):
        if secret and ("\n" in secret or "\r" in secret):
            problems.append("비밀번호·토큰에 줄바꿈을 넣을 수 없습니다")
    project = str(i.get("project") or "").strip()
    if out["enabled"]:
        if not url:
            problems.append("티켓 시스템 주소가 필요합니다")
        else:
            _check_url(url, "티켓 시스템", problems)
        if auth == "basic" and not (username and pw):
            problems.append("basic 인증에는 계정과 비밀번호가 필요합니다")
        if auth == "bearer" and not token:
            problems.append("bearer 인증에는 토큰이 필요합니다")
        if fmt == "jira" and not re.match(r"^[A-Z][A-Z0-9_]{1,19}$", project):
            problems.append("Jira 프로젝트 키(대문자·숫자, 예: CERT)가 필요합니다")
    for k in ("issue_type", "assignment_group", "category", "resolve_transition_id"):
        if len(str(i.get(k) or "")) > 100:
            problems.append(f"{k} 값이 너무 깁니다")
    try:
        sev = _sev(i.get("min_severity", previous.get("min_severity", "warning")))
    except SettingsError as e:
        problems += e.problems
        sev = "warning"
    ca = str(i.get("ca_file") or "").strip()
    if ca and not ca.startswith("/"):
        problems.append("CA 파일은 절대 경로여야 합니다")
    if problems:
        raise SettingsError(problems)
    out.update(format=fmt, url=url, auth=auth, username=username or None, password=pw or None, token=token or None, min_severity=sev,
               project=project or None, issue_type=str(i.get("issue_type") or "Task").strip() or "Task",
               assignment_group=str(i.get("assignment_group") or "").strip() or None, category=str(i.get("category") or "").strip() or None,
               resolve_transition_id=str(i.get("resolve_transition_id") or "").strip() or None, verify_tls=bool(i.get("verify_tls", True)), ca_file=ca or None)
    return out


def normalize_common(c: dict) -> dict:
    try:
        rh = int(c.get("repeat_hours", 0))
        if not 0 <= rh <= 720:
            raise ValueError
    except (TypeError, ValueError):
        raise SettingsError("반복 알림 간격은 0~720 시간 숫자여야 합니다")
    return {"repeat_hours": rh}


def normalize_cert_opts(name: str, o: dict, previous: Optional[dict] = None) -> dict:
    previous = previous or {}
    enc = o.get("key_encryption", previous.get("key_encryption", "none"))
    if enc not in ("none", "passphrase"):
        raise SettingsError(f"{name}: key_encryption 은 none 또는 passphrase 여야 합니다")
    out = {"key_encryption": enc}
    if enc == "passphrase":
        pp = o.get("key_passphrase") or previous.get("key_passphrase")
        if not pp:
            raise SettingsError(f"{name}: 개인키 보호를 사용하려면 암호를 입력해야 합니다")
        if len(pp) < MIN_PASSPHRASE:
            raise SettingsError(f"{name}: 암호는 {MIN_PASSPHRASE}자 이상이어야 합니다")
        if "\n" in pp or "\r" in pp:
            raise SettingsError(f"{name}: 암호에 줄바꿈을 넣을 수 없습니다")
        out["key_passphrase"] = pp
    return out


def mask(data: dict) -> dict:
    """화면·로그용: 비밀번호·암호는 값 대신 설정 여부만."""
    out = json.loads(json.dumps(data))
    mail = out.get("mail")
    if mail:
        mail["password_set"] = bool(mail.pop("password", None))
    wh = out.get("webhook")
    if wh:
        wh["url_set"] = bool(wh.pop("url", None))
    it = out.get("itsm")
    if it:
        it["password_set"] = bool(it.pop("password", None))
        it["token_set"] = bool(it.pop("token", None))
    for c in (out.get("certificates") or {}).values():
        c["passphrase_set"] = bool(c.pop("key_passphrase", None))
    return out


def apply(cfg, st: dict) -> List[str]:
    """설정 화면 값을 Config 에 덮어쓴다. 적용한 항목 목록을 반환."""
    from .config import ItsmCfg, SmtpCfg, WebhookCfg
    notes = []
    mail = st.get("mail")
    if mail is not None:
        if not mail.get("enabled", True):
            cfg.notify.smtp = None
            notes.append("메일: 사용 안 함")
        else:
            cfg.notify.smtp = SmtpCfg(mail["host"], mail["from"], list(mail["to"]), int(mail.get("port", 587)), bool(mail.get("starttls", True)),
                                      mail.get("username"), None, None, bool(mail.get("on_success", True)), mail.get("password"),
                                      mail.get("min_severity", "info"))
            notes.append(f"메일: {mail['host']} → {', '.join(mail['to'])}")
    wh = st.get("webhook")
    if wh is not None:
        if not wh.get("enabled", True):
            cfg.notify.webhook = None
            notes.append("웹훅: 사용 안 함")
        else:
            cfg.notify.webhook = WebhookCfg(None, None, wh.get("format", "generic"), bool(wh.get("on_success", False)), wh.get("url"), wh.get("min_severity", "info"))
            notes.append(f"웹훅: {wh.get('format')}")
    it = st.get("itsm")
    if it is not None:
        if not it.get("enabled", True):
            cfg.notify.itsm = None
            notes.append("티켓: 사용 안 함")
        else:
            cfg.notify.itsm = ItsmCfg(it["format"], it["url"], it.get("auth", "basic"), it.get("username"), it.get("password"), None, it.get("token"), None,
                                      it.get("min_severity", "warning"), it.get("project"), it.get("issue_type", "Task"), None, it.get("assignment_group"),
                                      it.get("category"), it.get("resolve_transition_id"), bool(it.get("verify_tls", True)), it.get("ca_file"))
            notes.append(f"티켓: {it['format']}")
    common = st.get("notify_common")
    if common is not None:
        cfg.notify.repeat_hours = int(common.get("repeat_hours", 0))
        notes.append(f"반복 알림 간격: {cfg.notify.repeat_hours}시간")
    for cs in cfg.certs:
        o = (st.get("certificates") or {}).get(cs.name)
        if o:
            cs.key_encryption = o.get("key_encryption", cs.key_encryption)
            cs.key_passphrase = o.get("key_passphrase")
            notes.append(f"개인키 보호({cs.name}): {'사용' if cs.key_encryption == 'passphrase' else '사용 안 함'}")
    return notes
