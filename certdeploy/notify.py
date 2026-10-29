"""알림 채널: Alertmanager(API v2), SMTP 메일, 웹훅(Slack·Mattermost·Teams·Google Chat·Discord·일반), 티켓(ServiceNow·Jira·일반). 알림 실패가 배포를 막지 않는다.

- fire/resolve: 대상별 배포 실패 발생·해소
- summary: 실행 1회가 끝났을 때의 요약(성공 요약은 설정에서 켠 채널에만)
"""
import base64
import json
import logging
import os
import smtplib
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Callable, List, Optional

from certpilot_core import netutil, trace

log = logging.getLogger("certdeploy")

SEV_RANK = {"info": 0, "warning": 1, "critical": 2}


def sev_ok(severity: str, minimum: str) -> bool:
    return SEV_RANK.get(severity, 2) >= SEV_RANK.get(minimum, 0)


class Throttle:
    """같은 대상의 같은 알림을 repeat_hours 안에는 다시 보내지 않는다(채널별). 해소(resolve)되면 기록을 지워 다음 장애는 바로 알린다."""

    def __init__(self, state_dir: Optional[str], hours: int, clock: Callable[[], float] = time.time):
        self.path = os.path.join(state_dir, "notify-state.json") if state_dir else None
        self.hours, self.clock = hours, clock

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError, TypeError):
            return {}

    def _save(self, data: dict) -> None:
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path), prefix=".notify-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def allow(self, channel: str, target: str, summary: str) -> bool:
        if not self.hours or not self.path:
            return True
        key, now = f"{channel}|{target}|{summary}", self.clock()
        data = self._load()
        last = data.get(key)
        if last is not None and now - last < self.hours * 3600:
            trace.event("notify", "throttled", channel=channel, target=target)
            return False
        data[key] = now
        data = {k: v for k, v in data.items() if now - v < max(self.hours, 1) * 3600 * 4}      # 오래된 기록 정리
        try:
            self._save(data)
        except OSError:
            pass
        return True

    def clear(self, target: str) -> None:
        if not self.hours or not self.path:
            return
        data = self._load()
        keep = {k: v for k, v in data.items() if k.split("|")[1:2] != [target]}
        if keep != data:
            try:
                self._save(keep)
            except OSError:
                pass


class NullNotifier:
    def fire(self, target, summary, description, severity="critical"):
        pass

    def resolve(self, target):
        pass

    def summary(self, title: str, text: str, ok: bool):
        pass


class AlertmanagerNotifier(NullNotifier):
    ALERT = "CertDeployFailed"

    def __init__(self, url: str, timeout: float = 10.0, clock=lambda: datetime.now(timezone.utc)):
        self.url = url.rstrip("/") + "/api/v2/alerts"
        self.timeout, self.clock = timeout, clock

    def _post(self, alerts):
        req = urllib.request.Request(self.url, data=json.dumps(alerts).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            netutil.urlopen(req, timeout=self.timeout).read()
        except OSError as e:
            log.warning("Alertmanager 알림 전송 실패: %s", type(e).__name__)
            trace.event("notify", "alertmanager", "error", url=self.url, error=type(e).__name__, message=str(e))

    def _alert(self, target, starts_at, ends_at, summary="", description="", severity="critical"):
        return {"labels": {"alertname": self.ALERT, "severity": severity, "target": target, "service": "certdeploy"},
                "annotations": {"summary": summary, "description": description},
                "startsAt": starts_at.isoformat(), "endsAt": ends_at.isoformat()}

    def fire(self, target, summary, description, severity="critical"):
        now = self.clock()
        self._post([self._alert(target, now, now + timedelta(hours=24), summary, description, severity)])

    def resolve(self, target):
        now = self.clock()
        self._post([self._alert(target, now - timedelta(minutes=1), now)])


def _read_secret(env_name: Optional[str], file_path: Optional[str], environ=os.environ) -> Optional[str]:
    if env_name and environ.get(env_name):
        return environ[env_name]
    if file_path:
        try:
            with open(file_path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return None
    return None


class SmtpNotifier(NullNotifier):
    """실패는 항상 메일로, 요약은 on_success 가 켜져 있을 때만(실패 요약은 항상)."""

    def __init__(self, cfg, environ=os.environ, smtp_factory: Callable = smtplib.SMTP, prefix="[certdeploy]", throttle: Optional[Throttle] = None):
        self.cfg, self.environ, self.factory, self.prefix, self.throttle = cfg, environ, smtp_factory, prefix, throttle

    def _send(self, subject: str, body: str):
        c = self.cfg
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = c.sender, ", ".join(c.to), f"{self.prefix} {subject}"
        msg.set_content(body)
        try:
            with self.factory(c.host, c.port, timeout=20) as s:
                if c.starttls:
                    s.starttls(context=ssl.create_default_context())
                pw = c.password or _read_secret(c.password_env, c.password_file, self.environ)
                if c.username and pw:
                    s.login(c.username, pw)
                s.send_message(msg)
        except (OSError, smtplib.SMTPException) as e:
            log.warning("메일 전송 실패: %s", type(e).__name__)
            trace.event("notify", "smtp", "error", host=c.host, port=c.port, error=type(e).__name__, message=str(e))

    def fire(self, target, summary, description, severity="critical"):
        if not sev_ok(severity, self.cfg.min_severity) or (self.throttle and not self.throttle.allow("mail", target, summary)):
            return
        self._send(f"{severity.upper()} {summary}", f"{summary}\n\n{description}\n")

    def resolve(self, target):
        if self.throttle:
            self.throttle.clear(target)

    def summary(self, title, text, ok):
        if (ok and not self.cfg.on_success) or not sev_ok("info" if ok else "critical", self.cfg.min_severity):
            return
        self._send(("완료 " if ok else "실패 ") + title, text)


class MailTestError(Exception):
    """시험 메일 실패 원인(사람이 고칠 수 있게 분류한 한국어 메시지). 비밀번호는 포함하지 않는다."""


def send_test_mail(cfg, environ=os.environ, smtp_factory: Callable = smtplib.SMTP) -> None:
    """설정(SmtpCfg)대로 시험 메일 1통을 보낸다. 실패하면 원인을 분류해 MailTestError 로 알린다."""
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = cfg.sender, ", ".join(cfg.to), "[certdeploy] 메일 알림 시험"
    msg.set_content("certdeploy 메일 알림 시험입니다. 이 메일이 도착했다면 설정이 올바른 것이며, 무시하셔도 됩니다.\n")
    try:
        with smtp_factory(cfg.host, cfg.port, timeout=20) as s:
            if cfg.starttls:
                s.starttls(context=ssl.create_default_context())
            pw = cfg.password or _read_secret(cfg.password_env, cfg.password_file, environ)
            if cfg.username and pw:
                s.login(cfg.username, pw)
            s.send_message(msg)
    except smtplib.SMTPAuthenticationError:
        raise MailTestError("로그인 실패: 계정 또는 비밀번호를 확인하세요") from None
    except smtplib.SMTPRecipientsRefused:
        raise MailTestError("수신 주소가 거부되었습니다(릴레이 허용·수신 도메인 확인)") from None
    except smtplib.SMTPSenderRefused:
        raise MailTestError("발신 주소가 거부되었습니다(릴레이에서 허용된 발신 주소 확인)") from None
    except ssl.SSLError as e:
        raise MailTestError(f"TLS 오류: STARTTLS 사용 여부·포트(587/465/25)·서버 인증서를 확인하세요({type(e).__name__})") from None
    except smtplib.SMTPNotSupportedError:
        raise MailTestError("서버가 STARTTLS 또는 로그인을 지원하지 않습니다(STARTTLS·계정 설정 확인)") from None
    except smtplib.SMTPServerDisconnected:
        raise MailTestError("서버가 연결을 끊었습니다(포트·STARTTLS 설정이 맞는지 확인)") from None
    except smtplib.SMTPException as e:
        raise MailTestError(f"SMTP 오류: {type(e).__name__}") from None
    except TimeoutError:
        raise MailTestError("시간 초과: 서버 주소·포트·방화벽을 확인하세요") from None
    except ConnectionRefusedError:
        raise MailTestError("연결 거부: 서버 주소·포트를 확인하세요") from None
    except OSError as e:
        raise MailTestError(f"접속 실패: {type(e).__name__}(주소 해석·방화벽 확인)") from None


class NotifyTestError(Exception):
    """채널 시험 실패 원인(사람이 고칠 수 있게 분류한 한국어 메시지). 비밀번호·토큰·URL 은 포함하지 않는다."""


def _classify_http(e: Exception, what: str) -> NotifyTestError:
    if isinstance(e, urllib.error.HTTPError):
        code = e.code
        hint = {401: "인증 실패(계정·비밀번호·토큰 확인)", 403: "권한 없음(계정 권한·IP 허용 확인)", 404: "주소를 찾을 수 없음(URL·프로젝트 키 확인)",
                400: "요청이 거부됨(형식·필수 필드 확인)", 429: "요청 한도 초과(잠시 후 다시)"}.get(code, f"서버 오류 응답({code})")
        return NotifyTestError(f"{what}: {hint}")
    if isinstance(e, ssl.SSLError) or (isinstance(e, urllib.error.URLError) and isinstance(e.reason, ssl.SSLError)):
        return NotifyTestError(f"{what}: TLS 오류 — 서버 인증서를 신뢰할 수 없습니다(사내 CA 이면 ca_file 지정)")
    if isinstance(e, TimeoutError):
        return NotifyTestError(f"{what}: 시간 초과(주소·방화벽·프록시 확인)")
    return NotifyTestError(f"{what}: 접속 실패({type(e).__name__}) — 주소·방화벽·DNS 확인")


class WebhookNotifier(NullNotifier):
    def __init__(self, cfg, environ=os.environ, timeout: float = 10.0, throttle: Optional[Throttle] = None):
        self.cfg, self.environ, self.timeout, self.throttle = cfg, environ, timeout, throttle

    def _url(self) -> Optional[str]:
        return self.cfg.url or _read_secret(self.cfg.url_env, self.cfg.url_file, self.environ)

    def payload(self, title: str, text: str, ok: bool) -> dict:
        icon = "✅" if ok else "🚨"
        full = f"{icon} {title}\n{text}"
        f = self.cfg.format
        if f == "slack":                       # Slack · Mattermost 호환
            return {"text": full}
        if f == "googlechat":
            return {"text": full}
        if f == "discord":
            return {"content": full[:1900]}
        if f == "teams":                       # Teams Workflows(Adaptive Card) 웹훅 형식 — 환경에서 확인 필요
            return {"type": "message", "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
                "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                            "version": "1.4", "body": [
                                {"type": "TextBlock", "text": f"{icon} {title}", "weight": "Bolder", "wrap": True},
                                {"type": "TextBlock", "text": text, "wrap": True}]}}]}
        return {"title": title, "text": text, "ok": ok, "source": "certdeploy"}

    def _post(self, title, text, ok, raise_errors=False):
        url = self._url()
        if not url:
            if raise_errors:
                raise NotifyTestError("웹훅 주소가 설정되어 있지 않습니다")
            log.warning("웹훅 URL 을 읽을 수 없어 알림을 건너뜀")
            return
        req = urllib.request.Request(url, data=json.dumps(self.payload(title, text, ok)).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            netutil.urlopen(req, timeout=self.timeout).read()
        except (OSError, ValueError) as e:
            log.warning("웹훅 알림 전송 실패: %s", type(e).__name__)
            trace.event("notify", "webhook", "error", error=type(e).__name__)      # 주소에 토큰이 있을 수 있어 메시지는 남기지 않는다
            if raise_errors:
                raise _classify_http(e, "웹훅") from None

    def fire(self, target, summary, description, severity="critical"):
        if not sev_ok(severity, self.cfg.min_severity) or (self.throttle and not self.throttle.allow("webhook", target, summary)):
            return
        self._post(summary, description, False)

    def resolve(self, target):
        if self.throttle:
            self.throttle.clear(target)

    def summary(self, title, text, ok):
        if (ok and not self.cfg.on_success) or not sev_ok("info" if ok else "critical", self.cfg.min_severity):
            return
        self._post(title, text, ok)


def send_test_webhook(cfg, environ=os.environ) -> None:
    """설정대로 시험 메시지 1건을 보낸다. 실패하면 원인을 분류해 NotifyTestError."""
    WebhookNotifier(cfg, environ)._post("certdeploy 웹훅 알림 시험", "이 메시지가 보이면 설정이 올바른 것입니다. 무시하셔도 됩니다.", True, raise_errors=True)


class ItsmNotifier(NullNotifier):
    """티켓 시스템: 장애 알림(fire)이 처음 생기면 티켓을 만들고, 해소(resolve)되면 닫는다. 같은 대상의 열린 티켓이 있으면 새로 만들지 않는다.
    열린 티켓 기록은 `<state_dir>/tickets.json`(대상 → 티켓 식별자). 형식: ServiceNow(Table API), Jira(REST v2), 일반(JSON POST)."""

    def __init__(self, cfg, environ=os.environ, state_dir: Optional[str] = None, timeout: float = 15.0):
        self.cfg, self.environ, self.timeout = cfg, environ, timeout
        self.path = os.path.join(state_dir, "tickets.json") if state_dir else None

    # ---- 인증·HTTP
    def _headers(self) -> dict:
        c = self.cfg
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if c.auth == "bearer":
            tok = c.token or _read_secret(c.token_env, None, self.environ)
            if not tok:
                raise NotifyTestError("인증 토큰이 설정되어 있지 않습니다")
            h["Authorization"] = f"Bearer {tok}"
        else:
            pw = c.password or _read_secret(c.password_env, None, self.environ)
            if not (c.username and pw):
                raise NotifyTestError("계정 또는 비밀번호가 설정되어 있지 않습니다")
            h["Authorization"] = "Basic " + base64.b64encode(f"{c.username}:{pw}".encode()).decode()
        return h

    def _ctx(self):
        c = self.cfg
        if not c.url.startswith("https"):
            return None
        if not c.verify_tls:
            return ssl._create_unverified_context()  # nosec B323 — 관리자가 명시적으로 끈 경우에만(시험 환경용)
        return ssl.create_default_context(cafile=c.ca_file)

    def _call(self, method: str, url: str, body: Optional[dict] = None) -> dict:
        req = urllib.request.Request(netutil.http_url(url), data=json.dumps(body).encode() if body is not None else None, method=method,
                                     headers=self._headers())
        with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx()) as r:   # nosec B310 — 스킴은 http_url 로 검증
            raw = r.read()
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            return {}

    def _base(self) -> str:
        return self.cfg.url.rstrip("/")

    # ---- 기록
    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError, TypeError):
            return {}

    def _store(self, data: dict) -> None:
        if not self.path:
            return
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path), prefix=".tickets-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    # ---- 형식별 본문
    def _prio(self, severity: str) -> str:
        m = self.cfg.priority_map or {}
        d = {"jira": {"critical": "Highest", "warning": "High", "info": "Medium"}, "servicenow": {"critical": "1", "warning": "2", "info": "3"}}
        return str(m.get(severity) or d.get(self.cfg.format, {}).get(severity, "3"))

    def _create(self, target: str, summary: str, description: str, severity: str) -> dict:
        c = self.cfg
        if c.format == "servicenow":
            body = {"short_description": summary[:160], "description": description, "urgency": self._prio(severity), "impact": self._prio(severity)}
            if c.assignment_group:
                body["assignment_group"] = c.assignment_group
            if c.category:
                body["category"] = c.category
            r = self._call("POST", self._base() + "/api/now/table/incident", body).get("result") or {}
            return {"id": r.get("sys_id"), "ref": r.get("number")}
        if c.format == "jira":
            fields = {"project": {"key": c.project}, "summary": summary[:250], "description": description, "issuetype": {"name": c.issue_type},
                      "priority": {"name": self._prio(severity)}}
            r = self._call("POST", self._base() + "/rest/api/2/issue", {"fields": fields})
            return {"id": r.get("key"), "ref": r.get("key")}
        r = self._call("POST", c.url, {"event": "fire", "target": target, "title": summary, "text": description, "severity": severity, "source": "certdeploy"})
        return {"id": str(r.get("id") or r.get("key") or target), "ref": str(r.get("id") or r.get("key") or "")}

    def _close(self, target: str, ticket: dict) -> None:
        c = self.cfg
        if c.format == "servicenow":
            self._call("PATCH", f"{self._base()}/api/now/table/incident/{urllib.parse.quote(str(ticket['id']), safe='')}",
                       {"state": "6", "close_code": "Solved (Permanently)", "close_notes": "certdeploy: 문제가 해소되어 자동으로 닫았습니다."})
        elif c.format == "jira":
            key = urllib.parse.quote(str(ticket["id"]), safe="")
            self._call("POST", f"{self._base()}/rest/api/2/issue/{key}/comment", {"body": "certdeploy: 문제가 해소되었습니다."})
            if c.resolve_transition_id:
                self._call("POST", f"{self._base()}/rest/api/2/issue/{key}/transitions", {"transition": {"id": c.resolve_transition_id}})
        else:
            self._call("POST", c.url, {"event": "resolve", "target": target, "id": ticket.get("id"), "source": "certdeploy"})

    # ---- 알림 인터페이스
    def fire(self, target, summary, description, severity="critical"):
        if not sev_ok(severity, self.cfg.min_severity) or not self.path:
            return
        data = self._load()
        if target in data:                              # 이미 열린 티켓이 있음 — 중복 생성하지 않는다
            return
        try:
            tk = self._create(target, summary, description, severity)
        except (OSError, ValueError, NotifyTestError) as e:
            log.warning("티켓 생성 실패: %s", type(e).__name__)
            trace.event("notify", "itsm", "error", op="create", error=type(e).__name__)
            return
        if tk.get("id"):
            data[target] = {**tk, "created_at": datetime.now(timezone.utc).isoformat(), "summary": summary[:120]}
            self._store(data)
            trace.event("notify", "itsm", op="create", ref=tk.get("ref"))

    def resolve(self, target):
        if not self.path:
            return
        data = self._load()
        tk = data.get(target)
        if not tk:
            return
        try:
            self._close(target, tk)
        except (OSError, ValueError, NotifyTestError) as e:
            log.warning("티켓 닫기 실패: %s", type(e).__name__)
            trace.event("notify", "itsm", "error", op="close", error=type(e).__name__)
            return                                       # 기록을 남겨 다음 해소 때 다시 시도
        data.pop(target, None)
        self._store(data)
        trace.event("notify", "itsm", op="close", ref=tk.get("ref"))

    def check(self) -> str:
        """티켓을 만들지 않고 접속·인증·(jira)프로젝트 존재를 확인한다. 실패하면 NotifyTestError."""
        c = self.cfg
        try:
            if c.format == "servicenow":
                self._call("GET", self._base() + "/api/now/table/incident?sysparm_limit=1&sysparm_fields=number")
                return "ServiceNow 접속·인증 확인(인시던트 조회 가능). 티켓은 만들지 않았습니다."
            if c.format == "jira":
                me = self._call("GET", self._base() + "/rest/api/2/myself")
                self._call("GET", f"{self._base()}/rest/api/2/project/{urllib.parse.quote(str(c.project), safe='')}")
                return f"Jira 접속·인증 확인({me.get('displayName') or me.get('name') or '계정'}), 프로젝트 {c.project} 확인. 티켓은 만들지 않았습니다."
            self._call("POST", c.url, {"event": "test", "source": "certdeploy", "text": "certdeploy 티켓 연동 시험"})
            return "일반 티켓 주소에 시험 요청을 보냈습니다(티켓 생성 여부는 해당 시스템에서 확인)."
        except NotifyTestError:
            raise
        except (OSError, ValueError) as e:
            raise _classify_http(e, "티켓 시스템") from None


def check_itsm(cfg, environ=os.environ) -> str:
    return ItsmNotifier(cfg, environ).check()


class CompositeNotifier(NullNotifier):
    def __init__(self, notifiers: List[NullNotifier]):
        self.notifiers = notifiers

    def fire(self, *a, **k):
        for n in self.notifiers:
            n.fire(*a, **k)

    def resolve(self, *a, **k):
        for n in self.notifiers:
            n.resolve(*a, **k)

    def summary(self, *a, **k):
        for n in self.notifiers:
            n.summary(*a, **k)


def build_notifier(notify_cfg, environ=os.environ) -> NullNotifier:
    parts: List[NullNotifier] = []
    throttle = Throttle(notify_cfg.state_dir, notify_cfg.repeat_hours) if notify_cfg.repeat_hours else None
    if notify_cfg.alertmanager_url:
        parts.append(AlertmanagerNotifier(notify_cfg.alertmanager_url))
    if notify_cfg.smtp:
        parts.append(SmtpNotifier(notify_cfg.smtp, environ, throttle=throttle))
    if notify_cfg.webhook:
        parts.append(WebhookNotifier(notify_cfg.webhook, environ, throttle=throttle))
    if notify_cfg.itsm:
        parts.append(ItsmNotifier(notify_cfg.itsm, environ, notify_cfg.state_dir))
    return CompositeNotifier(parts) if parts else NullNotifier()
