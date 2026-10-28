"""알림 채널: Alertmanager(API v2), SMTP 메일, 웹훅(Slack·Mattermost·Teams·일반). 알림 실패가 배포를 막지 않는다.

- fire/resolve: 대상별 배포 실패 발생·해소
- summary: 실행 1회가 끝났을 때의 요약(성공 요약은 설정에서 켠 채널에만)
"""
import json
import logging
import os
import smtplib
import ssl
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Callable, List, Optional

from certpilot_core import netutil, trace

log = logging.getLogger("certdeploy")


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

    def __init__(self, cfg, environ=os.environ, smtp_factory: Callable = smtplib.SMTP, prefix="[certdeploy]"):
        self.cfg, self.environ, self.factory, self.prefix = cfg, environ, smtp_factory, prefix

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
        self._send(f"{severity.upper()} {summary}", f"{summary}\n\n{description}\n")

    def summary(self, title, text, ok):
        if ok and not self.cfg.on_success:
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


class WebhookNotifier(NullNotifier):
    def __init__(self, cfg, environ=os.environ, timeout: float = 10.0):
        self.cfg, self.environ, self.timeout = cfg, environ, timeout

    def _url(self) -> Optional[str]:
        return _read_secret(self.cfg.url_env, self.cfg.url_file, self.environ)

    def payload(self, title: str, text: str, ok: bool) -> dict:
        icon = "✅" if ok else "🚨"
        full = f"{icon} {title}\n{text}"
        f = self.cfg.format
        if f == "slack":                       # Slack · Mattermost 호환
            return {"text": full}
        if f == "teams":                       # Teams Workflows(Adaptive Card) 웹훅 형식 — 환경에서 확인 필요
            return {"type": "message", "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
                "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                            "version": "1.4", "body": [
                                {"type": "TextBlock", "text": f"{icon} {title}", "weight": "Bolder", "wrap": True},
                                {"type": "TextBlock", "text": text, "wrap": True}]}}]}
        return {"title": title, "text": text, "ok": ok, "source": "certdeploy"}

    def _post(self, title, text, ok):
        url = self._url()
        if not url:
            log.warning("웹훅 URL 을 읽을 수 없어 알림을 건너뜀")
            return
        req = urllib.request.Request(url, data=json.dumps(self.payload(title, text, ok)).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            netutil.urlopen(req, timeout=self.timeout).read()
        except OSError as e:
            log.warning("웹훅 알림 전송 실패: %s", type(e).__name__)
            trace.event("notify", "webhook", "error", error=type(e).__name__, message=str(e))

    def fire(self, target, summary, description, severity="critical"):
        self._post(summary, description, False)

    def summary(self, title, text, ok):
        if ok and not self.cfg.on_success:
            return
        self._post(title, text, ok)


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
    if notify_cfg.alertmanager_url:
        parts.append(AlertmanagerNotifier(notify_cfg.alertmanager_url))
    if notify_cfg.smtp:
        parts.append(SmtpNotifier(notify_cfg.smtp, environ))
    if notify_cfg.webhook:
        parts.append(WebhookNotifier(notify_cfg.webhook, environ))
    return CompositeNotifier(parts) if parts else NullNotifier()
