"""Alertmanager(API v2) 알림: 배포 실패는 즉시 알리고, 성공하면 해소 처리한다. 알림 실패가 배포를 막지 않는다."""
import json
import logging
import urllib.request
from datetime import datetime, timedelta, timezone

log = logging.getLogger("certdeploy")


class NullNotifier:
    def fire(self, target, summary, description, severity="critical"):
        pass

    def resolve(self, target):
        pass


class AlertmanagerNotifier:
    ALERT = "CertDeployFailed"

    def __init__(self, url: str, timeout: float = 10.0, clock=lambda: datetime.now(timezone.utc)):
        self.url = url.rstrip("/") + "/api/v2/alerts"
        self.timeout, self.clock = timeout, clock

    def _post(self, alerts):
        req = urllib.request.Request(self.url, data=json.dumps(alerts).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=self.timeout).read()
        except OSError as e:
            log.warning("Alertmanager 알림 전송 실패: %s", type(e).__name__)

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
