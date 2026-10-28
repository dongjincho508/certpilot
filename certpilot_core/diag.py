"""진단 번들·환경 점검(웹 API 와 certdeploy 공용). 비밀값은 포함하지 않는다."""
import json
import os
import platform
import shutil
import socket
import sys
import urllib.error
import urllib.request
from typing import List, Optional

from . import netutil
from .trace import redact

# 값은 노출하지 않고 설정 여부만 보여 줄 환경변수
ENV_FLAGS = ("CERTPILOT_ADMIN_USER", "CERTPILOT_ADMIN_PASSWORD", "CERTPILOT_ADMIN_RESET_PASSWORD", "CERTPILOT_SSH_PRIVATE_KEY",
             "CERTPILOT_SSH_PRIVATE_KEY_B64", "CERTPILOT_DATA_DIR", "CERTPILOT_DEBUG", "CERTPILOT_TRACE_FILE",
             "SSH_AUTH_SOCK", "PORT")


def environment_info() -> dict:
    return {"python": sys.version.split()[0], "platform": platform.platform(), "hostname": socket.gethostname(),
            "tools": {t: bool(shutil.which(t)) for t in ("ssh", "ssh-agent", "ssh-add", "openssl", "lego", "keytool")},
            "env_set": {k: bool(os.environ.get(k)) for k in ENV_FLAGS}}


def check(name: str, ok: bool, detail: str = "", hint: str = "") -> dict:
    return {"name": name, "ok": bool(ok), "detail": detail, "hint": "" if ok else hint}


def _get_json(url: str, timeout: float = 5.0):
    with netutil.urlopen(url, timeout=timeout) as r:    # noqa: S310 — 운영자가 지정한 감시 서버 주소
        return json.loads(r.read().decode())


def check_monitoring(prometheus: Optional[str] = None, alertmanager: Optional[str] = None,
                     pushgateway: Optional[str] = None, cert: Optional[str] = None) -> List[dict]:
    """감시 스택 점검: 수집 대상 상태·마지막 오류, 규칙 로드, 알림 경로, certdeploy 지표 도달 여부."""
    out: List[dict] = []
    if prometheus:
        p = prometheus.rstrip("/")
        try:
            targets = _get_json(f"{p}/api/v1/targets")["data"]["activeTargets"]
            down = [t for t in targets if t.get("health") != "up"]
            out.append(check("prometheus.targets", not down, f"{len(targets)}개 중 {len(down)}개 비정상" + "".join(
                f"\n  - {t['labels'].get('job')} {t['labels'].get('instance')}: {t.get('lastError', '')[:160]}" for t in down),
                "lastError 확인: 주소·방화벽·ssl_exporter 모듈 이름"))
            rules = _get_json(f"{p}/api/v1/rules")["data"]["groups"]
            bad = [r for g in rules for r in g["rules"] if r.get("health") not in (None, "ok")]
            out.append(check("prometheus.rules", bool(rules) and not bad, f"{sum(len(g['rules']) for g in rules)}개 규칙, 오류 {len(bad)}",
                             "rule_files 경로·promtool check rules 로 확인"))
            alerts = _get_json(f"{p}/api/v1/alerts")["data"]["alerts"]
            firing = sorted({a["labels"].get("alertname", "?") for a in alerts if a.get("state") == "firing"})
            out.append(check("prometheus.alerts", True, f"발화 중: {', '.join(firing) or '없음'}"))
            q = "certdeploy_last_run_timestamp_seconds" + (f'{{cert="{cert}"}}' if cert else "")
            res = _get_json(f"{p}/api/v1/query?query={urllib.request.quote(q)}")["data"]["result"]
            out.append(check("prometheus.certdeploy_metrics", bool(res), f"{len(res)}개 시계열",
                             "certdeploy deploy 후 notify.pushgateway_url / metrics_file 과 prometheus 의 pushgateway job 확인"))
        except (OSError, ValueError, KeyError, urllib.error.URLError) as e:
            out.append(check("prometheus.reachable", False, f"{type(e).__name__}: {e}", "주소·포트·방화벽 확인"))
    if alertmanager:
        try:
            _get_json(f"{alertmanager.rstrip('/')}/api/v2/status")
            out.append(check("alertmanager.reachable", True))
        except (OSError, ValueError, urllib.error.URLError) as e:
            out.append(check("alertmanager.reachable", False, f"{type(e).__name__}: {e}", "주소·포트 확인"))
    if pushgateway:
        try:
            with netutil.urlopen(f"{pushgateway.rstrip('/')}/metrics", timeout=5) as r:   # noqa: S310
                text = r.read().decode()
            seen = [l for l in text.splitlines() if l.startswith("certdeploy_last_run_timestamp_seconds")]
            out.append(check("pushgateway.certdeploy_metrics", bool(seen), f"{len(seen)}개 시계열", "certdeploy 가 지표를 푸시했는지(notify.pushgateway_url) 확인"))
        except (OSError, urllib.error.URLError) as e:
            out.append(check("pushgateway.reachable", False, f"{type(e).__name__}: {e}", "주소·포트 확인"))
    return out


def summarize(checks: List[dict]) -> dict:
    return {"ok": all(c["ok"] for c in checks), "failed": [c["name"] for c in checks if not c["ok"]]}


def dumps(obj) -> str:
    return json.dumps(redact(obj), ensure_ascii=False, indent=2, default=str)
