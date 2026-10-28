"""실행 기록: 보고서(JSON·Markdown), 감사 로그(해시 체인), Prometheus 메트릭(textfile·Pushgateway)."""
import base64
import json
import logging
import os
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .engine import TargetResult

log = logging.getLogger("certdeploy")
STATUSES = ("deployed", "skipped", "failed", "rolled_back", "not_run", "dry_run")
OK_STATUSES = ("deployed", "skipped", "dry_run")
STATUS_KO = {"deployed": "배포 완료", "skipped": "건너뜀", "failed": "실패", "rolled_back": "롤백됨",
             "not_run": "실행 안 함", "dry_run": "계획만"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _atomic_write(path: str, text: str, mode: int = 0o640) -> None:
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


# ---------------------------------------------------------------- 보고서
def build_report(cert_name: str, bundle, results: List[TargetResult], started: datetime, finished: datetime,
                 action: str = "deploy") -> dict:
    return {
        "cert": cert_name, "action": action,
        "started_at": started.isoformat(), "finished_at": finished.isoformat(),
        "certificate": {"serial": f"{bundle.serial:x}", "not_after": bundle.not_after.isoformat(),
                        "days_left": round(bundle.days_left(), 1), "names": bundle.names},
        "ok": all(r.status in OK_STATUSES for r in results),
        "results": [{"target": r.name, "status": r.status, "message": r.message} for r in results],
    }


def report_markdown(rep: dict) -> str:
    c = rep["certificate"]
    lines = [f"# 인증서 배포 보고 — {rep['cert']}", "",
             f"- 결과: **{'성공' if rep['ok'] else '문제 있음'}**",
             f"- 시각: {rep['started_at']} → {rep['finished_at']}",
             f"- 인증서: 일련번호 `{c['serial']}`, 만료 {c['not_after'][:10]} (남은 {c['days_left']}일), 이름: {', '.join(c['names'])}",
             "", "| 대상 | 상태 | 내용 |", "|---|---|---|"]
    for r in rep["results"]:
        lines.append(f"| {r['target']} | {STATUS_KO.get(r['status'], r['status'])} | {r['message'].replace('|', '/')} |")
    return "\n".join(lines) + "\n"


def save_report(state_dir: str, rep: dict) -> None:
    _atomic_write(os.path.join(state_dir, "last-run.json"), json.dumps(rep, ensure_ascii=False, indent=2))


def load_report(state_dir: str) -> Optional[dict]:
    try:
        with open(os.path.join(state_dir, "last-run.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------- 메트릭
def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def metrics_text(rep: dict, state: dict, prev_success_ts: Optional[float] = None,
                 issue_failures: int = 0, now: Optional[datetime] = None) -> str:
    """Prometheus 텍스트 형식. 성공하지 못한 실행은 last_success 를 이전 값으로 유지해 '정체'를 알 수 있게 한다."""
    now = now or _now()
    cert = _esc(rep["cert"])
    ts = now.timestamp()
    success_ts = ts if rep["ok"] else (prev_success_ts or 0)
    out = [
        "# HELP certdeploy_last_run_timestamp_seconds 마지막 실행 시각(Unix).",
        "# TYPE certdeploy_last_run_timestamp_seconds gauge",
        f'certdeploy_last_run_timestamp_seconds{{cert="{cert}"}} {ts:.0f}',
        "# HELP certdeploy_last_success_timestamp_seconds 모든 대상이 정상(배포·건너뜀)이었던 마지막 실행 시각.",
        "# TYPE certdeploy_last_success_timestamp_seconds gauge",
        f'certdeploy_last_success_timestamp_seconds{{cert="{cert}"}} {success_ts:.0f}',
        "# HELP certdeploy_run_ok 마지막 실행이 성공(1)인지 문제(0)인지.",
        "# TYPE certdeploy_run_ok gauge",
        f'certdeploy_run_ok{{cert="{cert}"}} {1 if rep["ok"] else 0}',
        "# HELP certdeploy_target_ok 대상의 마지막 결과가 정상(1)/문제(0).",
        "# TYPE certdeploy_target_ok gauge",
    ]
    for r in rep["results"]:
        ok = 1 if r["status"] in OK_STATUSES else 0
        out.append(f'certdeploy_target_ok{{cert="{cert}",target="{_esc(r["target"])}"}} {ok}')
    out += ["# HELP certdeploy_target_status 대상의 마지막 상태(원-핫).", "# TYPE certdeploy_target_status gauge"]
    for r in rep["results"]:
        for st in STATUSES:
            out.append(f'certdeploy_target_status{{cert="{cert}",target="{_esc(r["target"])}",status="{st}"}} {1 if r["status"] == st else 0}')
    c = rep["certificate"]
    na = datetime.fromisoformat(c["not_after"]).timestamp()
    out += [
        "# HELP certdeploy_certificate_not_after_timestamp_seconds 배포 대상 인증서의 만료 시각.",
        "# TYPE certdeploy_certificate_not_after_timestamp_seconds gauge",
        f'certdeploy_certificate_not_after_timestamp_seconds{{cert="{cert}",serial="{_esc(c["serial"])}"}} {na:.0f}',
        "# HELP certdeploy_issue_failures 연속 발급·갱신 실패 횟수.",
        "# TYPE certdeploy_issue_failures gauge",
        f'certdeploy_issue_failures{{cert="{cert}"}} {issue_failures}',
    ]
    return "\n".join(out) + "\n"


def write_metrics_file(path: str, text: str) -> None:
    _atomic_write(path, text, 0o644)       # node_exporter textfile collector 가 읽을 수 있게


def push_metrics(url: str, cert: str, text: str, user: Optional[str] = None, password: Optional[str] = None,
                 timeout: float = 10.0) -> bool:
    """Pushgateway 로 전송(POST: 같은 그룹의 같은 이름 지표를 교체). 실패해도 예외를 내지 않는다."""
    target = f"{url.rstrip('/')}/metrics/job/certdeploy/cert/{urllib.parse.quote(cert, safe='')}"
    req = urllib.request.Request(target, data=text.encode(), method="POST", headers={"Content-Type": "text/plain"})
    if user and password:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
    try:
        urllib.request.urlopen(req, timeout=timeout).read()
        return True
    except OSError as e:
        log.warning("Pushgateway 전송 실패: %s", type(e).__name__)
        return False


# ---------------------------------------------------------------- 감사 로그
def audit_events(audit_dir: Optional[str], rep: dict, actor: str = "certdeploy") -> None:
    if not audit_dir:
        return
    from certpilot_core.audit_storage import AuditLogWriter
    w = AuditLogWriter(audit_dir, log_type="certdeploy")
    c = rep["certificate"]
    for r in rep["results"]:
        w.write({"event_type": f"deploy_{r['status']}", "description": f"{rep['cert']}/{r['target']}",
                 "details": {"actor": actor, "serial": c["serial"], "message": r["message"][:300]}})
    w.write({"event_type": "deploy_run", "description": rep["cert"],
             "details": {"actor": actor, "ok": rep["ok"], "serial": c["serial"], "action": rep["action"],
                         "targets": len(rep["results"])}})


def finish_run(certset, bundle, results, started, notifier, env=os.environ, action="deploy",
               issue_failures: int = 0, prev_success_ts: Optional[float] = None) -> dict:
    """보고서 저장 → 감사 로그 → 메트릭(textfile·Pushgateway) → 요약 알림. 모든 부가 동작은 실패해도 배포 결과에 영향이 없다."""
    finished = _now()
    rep = build_report(certset.name, bundle, results, started, finished, action)
    dry = all(r.status == "dry_run" for r in results) if results else False
    if dry:
        return rep
    prev = load_report(certset.state_dir) or {}
    rep["last_success_ts"] = finished.timestamp() if rep["ok"] else prev.get("last_success_ts")   # 정체 판단용(마지막 성공 시각 유지)
    try:
        save_report(certset.state_dir, rep)
    except OSError as e:
        log.warning("보고서 저장 실패: %s", e)
    try:
        audit_events(certset.audit_dir, rep)
    except Exception as e:   # noqa: BLE001 — 감사 로그 문제가 배포 결과를 바꾸지 않게 한다
        log.warning("감사 로그 기록 실패: %s", type(e).__name__)
    n = certset.notify
    text = metrics_text(rep, {}, rep.get("last_success_ts"), issue_failures, finished)
    if n.metrics_file:
        try:
            write_metrics_file(n.metrics_file, text)
        except OSError as e:
            log.warning("메트릭 파일 기록 실패: %s", e)
    if n.pushgateway_url:
        pw = env.get(n.pushgateway_password_env or "") if n.pushgateway_password_env else None
        push_metrics(n.pushgateway_url, certset.name, text, n.pushgateway_user, pw)
    changed = any(r.status != "skipped" for r in results)
    if changed or not rep["ok"]:
        notifier.summary(f"인증서 배포 {'완료' if rep['ok'] else '문제'} — {certset.name}", report_markdown(rep), rep["ok"])
    return rep


def issue_failure_metrics(cert: str, failures: int) -> str:
    """발급 실패 횟수만 갱신하는 부분 지표(POST 는 같은 이름의 지표만 교체한다)."""
    c = _esc(cert)
    return ("# HELP certdeploy_issue_failures 연속 발급·갱신 실패 횟수.\n# TYPE certdeploy_issue_failures gauge\n"
            f'certdeploy_issue_failures{{cert="{c}"}} {failures}\n')
