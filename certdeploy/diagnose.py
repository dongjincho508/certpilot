"""진단 번들: 설정(마스킹)·인증서 상태·마지막 실행·트레이스·감시 스택 점검을 한 JSON 으로 모은다. 비밀값은 포함하지 않는다."""
import os
from typing import Optional

import yaml

from certpilot_core import diag, trace

from . import __version__
from .bundle import BundleError, key_permission_problems, load_bundle
from .config import ConfigError, load_config
from .runlog import load_report


def trace_path(state_dir: str) -> str:
    return os.path.join(state_dir, "trace.jsonl")


def _cert_section(cs) -> dict:
    sec = {"name": cs.name, "state_dir": cs.state_dir, "cert_file": cs.cert_file, "key_file": cs.key_file}
    pw = (os.environ.get(cs.key_password_env) if cs.key_password_env else None) or cs.key_passphrase
    try:
        b = load_bundle(cs.cert_file, cs.key_file, pw)
        sec["certificate"] = {"ok": True, "serial": f"{b.serial:x}", "not_after": b.not_after.isoformat(),
                              "days_left": round(b.days_left(), 1), "names": b.names, "chain_length": len(b.chain)}
    except BundleError as e:
        sec["certificate"] = {"ok": False, "error": str(e)}
    except Exception as e:   # noqa: BLE001
        sec["certificate"] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    try:
        sec["key_permission_problems"] = key_permission_problems(cs.key_file)
    except Exception as e:   # noqa: BLE001
        sec["key_permission_problems"] = [f"{type(e).__name__}: {e}"]
    sec["pending_manual_key"] = os.path.exists(os.path.join(cs.state_dir, "pending", cs.name, "key.pem"))
    sec["last_run"] = load_report(cs.state_dir)
    sec["targets"] = [{"name": t.name, "type": t.type, "transport": {k: v for k, v in t.transport.items() if k != "key_file"},
                       "verify": bool(t.verify), "canary": t.canary} for t in cs.targets]
    return sec


def build(config_path: str, prometheus: Optional[str] = None, alertmanager: Optional[str] = None,
          pushgateway: Optional[str] = None, trace_limit: int = 300) -> dict:
    out = {"certdeploy_version": __version__, "environment": diag.environment_info(), "config_path": config_path}
    checks = []
    try:
        with open(config_path, encoding="utf-8") as f:
            out["config"] = yaml.safe_load(f)                      # 기록 시 redact() 가 비밀 키를 가린다
        cfg = load_config(config_path)
        checks.append(diag.check("config", True, f"인증서 {len(cfg.certs)}개"))
    except (OSError, ConfigError, yaml.YAMLError) as e:
        out["checks"] = [diag.check("config", False, str(e), "설정 파일 문법·필수 항목 확인: certdeploy validate")]
        out.update(diag.summarize(out["checks"]))
        return out
    out["certificates"] = []
    events = []
    for cs in cfg.certs:
        sec = _cert_section(cs)
        out["certificates"].append(sec)
        c = sec["certificate"]
        checks.append(diag.check(f"{cs.name}.certificate", c["ok"], c.get("error") or f"만료까지 {c.get('days_left')}일",
                                 "certdeploy import/issue 로 인증서를 준비하세요"))
        checks.append(diag.check(f"{cs.name}.key_permissions", not sec["key_permission_problems"], "; ".join(sec["key_permission_problems"]),
                                 "chmod 600 <key_file>"))
        lr = sec["last_run"]
        if lr:
            checks.append(diag.check(f"{cs.name}.last_run", lr.get("ok", False),
                                     "; ".join(f"{r['target']}={r['status']}" for r in lr["results"] if r["status"] not in ("deployed", "skipped")),
                                     "certdeploy trace --errors 로 실패 단계 확인"))
        events += trace.read_file(trace_path(cs.state_dir))[-trace_limit:]
        if cs.audit_dir:
            try:
                from certpilot_core.audit_storage import AuditLogReader
                r = AuditLogReader(cs.audit_dir).verify_integrity()
                checks.append(diag.check(f"{cs.name}.audit_chain", r["integrity_valid"], f"{r['total_logs']}건", "감사 로그 변조·손상 확인"))
            except Exception as e:   # noqa: BLE001
                checks.append(diag.check(f"{cs.name}.audit_chain", False, f"{type(e).__name__}: {e}"))
    checks += diag.check_monitoring(prometheus, alertmanager, pushgateway)
    out["checks"] = checks
    out["events"] = (events + trace.TRACER.events(limit=trace_limit))[-trace_limit:]
    out.update(diag.summarize(checks))
    return out
