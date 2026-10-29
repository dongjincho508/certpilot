"""certdeploy 명령행. 종료 코드: 0 성공 · 1 배포/점검 문제 · 2 설정·인증서 오류 · 3 다른 작업 실행 중 · 4 DNS TXT 등록 대기(수동 발급)."""
import csv
import json
import logging
import os
import sys
from datetime import datetime, timezone

import click
import yaml

from certpilot_core import diag as cpdiag, trace

from . import __version__, acme, approval, backup as backup_mod, backupjob, diagnose as dg
from .dnsprov import DnsProviderError, build_provider
from .dnsquery import DnsError, system_resolvers
from .backup import BackupError, create_backup, restore_backup
from .bundle import BundleError, key_permission_problems, load_bundle
from .config import HOST_RE, NAME_RE, ConfigError, load_config
from .engine import Deployer
from .handlers import TYPES
from .manual import (ManualError, build_bundle, collect_certs, generate_csr, install_bundle, load_key_file, load_pfx,
                     pending_dir, save_pending)
from .issuer import STAGING as LE_STAGING, BackoffActive, IssueBackoff, IssueError, LegoIssuer, lego_output_paths
from .notify import build_notifier
from .preflight import run_preflight
from .runlog import (STATUS_KO, finish_run, issue_failure_metrics, load_report, push_metrics, report_markdown)
from .state import LockedError, State, exclusive_lock
from .verify import VerifyError, tls_serial

STATUS_LABEL = STATUS_KO


def _cfg(obj):
    try:
        cfg = load_config(obj["config"])
    except ConfigError as e:
        raise click.ClickException(str(e)) from None
    if not trace.TRACER.path and cfg.certs:      # 항상 기록(파일 0600, 5MB 회전): 실패 후에도 원인을 볼 수 있게
        trace.TRACER.configure(path=dg.trace_path(cfg.certs[0].state_dir))
    return cfg


def _sets(obj):
    cfg = _cfg(obj)
    try:
        return cfg, cfg.select(obj.get("cert"))
    except ConfigError as e:
        raise click.ClickException(str(e)) from None


def _hdr(cs, many):
    if many:
        click.echo(f"== {cs.name} ==")


def _key_read_pw(cs):
    """저장된 개인키를 읽을 때 쓸 암호(환경변수가 있으면). 암호화 옵션이 켜져 있는데 없으면 안내와 함께 중단."""
    pw = (os.environ.get(cs.key_password_env) if cs.key_password_env else None) or cs.key_passphrase
    if cs.key_encryption == "passphrase" and not pw:
        raise click.ClickException(f"개인키 암호화가 켜져 있습니다 — 환경변수 {cs.key_password_env} 를 설정하세요(/etc/certdeploy/env) 또는 관리자 화면에서 암호를 입력하세요")
    return pw


def _key_write_pw(cs):
    """개인키를 저장할 때 암호화할 암호. key_encryption: passphrase 일 때만(none 이면 평문 0600)."""
    return _key_read_pw(cs) if cs.key_encryption == "passphrase" else None


def _bundle(cs, exit_on_error=True):
    try:
        pw = _key_read_pw(cs)
    except click.ClickException as e:
        if not exit_on_error:
            return None
        click.echo(f"인증서 오류: {e.message}", err=True)
        sys.exit(2)
    try:
        return load_bundle(cs.cert_file, cs.key_file, pw)
    except BundleError as e:
        if not exit_on_error:
            return None
        click.echo(f"인증서 오류: {e}", err=True)
        sys.exit(2)


def _deployer(cs, bundle):
    try:
        state = State(cs.state_dir).load()
    except RuntimeError as e:
        raise click.ClickException(str(e)) from None
    return Deployer(cs, bundle, state, notifier=build_notifier(cs.notify))


def _print_results(results):
    for r in results:
        click.echo(f"[{r.name}] {STATUS_LABEL.get(r.status, r.status)}" + (f" — {r.message}" if r.message else ""))
    ok = all(r.status in ("deployed", "skipped", "dry_run", "manual_pending") for r in results)
    n = {k: sum(1 for r in results if r.status == k) for k in STATUS_LABEL}
    click.echo("요약: " + ", ".join(f"{STATUS_LABEL[k]} {v}" for k, v in n.items() if v))
    return 0 if ok else 1


def _worst(codes):
    return max(codes) if codes else 0


@click.group()
@click.option("-c", "--config", "config", required=True, envvar="CERTDEPLOY_CONFIG", type=click.Path(), help="설정 파일(YAML)")
@click.option("--cert", "cert_name", default=None, help="여러 인증서 중 하나만 대상으로 함")
@click.option("-v", "--verbose", is_flag=True)
@click.option("--debug", is_flag=True, envvar="CERTDEPLOY_DEBUG", help="단계별 진단 이벤트를 실시간 출력하고 <state_dir>/trace.jsonl 에 기록")
@click.version_option(__version__)
@click.pass_context
def main(ctx, config, cert_name, verbose, debug):
    """인증서 발급(lego)·자동 배포·검증·롤백."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s")
    ctx.obj = {"config": config, "cert": cert_name, "debug": debug}
    trace.configure_from_env(prefix="CERTDEPLOY")
    trace.run_id_var.set(f"{ctx.invoked_subcommand or 'cli'}-{os.urandom(3).hex()}")
    if debug:
        trace.TRACER.configure(echo=lambda line: print(line, file=sys.stderr, flush=True))


# ------------------------------------------------------------------ 점검
@main.command()
@click.pass_obj
def validate(obj):
    """설정과 인증서를 검증한다(키 일치·유효기간·체인·대상 호스트명·환경변수·키 파일 권한)."""
    cfg, sets = _sets(obj)
    code = 0
    for cs in sets:
        _hdr(cs, len(sets) > 1)
        b = _bundle(cs)
        d = _deployer(cs, b)
        enc = open(cs.key_file, "rb").read(400).find(b"ENCRYPTED") >= 0
        click.echo(f"개인키 저장: {'암호화됨' if enc else '평문(권한 600으로 보호)'}  설정 key_encryption={cs.key_encryption}")
        if enc != (cs.key_encryption == 'passphrase'):
            click.echo(f"문제: 설정(key_encryption={cs.key_encryption})과 실제 키 파일 상태가 다릅니다 — certdeploy key-{'encrypt' if cs.key_encryption == 'passphrase' else 'decrypt'} 로 맞추세요")
            code = 1
        click.echo(f"인증서 OK: 일련번호 {b.serial:x}, 만료 {b.not_after:%Y-%m-%d}(남은 {b.days_left():.0f}일), SAN {', '.join(b.names)}")
        for w in b.warnings:
            click.echo(f"주의: {w}")
        if cfg.applied:
            click.echo("관리자 화면(settings.json) 적용: " + " · ".join(cfg.applied))
        problems = key_permission_problems(cs.key_file) + d.validate_targets()
        for p in problems:
            click.echo(f"문제: {p}")
        click.echo(f"대상 {len(cs.targets)}개")
        code = max(code, 1 if problems else 0)
    sys.exit(code)


@main.command()
@click.option("--target", "only", multiple=True, help="특정 대상만")
@click.pass_obj
def preflight(obj, only):
    """배포 전 사전 점검(접속·쓰기 권한·명령 존재·sudo·여유 공간·현재 TLS·헬스). 변경하지 않는다."""
    cfg, sets = _sets(obj)
    bad = 0
    for cs in sets:
        _hdr(cs, len(sets) > 1)
        checks = run_preflight(_deployer(cs, _bundle(cs)), list(only) or None)
        for c in checks:
            click.echo(f"{'✔' if c.ok else '✘'} [{c.target}] {c.name} — {c.detail}")
            bad += not c.ok
        click.echo(f"점검 {len(checks)}건 중 실패 {sum(1 for c in checks if not c.ok)}건")
    sys.exit(1 if bad else 0)


@main.command()
@click.option("--target", "only", multiple=True)
@click.pass_obj
def plan(obj, only):
    """배포 계획을 출력한다(아무것도 변경하지 않음)."""
    cfg, sets = _sets(obj)
    for cs in sets:
        _hdr(cs, len(sets) > 1)
        for line in _deployer(cs, _bundle(cs)).plan(list(only) or None):
            click.echo(line)


# ------------------------------------------------------------------ 배포
EXIT_WAITING_APPROVAL = 5     # 담당자 승인을 기다리는 중(오류가 아님)


def _whoami():
    import getpass
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"


def _push_approval_metrics(cs):
    if cs.notify.pushgateway_url:
        pw = os.environ.get(cs.notify.pushgateway_password_env or "") if cs.notify.pushgateway_password_env else None
        push_metrics(cs.notify.pushgateway_url, cs.name, approval.metrics_text(cs.name, cs.state_dir),
                     cs.notify.pushgateway_user, pw)


def _approval_audit(cs, event, req, extra=None):
    if cs.audit_dir:
        try:
            from certpilot_core.audit_storage import AuditLogWriter
            AuditLogWriter(cs.audit_dir, log_type="certdeploy").write({
                "event_type": event, "description": f"{cs.name}/{req.get('id')}",
                "details": {"actor": (extra or {}).get("actor", "certdeploy"), "cert": cs.name, "serial": req.get("serial"), **(extra or {})}})
        except Exception as e:  # noqa: BLE001 — 감사 기록 문제가 승인 절차를 막지 않게 한다
            click.echo(f"주의: 감사 로그 기록 실패({type(e).__name__})", err=True)


def _approval_gate(cs, bundle, d, only, force, dry_run, action, emergency):
    """배포 전 승인 확인. (진행 여부 코드, 승인 요청 또는 None) 반환 — 코드가 None 이면 계속 진행."""
    policy = cs.approval
    if not policy:
        return None, None
    # 실제로 바뀔 대상이 없으면(이미 배포됨) 승인 절차를 건드리지 않는다
    if not force and all(r.status == "skipped" for r in d.deploy(dry_run=True, only=list(only) or None)):
        return None, None
    names = [t.name for t in cs.targets if not only or t.name in only]
    if emergency and not dry_run:
        rec = approval.record_bypass(cs.state_dir, cs.name, bundle, emergency, _whoami())
        click.echo(f"[{cs.name}] ⚠ 승인 없이 긴급 배포합니다 — 사유: {emergency}")
        d.notifier.fire(f"approval-bypass:{cs.name}", f"승인 우회 긴급 배포: {cs.name}",
                        f"{_whoami()} 님이 승인 없이 긴급 배포했습니다. 일련번호 {bundle.serial:x}. 사유: {emergency}", "warning")
        _approval_audit(cs, "approval_bypass", rec, {"actor": _whoami(), "reason": emergency, "security": True})
        return None, None
    g = approval.gate(cs.name, cs.state_dir, policy, bundle, names, action,
                      requested_by=approval.SYSTEM if action == "renew" else _whoami(), create=not dry_run)
    req = g.request
    if req is None:                     # --dry-run: 요청은 만들지 않고 승인이 필요함만 알린다
        click.echo(f"[{cs.name}] 실제 배포 시에는 승인이 필요합니다(승인 {policy['approvers']}명, 아직 요청 없음)")
        return 0, None
    if g.status == "approved":
        if dry_run:
            click.echo(f"[{cs.name}] 승인됨: 요청 {req['id']}")
        return None, req
    why = {"pending": f"승인 대기 {len(req['approvals'])}/{req['needed']}", "rejected": "반려됨"}[g.status]
    click.echo(f"[{cs.name}] 배포 보류 — {why} (요청 {req['id']}, 일련번호 {req['serial']}, 만료 {req['not_after'][:10]})")
    if g.status == "pending":
        click.echo(f"  승인: certdeploy -c <설정> approve {req['id']} --by <이름>   (관리자 화면에서도 가능, 유효 {policy['ttl_hours']}시간)")
    if g.created and not dry_run:
        d.notifier.fire(f"approval:{cs.name}", f"인증서 배포 승인 요청: {cs.name}",
                        f"새 인증서(일련번호 {req['serial']}, 만료 {req['not_after'][:10]})를 {', '.join(names)} 에 배포하려면 승인 {req['needed']}명이 필요합니다.\n"
                        f"관리자 화면 '발급·배포 설정' 에서 승인하거나 `certdeploy approve {req['id']} --by 이름` 을 실행하세요. 유효 {policy['ttl_hours']}시간.", "warning")
        _approval_audit(cs, "approval_requested", req, {"actor": req["requested_by"]})
    if not dry_run:
        _push_approval_metrics(cs)
    return (0 if dry_run else EXIT_WAITING_APPROVAL), req


def _run_deploy(cfg, cs, bundle, force, dry_run, only, cont, action="deploy", issue_failures=0, emergency=None):
    d = _deployer(cs, bundle)
    problems = d.validate_targets()
    if problems:
        for p in problems:
            click.echo(f"문제: {p}", err=True)
        return 1
    started = datetime.now(timezone.utc)
    try:
        with exclusive_lock(cs.state_dir):
            blocked, req = _approval_gate(cs, bundle, d, only, force, dry_run, action, emergency)
            if blocked is not None:
                if dry_run:       # 계획 확인은 승인 여부와 무관하게 계속 보여준다
                    pass
                else:
                    return blocked
            results = d.deploy(force=force, dry_run=dry_run, only=list(only) or None, continue_on_error=cont)
            code = _print_results(results)
            finish_run(cs, bundle, results, started, d.notifier, action=action, issue_failures=issue_failures)
            if req and not dry_run and code == 0 and not only and req.get("status") == "approved":
                approval.mark_applied(cs.state_dir, req["id"])
                d.notifier.resolve(f"approval:{cs.name}")
                _approval_audit(cs, "approval_applied", req, {"actor": "certdeploy"})
                _push_approval_metrics(cs)
            return code
    except LockedError as e:
        click.echo(str(e), err=True)
        return 3


@main.command()
@click.option("--force", is_flag=True, help="이미 새 인증서를 서빙 중이어도 다시 배포")
@click.option("--dry-run", is_flag=True, help="계획만 확인")
@click.option("--target", "only", multiple=True)
@click.option("--continue-on-error", is_flag=True, help="실패해도 다음 대상 진행(기본은 중단)")
@click.option("--emergency", metavar="사유", help="승인 정책을 우회하는 긴급 배포(사유 필수; 감사 로그·알림에 남음)")
@click.pass_obj
def deploy(obj, force, dry_run, only, continue_on_error, emergency):
    """현재 인증서 파일을 모든 대상에 배포한다(승인 정책이 있으면 승인된 인증서만)."""
    cfg, sets = _sets(obj)
    codes = []
    for cs in sets:
        _hdr(cs, len(sets) > 1)
        codes.append(_run_deploy(cfg, cs, _bundle(cs), force, dry_run, only, continue_on_error, emergency=emergency))
    sys.exit(_worst(codes))


@main.command()
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.pass_obj
def status(obj, fmt):
    """대상별 마지막 배포 결과와 현재 서빙 중인 인증서를 보여준다."""
    cfg, sets = _sets(obj)
    bad, rows = 0, []
    for cs in sets:
        b = _bundle(cs)
        st = State(cs.state_dir).load()
        for t in cs.targets:
            s = st.target(t.name)
            live, live_serial = "unknown", None
            if t.verify:
                try:
                    live_serial = tls_serial(t.verify.host, t.verify.port, t.verify.sni)
                    live = "latest" if live_serial == b.serial else "stale"
                except VerifyError:
                    live = "unreachable"
                bad += live != "latest"
            rows.append({"cert": cs.name, "target": t.name, "recorded_status": s.get("status", "none"),
                         "deployed_at": s.get("deployed_at"), "serial": s.get("serial"), "live": live,
                         "live_serial": f"{live_serial:x}" if live_serial else None,
                         "cert_serial": f"{b.serial:x}", "days_left": round(b.days_left(), 1)})
    if fmt == "json":
        click.echo(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        label = {"latest": "최신", "stale": "이전/다른 인증서", "unreachable": "조회 실패", "unknown": "확인 안 함"}
        for r in rows:
            click.echo(f"[{r['target']}] 기록: {r['recorded_status']} {r['deployed_at'] or ''}  서빙: {label[r['live']]}"
                       + (f"({r['live_serial']})" if r["live"] == "stale" else ""))
    sys.exit(1 if bad else 0)


@main.command()
@click.option("--format", "fmt", type=click.Choice(["md", "json"]), default="md")
@click.pass_obj
def report(obj, fmt):
    """마지막 실행 보고서를 출력한다."""
    cfg, sets = _sets(obj)
    missing = 0
    for cs in sets:
        rep = load_report(cs.state_dir)
        if not rep:
            click.echo(f"[{cs.name}] 실행 기록이 없습니다", err=True)
            missing += 1
            continue
        click.echo(json.dumps(rep, ensure_ascii=False, indent=2) if fmt == "json" else report_markdown(rep))
    sys.exit(1 if missing == len(sets) else 0)


@main.command()
@click.option("--target", required=True)
@click.pass_obj
def rollback(obj, target):
    """마지막 배포 이전 파일로 되돌리고 재로드한다."""
    cfg, sets = _sets(obj)
    owners = [cs for cs in sets if any(t.name == target for t in cs.targets)]
    if not owners:
        raise click.ClickException(f"알 수 없는 대상: {target}")
    if len(owners) > 1:
        raise click.ClickException(f"대상 이름 {target} 가 여러 인증서에 있습니다 — --cert 로 지정하세요")
    cs = owners[0]
    d = _deployer(cs, _bundle(cs))
    try:
        with exclusive_lock(cs.state_dir):
            r = d.rollback(target)
    except LockedError as e:
        raise click.ClickException(str(e))
    click.echo(f"[{r.name}] {STATUS_LABEL.get(r.status, r.status)} — {r.message}")
    sys.exit(0 if r.status == "rolled_back" else 1)


# ------------------------------------------------------------------ 발급
def _lego_label(cs):
    return "lego" if cs.name == "default" else f"lego:{cs.name}"


def _report_issue_failure(cs, notifier, backoff, message):
    click.echo(f"발급 실패: {message}", err=True)
    existing = _bundle(cs, exit_on_error=False)
    left = existing.days_left() if existing else None
    sev = "critical" if (left is None or left < 14) else "warning"
    extra = f" (현재 인증서 만료까지 {left:.0f}일)" if left is not None else " (현재 사용 가능한 인증서 없음)"
    notifier.fire(_lego_label(cs), f"인증서 발급·갱신 실패: {cs.name}", message + extra, sev)
    if cs.notify.pushgateway_url:
        pw = os.environ.get(cs.notify.pushgateway_password_env or "") if cs.notify.pushgateway_password_env else None
        push_metrics(cs.notify.pushgateway_url, cs.name, issue_failure_metrics(cs.name, backoff.failures),
                     cs.notify.pushgateway_user, pw)
    return 1


EXIT_WAITING_DNS = 4          # 사람이 DNS 에 TXT 를 등록하기를 기다리는 중(수동 모드)


def _issue_acme(cfg, cs, staging, force_run, no_deploy, force_deploy, ignore_backoff):
    """내장 ACME(DNS-01). 연동(infoblox)은 한 번에, 수동(manual)은 'TXT 안내 → 등록 후 재실행' 두 단계."""
    a = cs.acme
    notifier = build_notifier(cs.notify)
    backoff = IssueBackoff(cs.state_dir)
    directory = LE_STAGING if staging else a["directory"]
    existing = _bundle(cs, exit_on_error=False)
    pend = acme.load_pending(cs.state_dir, cs.name)
    if pend and pend.get("directory") != directory:
        click.echo("이전에 시작한 주문이 다른 CA/디렉터리용이라 폐기하고 새로 시작합니다", err=True)
        acme.clear_pending(cs.state_dir, cs.name)
        pend = None
    if not pend and not staging and existing and not force_run and existing.days_left() > a["renew_days"]:
        click.echo(f"[{cs.name}] 갱신 불필요: 만료까지 {existing.days_left():.0f}일(기준 {a['renew_days']}일 이내에 갱신)")
        return 0 if no_deploy else _run_deploy(cfg, cs, existing, force_deploy, False, (), False, action="renew")
    try:
        if not ignore_backoff:
            backoff.check(cs.options.lego_backoff_minutes)
        client = acme.load_account(cs.state_dir, directory, a["email"])
        provider = build_provider(a["dns"])
        resolvers = a["dns"]["check_resolvers"] or system_resolvers()
        if provider.automatic:
            if pend:
                acme.clear_pending(cs.state_dir, cs.name)
            key_pem, chain = acme.issue_with_provider(client, provider, cs.state_dir, cs.name, a["domains"], a["key_type"],
                                                      resolvers, a["dns"]["propagation_timeout"], key_password=_key_write_pw(cs))
        else:
            if not pend:
                pend = acme.start_order(client, cs.state_dir, cs.name, a["domains"], a["key_type"], _key_write_pw(cs))
            missing = acme.wait_visible(acme.txt_records(pend), resolvers, 0) if acme.txt_records(pend) else []
            if missing:
                text = acme.instructions(pend)
                click.echo(f"[{cs.name}] DNS TXT 등록 대기 중\n{text}")
                if missing != acme.txt_records(pend):
                    click.echo("아직 보이지 않는 레코드: " + ", ".join(n for n, _ in missing))
                notifier.fire(_lego_label(cs) + ":dns", f"DNS TXT 등록 필요: {cs.name}", text, "warning")
                return EXIT_WAITING_DNS
            key_pem, chain = acme.complete_order(client, pend, cs.state_dir, _key_read_pw(cs))
        if staging:                                   # 시험 발급분은 신뢰되지 않으므로 운영 위치에 설치·배포하지 않는다
            sdir = os.path.join(cs.state_dir, "acme", "staging")
            bundle, _ = acme.install_issued(key_pem, chain, os.path.join(sdir, cs.name + ".crt"), os.path.join(sdir, cs.name + ".key"), _key_write_pw(cs))
            acme.clear_pending(cs.state_dir, cs.name)
            click.echo(f"[{cs.name}] 스테이징 발급 성공(일련번호 {bundle.serial:x}) — 운영 위치에는 설치하지 않았습니다. 이제 --staging 없이 실행하세요")
            return 0
        bundle, _ = acme.install_issued(key_pem, chain, cs.cert_file, cs.key_file, _key_write_pw(cs))
        acme.clear_pending(cs.state_dir, cs.name)
    except BackoffActive as e:
        click.echo(f"발급 건너뜀: {e}", err=True)
        return 0
    except (acme.AcmeError, DnsProviderError, ManualError, DnsError, OSError) as e:
        backoff.record_failure()
        return _report_issue_failure(cs, notifier, backoff, f"{type(e).__name__}: {e}")
    backoff.record_success()
    notifier.resolve(_lego_label(cs))
    notifier.resolve(_lego_label(cs) + ":dns")
    click.echo(f"[{cs.name}] 발급 완료: 일련번호 {bundle.serial:x}, 만료 {bundle.not_after:%Y-%m-%d} → {cs.cert_file}")
    if no_deploy:
        return 0
    return _run_deploy(cfg, cs, _bundle(cs), force_deploy, False, (), False, action="renew", issue_failures=0)


def _issue_one(cfg, cs, staging, force_run, no_deploy, force_deploy, ignore_backoff):
    if cs.acme:
        return _issue_acme(cfg, cs, staging, force_run, no_deploy, force_deploy, ignore_backoff)
    if not cs.lego:
        click.echo(f"[{cs.name}] lego 설정이 없어 발급을 건너뜁니다", err=True)
        return 1
    notifier = build_notifier(cs.notify)
    backoff = IssueBackoff(cs.state_dir)
    try:
        action = LegoIssuer(cs.lego).ensure(staging=staging, force_run=force_run, backoff=backoff,
                                            backoff_minutes=cs.options.lego_backoff_minutes,
                                            ignore_backoff=ignore_backoff)
    except BackoffActive as e:
        click.echo(f"발급 건너뜀: {e}", err=True)
        action = None
    except IssueError as e:
        return _report_issue_failure(cs, notifier, backoff, str(e))
    if action:
        notifier.resolve(_lego_label(cs))
        click.echo(f"lego {action} 완료 → {lego_output_paths(cs.lego)[0]}")
    if no_deploy:
        return 0
    bundle = _bundle(cs)
    return _run_deploy(cfg, cs, bundle, force_deploy, False, (), False, action="renew", issue_failures=backoff.failures)


def _issue_all(obj, staging, force_run, no_deploy, force_deploy, ignore_backoff):
    cfg, sets = _sets(obj)
    codes = []
    for cs in sets:
        _hdr(cs, len(sets) > 1)
        codes.append(_issue_one(cfg, cs, staging, force_run, no_deploy, force_deploy, ignore_backoff))
    sys.exit(_worst(codes))


@main.command()
@click.option("--staging", is_flag=True, help="Let's Encrypt 스테이징 CA 사용(시험용)")
@click.option("--no-deploy", is_flag=True, help="발급만 하고 배포하지 않음")
@click.option("--ignore-backoff", is_flag=True, help="직전 실패 후 대기 시간을 무시하고 시도")
@click.pass_obj
def issue(obj, staging, no_deploy, ignore_backoff):
    """(최초) 인증서를 발급(lego run)하고 배포한다."""
    _issue_all(obj, staging, True, no_deploy, False, ignore_backoff)


@main.command()
@click.option("--staging", is_flag=True)
@click.option("--no-deploy", is_flag=True)
@click.option("--force-deploy", is_flag=True)
@click.option("--ignore-backoff", is_flag=True)
@click.pass_obj
def renew(obj, staging, no_deploy, force_deploy, ignore_backoff):
    """갱신(lego renew; 인증서가 없으면 최초 발급)하고 배포한다. 타이머로 주기 실행하는 명령."""
    _issue_all(obj, staging, False, no_deploy, force_deploy, ignore_backoff)


# ------------------------------------------------------------------ 배포 승인
def _find_request(sets, req_id):
    for cs in sets:
        for r in approval.list_requests(cs.state_dir, include_closed=True):
            if r["id"] == req_id:
                return cs, r
    raise click.ClickException(f"승인 요청을 찾을 수 없습니다: {req_id}")


@main.command()
@click.option("--all", "show_all", is_flag=True, help="완료·반려·만료된 이력도 표시")
@click.pass_obj
def approvals(obj, show_all):
    """배포 승인 요청 목록(대기 중 기본)."""
    cfg, sets = _sets(obj)
    n = 0
    for cs in sets:
        for r in approval.list_requests(cs.state_dir, include_closed=show_all):
            n += 1
            who = ", ".join(a["by"] for a in r["approvals"]) or "-"
            click.echo(f"{r['id']}  [{approval.label(r['status'])}]  인증서 {r['cert']}  일련번호 {r.get('serial')}  승인 {len(r['approvals'])}/{r.get('needed', 0)} ({who})  "
                       f"요청 {r['requested_at']} by {r['requested_by']}  유효 ~ {r.get('expires_at', '-')}")
    if not n:
        click.echo("대기 중인 승인 요청이 없습니다" if not show_all else "승인 이력이 없습니다")


@main.command()
@click.argument("request_id")
@click.option("--by", default=None, help="승인자 이름(기본: 현재 OS 사용자)")
@click.option("--comment", default="", help="승인 의견")
@click.pass_obj
def approve(obj, request_id, by, comment):
    """배포 승인. 필요한 인원(approvers)이 모두 승인하면 다음 배포(타이머 또는 deploy)에서 반영된다."""
    cfg, sets = _sets(obj)
    cs, _ = _find_request(sets, request_id)
    try:
        r = approval.approve(cs.state_dir, request_id, by or _whoami(), comment)
    except approval.ApprovalError as e:
        raise click.ClickException(str(e))
    _approval_audit(cs, "approval_approved", r, {"actor": by or _whoami(), "approvals": len(r["approvals"]), "needed": r["needed"]})
    _push_approval_metrics(cs)
    if r["status"] == "approved":
        click.echo(f"승인 완료({len(r['approvals'])}/{r['needed']}). 즉시 반영하려면: certdeploy --cert {cs.name} deploy  (아니면 다음 갱신 점검 때 자동 반영)")
        build_notifier(cs.notify).resolve(f"approval:{cs.name}")
    else:
        click.echo(f"승인 {len(r['approvals'])}/{r['needed']} — 다른 승인자가 더 필요합니다")


@main.command()
@click.argument("request_id")
@click.option("--by", default=None)
@click.option("--reason", default="", help="반려 사유")
@click.pass_obj
def reject(obj, request_id, by, reason):
    """배포 승인 요청을 반려한다(이 인증서는 새 요청을 만들기 전까지 배포되지 않는다)."""
    cfg, sets = _sets(obj)
    cs, _ = _find_request(sets, request_id)
    try:
        r = approval.reject(cs.state_dir, request_id, by or _whoami(), reason)
    except approval.ApprovalError as e:
        raise click.ClickException(str(e))
    _approval_audit(cs, "approval_rejected", r, {"actor": by or _whoami(), "reason": reason})
    _push_approval_metrics(cs)
    click.echo(f"반려했습니다: {request_id}")


@main.command("approval-request")
@click.pass_obj
def approval_request(obj):
    """반려·만료된 인증서에 대해 승인 요청을 다시 만든다."""
    cfg, sets = _sets(obj)
    for cs in sets:
        if not cs.approval:
            click.echo(f"[{cs.name}] 승인 정책이 없습니다")
            continue
        b = _bundle(cs)
        g = approval.gate(cs.name, cs.state_dir, cs.approval, b, [t.name for t in cs.targets], "deploy", _whoami(), reopen=True)
        click.echo(f"[{cs.name}] 요청 {g.request['id']} — {approval.label(g.request['status'])}")
        if g.created:
            build_notifier(cs.notify).fire(f"approval:{cs.name}", f"인증서 배포 승인 요청: {cs.name}",
                                           f"일련번호 {g.request['serial']} 배포 승인이 필요합니다. certdeploy approve {g.request['id']}", "warning")
            _approval_audit(cs, "approval_requested", g.request, {"actor": _whoami()})
        _push_approval_metrics(cs)


# ------------------------------------------------------------------ 운영 편의
# ------------------------------------------------------------------ 수동 발급 인증서(상용 CA 구매 등)
def _one_set(obj):
    cfg, sets = _sets(obj)
    if len(sets) != 1:
        raise click.ClickException("인증서가 여러 개입니다 — 전역 옵션 --cert 이름 으로 하나를 지정하세요")
    return cfg, sets[0]


@main.command()
@click.option("--domains", help="쉼표로 구분한 도메인(첫 번째가 CN). 생략하면 lego.domains 를 사용")
@click.option("--key-type", default="rsa2048", show_default=True, type=click.Choice(["rsa2048", "rsa3072", "rsa4096", "ec256", "ec384"]))
@click.option("--country", help="국가 코드(예: KR)")
@click.option("--state")
@click.option("--locality")
@click.option("--org", help="조직명(OV 인증서용)")
@click.option("--ou", help="부서")
@click.option("--force", is_flag=True, help="대기 중인 키/CSR 을 덮어씀(이미 제출한 CSR 의 키를 잃는다)")
@click.pass_obj
def csr(obj, domains, key_type, country, state, locality, org, ou, force):
    """수동 발급용 키와 CSR 을 만든다. 키는 이 서버의 대기 디렉터리(0600)에만 저장되고, CSR 만 CA 에 제출한다."""
    cfg, cs = _one_set(obj)
    names = [d.strip() for d in (domains.split(",") if domains else (cs.lego or {}).get("domains", [])) if d.strip()]
    if not names:
        raise click.ClickException("--domains 로 도메인을 지정하세요(예: --domains '*.univ.example,univ.example')")
    subject = {k: v for k, v in {"C": country, "ST": state, "L": locality, "O": org, "OU": ou}.items() if v}
    try:
        key_pem, csr_pem = generate_csr(names, key_type, subject)
        kp, cp = save_pending(cs.state_dir, cs.name, key_pem, csr_pem, force, key_password=_key_write_pw(cs))
    except ManualError as e:
        raise click.ClickException(str(e))
    click.echo(f"키(0600): {kp}\nCSR: {cp}\n\n아래 CSR 을 CA(예: RapidSSL/DigiCert)에 제출하세요. 개인키는 외부로 보내지 마세요.\n")
    click.echo(csr_pem.decode())
    click.echo("CA 에서 인증서를 받으면: certdeploy import --file <서버 인증서> [--file <중간 CA 번들>] --deploy")


@main.command("import")
@click.option("--file", "files", multiple=True, type=click.Path(), help="CA 가 준 인증서 파일(서버 인증서, 중간 CA 번들 등; PEM/DER/PKCS#7 가능). 여러 번 지정")
@click.option("--key-file", type=click.Path(), help="개인키 PEM(생략하면 csr 로 만든 대기 키 사용)")
@click.option("--key-pass-env", help="개인키 암호가 든 환경변수 이름")
@click.option("--pfx", type=click.Path(), help="키+인증서가 든 PFX/P12 (이 경우 --file 불필요)")
@click.option("--pfx-pass-env", help="PFX 비밀번호가 든 환경변수 이름")
@click.option("--dry-run", is_flag=True, help="검증·정리 결과만 보여주고 설치하지 않음")
@click.option("--deploy", "do_deploy", is_flag=True, help="설치 후 바로 배포")
@click.option("--force-deploy", is_flag=True)
@click.pass_obj
def import_cmd(obj, files, key_file, key_pass_env, pfx, pfx_pass_env, dry_run, do_deploy, force_deploy):
    """수동으로 받은 인증서를 검증·정리(체인 정렬)해 설정된 위치에 설치한다. 선택적으로 바로 배포."""
    cfg, cs = _one_set(obj)
    used_pending = None
    try:
        if pfx:
            key, certs = load_pfx(pfx, os.environ.get(pfx_pass_env or ""))
            certs += collect_certs(list(files)) if files else []
        else:
            if not files:
                raise ManualError("--file 로 CA 가 준 인증서 파일을 지정하거나 --pfx 를 사용하세요")
            certs = collect_certs(list(files))
            if key_file:
                key = load_key_file(key_file, os.environ.get(key_pass_env or ""))
            else:
                used_pending = os.path.join(pending_dir(cs.state_dir, cs.name), "key.pem")
                if not os.path.exists(used_pending):
                    raise ManualError("개인키가 없습니다 — 먼저 `certdeploy csr` 로 키/CSR 을 만들었거나 --key-file 을 지정해야 합니다")
                key = load_key_file(used_pending, _key_read_pw(cs))
        with trace.span("import", "build_bundle", files=len(certs), pfx=bool(pfx), pending_key=bool(used_pending)) as ctx:
            bundle, notes = build_bundle(certs, key)
            ctx.update(serial=f"{bundle.serial:x}", chain=len(bundle.chain), notes=notes)
    except ManualError as e:
        click.echo(f"가져오기 실패: {e}", err=True)
        trace.event("import", "failed", "error", message=str(e))
        sys.exit(2)
    click.echo(f"서버 인증서: 일련번호 {bundle.serial:x}, 유효 {bundle.not_before:%Y-%m-%d} ~ {bundle.not_after:%Y-%m-%d} (남은 {bundle.days_left():.0f}일)")
    click.echo(f"SAN: {', '.join(bundle.names)}   중간 CA {len(bundle.chain)}개")
    for n in notes:
        click.echo(f"주의: {n}")
    if dry_run:
        click.echo("(--dry-run) 설치하지 않았습니다.")
        return
    os.makedirs(os.path.dirname(cs.cert_file), mode=0o700, exist_ok=True)
    os.makedirs(os.path.dirname(cs.key_file), mode=0o700, exist_ok=True)
    with trace.span("import", "install", cert_file=cs.cert_file, key_file=cs.key_file) as ctx:
        backups = install_bundle(cs.cert_file, cs.key_file, bundle, key_password=_key_write_pw(cs))
        ctx["backups"] = backups
    click.echo(f"설치 완료: {cs.cert_file} (서버+중간 CA), {cs.key_file} (0600)")
    for b in backups:
        click.echo(f"이전 파일 백업: {b}")
    if used_pending:                      # 개인키 사본이 두 곳에 남지 않도록 대기 키 삭제
        try:
            os.remove(used_pending)
        except OSError:
            pass
    if do_deploy:
        sys.exit(_run_deploy(cfg, cs, _bundle(cs), force_deploy, False, (), False, action="import"))


@main.command()
@click.option("--warn", "warn_days", default=30, show_default=True, help="남은 일수가 이 값 이하면 WARNING")
@click.option("--crit", "crit_days", default=14, show_default=True, help="남은 일수가 이 값 이하면 CRITICAL")
@click.pass_obj
def check(obj, warn_days, crit_days):
    """Nagios/Zabbix/cron 용 한 줄 점검: 관리 중인 인증서 만료일 + 각 서버가 같은 인증서를 서빙하는지.
    종료 코드: 0 OK · 1 WARNING · 2 CRITICAL · 3 UNKNOWN(설정·인증서 읽기 오류)."""
    try:
        cfg, sets = _sets(obj)
    except click.ClickException as e:
        click.echo(f"CERTDEPLOY UNKNOWN - {e.message.splitlines()[0]}")
        sys.exit(3)
    level, notes, perf = 0, [], []
    for cs in sets:
        b = _bundle(cs, exit_on_error=False)
        if b is None:
            click.echo(f"CERTDEPLOY UNKNOWN - {cs.name}: 인증서를 읽을 수 없습니다")
            sys.exit(3)
        left = b.days_left()
        lv = 2 if left <= crit_days else 1 if left <= warn_days else 0
        level = max(level, lv)
        notes.append(f"{cs.name} 만료까지 {left:.0f}일")
        perf.append(f"'{cs.name}_days_left'={left:.0f};{warn_days};{crit_days}")
        d = _deployer(cs, b)
        for t in cs.targets:
            if not t.verify:
                continue
            try:
                got = d._tls(t)
            except VerifyError as e:
                level = 2
                notes.append(f"{t.name} 서빙 확인 실패({str(e)[:60]})")
                continue
            if got != b.serial:
                level = max(level, 1 if lv == 0 else lv)
                notes.append(f"{t.name} 이전/다른 인증서 서빙")
    word = ("OK", "WARNING", "CRITICAL")[level]
    click.echo(f"CERTDEPLOY {word} - {'; '.join(notes)} | {' '.join(perf)}")
    sys.exit(level)


@main.command()
def schema():
    """설정 파일의 JSON Schema 를 출력한다(편집기 자동완성·검증용: yaml-language-server 등)."""
    from .schema import config_schema
    click.echo(json.dumps(config_schema(), ensure_ascii=False, indent=2))


@main.command("notify-test")
@click.pass_obj
def notify_test(obj):
    """설정된 알림 채널(메일·Alertmanager·웹훅)로 시험 알림을 보낸다. 수신 여부는 받는 쪽에서 확인한다."""
    cfg = _cfg(obj)
    n = cfg.certs[0].notify
    chans = []
    if n.alertmanager_url:
        chans.append(f"Alertmanager({n.alertmanager_url})")
    if n.smtp:
        chans.append(f"메일({', '.join(n.smtp.to)} ← {n.smtp.host}:{n.smtp.port})")
    if n.webhook:
        chans.append(f"웹훅({n.webhook.format})")
    if not chans:
        raise click.ClickException("알림 채널이 설정되어 있지 않습니다(notify.smtp / alertmanager_url / webhook)")
    notifier = build_notifier(n)
    notifier.fire("notify-test", "certdeploy 알림 시험", "알림 경로 시험입니다. 이 메시지가 도착했다면 정상이며, 무시하셔도 됩니다.", "warning")
    notifier.resolve("notify-test")
    click.echo("시험 알림을 보냈습니다: " + ", ".join(chans) + "\n전송 오류는 `certdeploy trace --errors` 의 notify/* 이벤트로 확인할 수 있습니다(수신함도 확인하세요).")


@main.command()
@click.option("--target", "name", required=True, help="수동 교체 대상 이름")
@click.pass_obj
def confirm(obj, name):
    """수동 교체 대상(type: manual)의 교체 완료를 기록하고 교체용 파일(개인키 포함)을 삭제한다."""
    cfg, sets = _sets(obj)
    for cs in sets:
        t = next((x for x in cs.targets if x.name == name), None)
        if t is None:
            continue
        if not t.manual:
            raise click.ClickException(f"{name} 은(는) 수동 교체 대상이 아닙니다")
        d = _deployer(cs, _bundle(cs))
        d.manual_done(t)
        click.echo(f"[{name}] 수동 교체 완료를 기록했고 교체용 파일을 삭제했습니다")
        return
    raise click.ClickException(f"대상을 찾을 수 없습니다: {name}")


@main.command("key-encrypt")
@click.pass_obj
def key_encrypt(obj):
    """저장된 개인키를 암호(certificate.key_password_env)로 보호된 형태로 바꾼다. 이후 설정에 key_encryption: passphrase 를 켠다."""
    _convert_key(obj, encrypt=True)


@main.command("key-decrypt")
@click.pass_obj
def key_decrypt(obj):
    """암호로 보호된 개인키를 평문(권한 600)으로 바꾼다. 이후 설정을 key_encryption: none 으로 바꾼다."""
    _convert_key(obj, encrypt=False)


def _convert_key(obj, encrypt: bool):
    from .manual import convert_key_file
    cfg, cs = _one_set(obj)
    pw = (os.environ.get(cs.key_password_env) if cs.key_password_env else None) or cs.key_passphrase
    if not pw:
        raise click.ClickException(f"암호가 필요합니다: 환경변수 {cs.key_password_env or '(certificate.key_password_env 미설정)'} 또는 관리자 화면의 개인키 보호 암호")
    try:
        changed, bak = convert_key_file(cs.key_file, pw, encrypt)
    except ManualError as e:
        click.echo(f"변환 실패: {e}", err=True)
        sys.exit(2)
    if not changed:
        click.echo(f"이미 {'암호화' if encrypt else '평문'} 상태입니다 — 변경하지 않았습니다")
        return
    click.echo(f"개인키를 {'암호화' if encrypt else '평문으로 변환'}했습니다: {cs.key_file}\n변환 전 파일: {bak} (확인 후 삭제하세요)\n"
               f"설정에 key_encryption: {'passphrase' if encrypt else 'none'} 를 지정하고 `certdeploy validate` 로 확인하세요")


@main.command("acme-reset")
@click.pass_obj
def acme_reset(obj):
    """진행 중인 내장 ACME 주문(대기 키·TXT 안내)을 폐기한다. 처음부터 다시 시작할 때 사용."""
    cfg, cs = _one_set(obj)
    had = acme.load_pending(cs.state_dir, cs.name) is not None
    acme.clear_pending(cs.state_dir, cs.name)
    click.echo("대기 중인 주문을 폐기했습니다" if had else "대기 중인 주문이 없습니다")


@main.command("trace")
@click.option("--run", "run_id", help="작업 ID 로 필터")
@click.option("--errors", is_flag=True, help="경고·오류만")
@click.option("--debug", "show_debug", is_flag=True, help="상세(.start) 이벤트 포함")
@click.option("-n", "count", default=60, show_default=True)
@click.pass_obj
def trace_cmd(obj, run_id, errors, show_debug, count):
    """최근 실행의 단계별 진단 이벤트(성공·실패·소요시간)를 본다. 비밀값은 마스킹되어 있다."""
    cfg = _cfg(obj)
    evs = []
    for cs in cfg.certs:
        evs += trace.read_file(dg.trace_path(cs.state_dir))
    evs = [e for e in evs if (not run_id or e.get("run_id") == run_id) and (not errors or e["level"] in ("warning", "error"))
           and (show_debug or e["level"] != "debug")]
    if not evs:
        click.echo("기록된 이벤트가 없습니다. 먼저 명령을 실행하세요(항상 기록됩니다).")
    for e in evs[-count:]:
        click.echo(trace.format_event(e))


@main.command()
@click.option("--out", type=click.Path(), help="진단 번들을 저장할 JSON 파일(생략하면 요약만 출력)")
@click.option("--prometheus", help="Prometheus 주소(예: http://127.0.0.1:9090) — 수집 대상·규칙·certdeploy 지표 점검")
@click.option("--alertmanager", help="Alertmanager 주소")
@click.option("--pushgateway", help="Pushgateway 주소")
@click.pass_obj
def diagnose(obj, out, prometheus, alertmanager, pushgateway):
    """설정·인증서·마지막 실행·트레이스·감시 스택을 점검해 문제 목록과(선택) 공유용 번들을 만든다. 비밀값 제외."""
    b = dg.build(obj["config"], prometheus, alertmanager, pushgateway)
    for c in b["checks"]:
        click.echo(f"[{'OK' if c['ok'] else '문제'}] {c['name']}" + (f" — {c['detail']}" if c["detail"] else "") + (f"  → {c['hint']}" if c["hint"] else ""))
    if out:
        with open(os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
            f.write(cpdiag.dumps(b))
        click.echo(f"진단 번들 저장: {out} (비밀값 마스킹됨)")
    sys.exit(0 if b["ok"] else 1)


@main.command("verify-audit")
@click.pass_obj
def verify_audit(obj):
    """배포 감사 로그의 해시 체인 무결성을 검증한다."""
    cfg = _cfg(obj)
    if not cfg.audit_dir:
        raise click.ClickException("설정에 audit_log 가 없습니다")
    from certpilot_core.audit_storage import AuditLogReader
    r = AuditLogReader(cfg.audit_dir).verify_integrity()
    click.echo(json.dumps(r, ensure_ascii=False, indent=2))
    sys.exit(0 if r["integrity_valid"] else 1)


@main.command()
@click.option("--out", "out", required=True, type=click.Path(), help="백업 파일(.cdbk)")
@click.option("--passphrase-env", required=True, help="백업 비밀번호가 담긴 환경변수 이름(12자 이상)")
@click.pass_obj
def backup(obj, out, passphrase_env):
    """lego 계정·인증서, 상태, 설정 파일을 암호화해 백업한다."""
    cfg, sets = _sets({**obj, "cert": None})
    pw = os.environ.get(passphrase_env)
    if not pw:
        raise click.ClickException(f"환경변수 {passphrase_env} 가 설정되지 않았습니다")
    sources = {"config/" + os.path.basename(obj["config"]): obj["config"]}
    for cs in cfg.certs:
        sources[f"state/{cs.name}"] = cs.state_dir
        if cs.lego:
            sources[f"lego/{cs.name}"] = cs.lego.get("path", "/var/lib/lego")
    try:
        blob = create_backup(sources, pw)
    except BackupError as e:
        raise click.ClickException(str(e))
    with open(os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(blob)
    click.echo(f"백업 완료: {out} ({len(blob)} bytes, 항목 {len(sources)}개). 이 파일에는 개인키가 들어 있으므로 안전한 곳에 보관하세요.")


@main.command()
@click.option("--in", "src", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--dest", required=True, type=click.Path(), help="복원할 디렉터리(기존 위치에 덮어쓰지 않도록 별도 위치에 풀어 확인 후 옮긴다)")
@click.option("--passphrase-env", required=True)
def restore(src, dest, passphrase_env):
    """암호화 백업을 지정 디렉터리에 복원한다."""
    pw = os.environ.get(passphrase_env)
    if not pw:
        raise click.ClickException(f"환경변수 {passphrase_env} 가 설정되지 않았습니다")
    try:
        names = restore_backup(open(src, "rb").read(), pw, dest)
    except BackupError as e:
        raise click.ClickException(str(e))
    click.echo(f"복원 완료: {dest} ← {', '.join(names)}")


# ------------------------------------------------------------------ 백업 자동화
def _backup_cfg(obj):
    cfg = _cfg(obj)
    if not cfg.backup:
        raise click.ClickException("설정 파일에 backup: 항목이 없습니다 — certdeploy.example.yml 의 backup 예시를 참고하세요")
    return cfg, cfg.backup


def _backup_pw(b):
    try:
        return backupjob.passphrase_of(b)
    except BackupError as e:
        raise click.ClickException(str(e))


@main.command("backup-run")
@click.option("--quiet", is_flag=True, help="성공 시 출력 최소화(타이머용)")
@click.pass_obj
def backup_run(obj, quiet):
    """관리 서버 전체(설정·상태·관리자 DB·감시 비밀·nginx)를 암호화 백업하고 검증·외부 복사·보관 정리·알림까지 수행한다."""
    cfg, b = _backup_cfg(obj)
    res = backupjob.run_backup(cfg, obj["config"], b, _backup_pw(b))
    state_dir = cfg.state_dir
    try:
        backupjob.save_status(state_dir, res)
    except OSError as e:
        click.echo(f"주의: 상태 기록 실패({type(e).__name__})", err=True)
    n = cfg.notify
    if n.pushgateway_url:
        pw = os.environ.get(n.pushgateway_password_env or "") if n.pushgateway_password_env else None
        push_metrics(n.pushgateway_url, "backup", backupjob.metrics_text(res), n.pushgateway_user, pw)
    notifier = build_notifier(n)
    if not res.ok:
        notifier.fire("backup", "백업 실패", f"{res.error}\n파일: {res.name}\n외부 복사: " + ", ".join(f"{c['name']}={'성공' if c['ok'] else '실패(' + c['error'] + ')'}" for c in res.copies), "critical")
    elif res.partial:
        notifier.fire("backup", "백업 일부 누락", "읽지 못해 빠진 항목:\n" + "\n".join(res.skipped[:20]), "warning")
    else:
        notifier.resolve("backup")
    if res.ok and not (quiet and not res.partial):
        click.echo(f"백업 완료: {os.path.join(b['dir'], res.name)} ({res.size:,} bytes, 항목 {res.members}개, {res.duration_s}초)")
        for c in res.copies:
            click.echo(f"  외부 복사 {c['name']} → {c['label']}")
        if res.pruned:
            click.echo(f"  오래된 백업 {len(res.pruned)}개 정리")
    if res.partial:
        click.echo(f"경고: 읽지 못해 빠진 항목 {len(res.skipped)}개 — " + "; ".join(res.skipped[:5]), err=True)
    if not res.ok:
        click.echo(f"백업 실패: {res.error}", err=True)
        for c in res.copies:
            if not c["ok"]:
                click.echo(f"  외부 복사 실패 {c['name']}: {c['error']}", err=True)
    sys.exit(0 if res.ok else 1)


@main.command("backup-list")
@click.pass_obj
def backup_list(obj):
    """로컬 보관 위치의 백업 목록."""
    cfg, b = _backup_cfg(obj)
    rows = backupjob.list_backups(b)
    for r in rows:
        click.echo(f"{r['name']}  {r['size']:>12,} bytes  {r['created']}")
    click.echo(f"총 {len(rows)}개 ({b['dir']})" if rows else f"백업이 없습니다 ({b['dir']})")


@main.command("backup-status")
@click.option("--max-age-hours", default=36, show_default=True, help="마지막 성공이 이보다 오래되면 종료 코드 1")
@click.pass_obj
def backup_status(obj, max_age_hours):
    """마지막 백업 실행 결과(성공 여부·크기·외부 복사·경과 시간)."""
    cfg, b = _backup_cfg(obj)
    st = backupjob.load_status(cfg.state_dir)
    if not st:
        click.echo("백업 기록이 없습니다 — certdeploy backup-run 을 실행하세요")
        sys.exit(1)
    age = backupjob.age_hours(st)
    click.echo(f"마지막 실행: {st['finished']} ({age:.1f}시간 전)  결과: {'성공' if st['ok'] else '실패'}{' (일부 누락)' if st.get('partial') else ''}  파일: {st['name']} ({st['size']:,} bytes)")
    for c in st.get("copies", []):
        click.echo(f"  외부 복사 {c['name']}: {'성공' if c['ok'] else '실패 — ' + c['error']}")
    if st.get("error"):
        click.echo(f"  오류: {st['error']}")
    sys.exit(0 if st["ok"] and age is not None and age <= max_age_hours else 1)


@main.command("backup-verify")
@click.option("--file", "path", type=click.Path(exists=True, dir_okay=False), help="검증할 백업 파일(기본: 가장 최근 로컬 백업)")
@click.option("--deep", is_flag=True, help="임시 폴더에 풀어 인증서·키 짝과 DB 무결성까지 확인(끝나면 삭제)")
@click.pass_obj
def backup_verify(obj, path, deep):
    """백업이 실제로 복원 가능한지 확인한다(비밀번호로 복호화, 항목 목록, --deep 은 내용 점검)."""
    cfg, b = _backup_cfg(obj)
    if not path:
        rows = backupjob.list_backups(b)
        if not rows:
            raise click.ClickException("검증할 백업이 없습니다")
        path = os.path.join(b["dir"], rows[0]["name"])
    pw = _backup_pw(b)
    try:
        blob = open(path, "rb").read()
        members = backup_mod.list_members(blob, pw)
        click.echo(f"복호화·목록 확인 OK: {path} (항목 {len(members)}개)")
        if deep:
            rep = backupjob.deep_verify(blob, pw)
            for c in rep["certs"]:
                click.echo(f"  인증서 {c['name']}: {'OK' if c['ok'] else '실패'} {c.get('serial', '') or c.get('note', '') or c.get('error', '')}")
            for d in rep["databases"]:
                click.echo(f"  DB {d['name']}: {'무결성 OK' if d['ok'] else '오류'}")
            for p_ in rep["problems"]:
                click.echo(f"문제: {p_}", err=True)
            sys.exit(1 if rep["problems"] else 0)
    except (BackupError, OSError) as e:
        click.echo(f"검증 실패: {e}", err=True)
        sys.exit(1)


@main.command("backup-restore")
@click.option("--file", "path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--root", default="/", show_default=True, help="복구 대상 루트(시험·점검용으로 다른 폴더 지정 가능)")
@click.option("--apply", "apply_", is_flag=True, help="실제로 되돌린다(기본은 계획만 출력). 기존 파일은 .pre-restore-<시각> 로 옮겨 둔다")
@click.pass_obj
def backup_restore(obj, path, root, apply_):
    """백업을 원래 위치에 되돌린다(새 VM 복구용). 먼저 계획을 확인한 뒤 --apply."""
    cfg, b = _backup_cfg(obj)
    pw = _backup_pw(b)
    try:
        plan = backupjob.restore_apply(open(path, "rb").read(), pw, root, dry_run=not apply_)
    except (BackupError, OSError, ValueError) as e:
        raise click.ClickException(f"복구 실패: {e}")
    for r in plan:
        click.echo(f"{'복구함' if apply_ else '복구 예정'}: {r['archive']} → {r['dest']} (소유자 {r['owner']}){' [기존 파일은 .pre-restore 로 이동]' if r['exists'] else ''}")
    if not apply_:
        click.echo("\n계획만 출력했습니다. 적용하려면 --apply 를 붙이세요. 적용 후 서비스 재시작과 확인 절차는 설치 매뉴얼 10-4 를 따르세요.")
    else:
        click.echo("\n복구 완료. 서비스를 재시작하고 `certdeploy validate`, `certdeploy status` 로 확인하세요.")


@main.command()
@click.argument("csv_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--user", default="deploy", show_default=True, help="SSH 접속 계정")
@click.option("--key-file", default="/var/lib/certdeploy/.ssh/id_ed25519", show_default=True)
@click.option("--known-hosts", default="/var/lib/certdeploy/.ssh/known_hosts", show_default=True)
def scaffold(csv_file, user, key_file, known_hosts):
    """서버 목록 CSV(name,host,type,port,canary,order,cert_path,key_path)로 targets 설정 조각을 만든다."""
    targets, errors = [], []
    with open(csv_file, newline="", encoding="utf-8-sig") as f:
        for n, row in enumerate(csv.DictReader(f), start=2):
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            name, host, typ = row.get("name", ""), row.get("host", ""), row.get("type") or "apache"
            if not NAME_RE.match(name) or not HOST_RE.match(host):
                errors.append(f"{n}행: name/host 형식 오류 ({name!r}, {host!r})")
                continue
            if typ not in TYPES:
                errors.append(f"{n}행: type 은 {', '.join(TYPES)} 중 하나여야 합니다: {typ!r}")
                continue
            try:
                port = int(row.get("port") or 443)
                order = int(row["order"]) if row.get("order") else None
            except ValueError:
                errors.append(f"{n}행: port/order 는 숫자여야 합니다")
                continue
            t = {"name": name, "type": typ, "transport": {"kind": "ssh", "host": host, "user": user,
                                                           "key_file": key_file, "known_hosts": known_hosts},
                 "verify": {"host": host, "port": port}}
            if row.get("canary", "").lower() in ("y", "yes", "true", "1"):
                t["canary"] = True
            if order is not None:
                t["order"] = order
            if typ in ("apache", "nginx", "nodejs"):
                t["cert_path"] = row.get("cert_path") or "/etc/ssl/univ/fullchain.pem"
                t["key_path"] = row.get("key_path") or "/etc/ssl/univ/privkey.pem"
            if typ in ("nodejs", "tomcat", "generic"):
                t["reload_cmd"] = "TODO: 재로드 명령"
            targets.append(t)
    if errors:
        for e in errors:
            click.echo(f"오류: {e}", err=True)
        sys.exit(1)
    click.echo("# certdeploy scaffold 로 생성 — 경로·재로드 명령(TODO)을 확인해 설정 파일의 targets 에 붙여넣으세요")
    click.echo(yaml.safe_dump({"targets": targets}, allow_unicode=True, sort_keys=False, default_flow_style=False))


if __name__ == "__main__":
    main()
