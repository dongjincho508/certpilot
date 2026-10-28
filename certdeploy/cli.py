"""certdeploy 명령행. 종료 코드: 0 성공 · 1 배포/점검 문제 · 2 설정·인증서 오류 · 3 다른 작업 실행 중."""
import logging
import os
import sys

import click

from . import __version__
from .bundle import BundleError, load_bundle
from .config import ConfigError, load_config
from .engine import Deployer
from .issuer import IssueError, LegoIssuer, lego_output_paths
from .notify import AlertmanagerNotifier, NullNotifier
from .state import LockedError, State, exclusive_lock
from .verify import VerifyError, tls_serial

STATUS_LABEL = {"deployed": "배포 완료", "skipped": "건너뜀", "failed": "실패", "rolled_back": "롤백됨",
                "dry_run": "계획만", "not_run": "실행 안 함"}


def _load(ctx_obj):
    try:
        cfg = load_config(ctx_obj["config"])
    except ConfigError as e:
        raise click.ClickException(str(e)) from None
    return cfg


def _bundle(cfg):
    pw = os.environ.get(cfg.key_password_env) if cfg.key_password_env else None
    try:
        return load_bundle(cfg.cert_file, cfg.key_file, pw)
    except BundleError as e:
        click.echo(f"인증서 오류: {e}", err=True)
        sys.exit(2)


def _deployer(cfg, bundle):
    notifier = AlertmanagerNotifier(cfg.alertmanager_url) if cfg.alertmanager_url else NullNotifier()
    try:
        state = State(cfg.state_dir).load()
    except RuntimeError as e:
        raise click.ClickException(str(e)) from None
    return Deployer(cfg, bundle, state, notifier=notifier)


def _print_results(results):
    for r in results:
        click.echo(f"[{r.name}] {STATUS_LABEL.get(r.status, r.status)}" + (f" — {r.message}" if r.message else ""))
    ok = all(r.status in ("deployed", "skipped", "dry_run") for r in results)
    n = {k: sum(1 for r in results if r.status == k) for k in STATUS_LABEL}
    click.echo("요약: " + ", ".join(f"{STATUS_LABEL[k]} {v}" for k, v in n.items() if v))
    return 0 if ok else 1


@click.group()
@click.option("-c", "--config", "config", required=True, envvar="CERTDEPLOY_CONFIG", type=click.Path(), help="설정 파일(YAML)")
@click.option("-v", "--verbose", is_flag=True)
@click.version_option(__version__)
@click.pass_context
def main(ctx, config, verbose):
    """인증서 발급(lego)·자동 배포·검증·롤백."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s")
    ctx.obj = {"config": config}


@main.command()
@click.pass_obj
def validate(obj):
    """설정과 인증서를 검증한다(키 일치·유효기간·체인·대상 호스트명·환경변수)."""
    cfg = _load(obj)
    b = _bundle(cfg)
    d = _deployer(cfg, b)
    click.echo(f"인증서 OK: 일련번호 {b.serial:x}, 만료 {b.not_after:%Y-%m-%d}(남은 {b.days_left():.0f}일), SAN {', '.join(b.names)}")
    for w in b.warnings:
        click.echo(f"주의: {w}")
    problems = d.validate_targets()
    for p in problems:
        click.echo(f"문제: {p}")
    click.echo(f"대상 {len(cfg.targets)}개")
    sys.exit(1 if problems else 0)


@main.command()
@click.option("--target", "only", multiple=True, help="특정 대상만")
@click.pass_obj
def plan(obj, only):
    """배포 계획을 출력한다(아무것도 변경하지 않음)."""
    cfg = _load(obj)
    for line in _deployer(cfg, _bundle(cfg)).plan(list(only) or None):
        click.echo(line)


def _run_deploy(cfg, bundle, force, dry_run, only, cont):
    d = _deployer(cfg, bundle)
    problems = d.validate_targets()
    if problems:
        for p in problems:
            click.echo(f"문제: {p}", err=True)
        return 1
    try:
        with exclusive_lock(cfg.state_dir):
            return _print_results(d.deploy(force=force, dry_run=dry_run, only=list(only) or None, continue_on_error=cont))
    except LockedError as e:
        click.echo(str(e), err=True)
        return 3


@main.command()
@click.option("--force", is_flag=True, help="이미 새 인증서를 서빙 중이어도 다시 배포")
@click.option("--dry-run", is_flag=True, help="계획만 확인")
@click.option("--target", "only", multiple=True)
@click.option("--continue-on-error", is_flag=True, help="실패해도 다음 대상 진행(기본은 중단)")
@click.pass_obj
def deploy(obj, force, dry_run, only, continue_on_error):
    """현재 인증서 파일을 모든 대상에 배포한다."""
    cfg = _load(obj)
    sys.exit(_run_deploy(cfg, _bundle(cfg), force, dry_run, only, continue_on_error))


@main.command()
@click.pass_obj
def status(obj):
    """대상별 마지막 배포 결과와 현재 서빙 중인 인증서를 보여준다."""
    cfg = _load(obj)
    b = _bundle(cfg)
    st = State(cfg.state_dir).load()
    bad = 0
    for t in cfg.targets:
        s = st.target(t.name)
        live = "확인 안 함"
        if t.verify:
            try:
                got = tls_serial(t.verify.host, t.verify.port, t.verify.sni)
                live = "최신" if got == b.serial else f"이전/다른 인증서({got:x})"
                bad += got != b.serial
            except VerifyError as e:
                live, bad = f"조회 실패({e})", bad + 1
        click.echo(f"[{t.name}] 기록: {s.get('status', '없음')} {s.get('deployed_at', '')}  서빙: {live}")
    sys.exit(1 if bad else 0)


@main.command()
@click.option("--target", required=True)
@click.pass_obj
def rollback(obj, target):
    """마지막 배포 이전 파일로 되돌리고 재로드한다."""
    cfg = _load(obj)
    d = _deployer(cfg, _bundle(cfg))
    try:
        with exclusive_lock(cfg.state_dir):
            r = d.rollback(target)
    except KeyError:
        raise click.ClickException(f"알 수 없는 대상: {target}")
    except LockedError as e:
        raise click.ClickException(str(e))
    click.echo(f"[{r.name}] {STATUS_LABEL.get(r.status, r.status)} — {r.message}")
    sys.exit(0 if r.status == "rolled_back" else 1)


def _issue_and_deploy(obj, staging, force_run, no_deploy, force_deploy):
    cfg = _load(obj)
    if not cfg.lego:
        raise click.ClickException("설정에 lego 항목이 없습니다")
    try:
        action = LegoIssuer(cfg.lego).ensure(staging=staging, force_run=force_run)
    except IssueError as e:
        click.echo(f"발급 실패: {e}", err=True)
        if cfg.alertmanager_url:
            AlertmanagerNotifier(cfg.alertmanager_url).fire("lego", "인증서 발급·갱신 실패", str(e))
        sys.exit(1)
    click.echo(f"lego {action} 완료 → {lego_output_paths(cfg.lego)[0]}")
    if no_deploy:
        return
    sys.exit(_run_deploy(cfg, _bundle(cfg), force_deploy, False, (), False))


@main.command()
@click.option("--staging", is_flag=True, help="Let's Encrypt 스테이징 CA 사용(시험용)")
@click.option("--no-deploy", is_flag=True, help="발급만 하고 배포하지 않음")
@click.pass_obj
def issue(obj, staging, no_deploy):
    """(최초) 인증서를 발급(lego run)하고 배포한다."""
    _issue_and_deploy(obj, staging, True, no_deploy, False)


@main.command()
@click.option("--staging", is_flag=True)
@click.option("--no-deploy", is_flag=True)
@click.option("--force-deploy", is_flag=True)
@click.pass_obj
def renew(obj, staging, no_deploy, force_deploy):
    """갱신(lego renew; 인증서가 없으면 최초 발급)하고 배포한다. 타이머로 주기 실행하는 명령."""
    _issue_and_deploy(obj, staging, False, no_deploy, force_deploy)


if __name__ == "__main__":
    main()
