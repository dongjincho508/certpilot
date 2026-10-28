"""배포 엔진: 대상별로 [현재 상태 확인 → 백업·교체 → 점검 → 재로드 → TLS 확인] 을 수행하고 실패하면 롤백한다.

안전 원칙
- 한 번에 한 대(순차). canary 대상이 먼저이며 실패하면 이후 대상으로 넘어가지 않는다(continue_on_error 로 변경 가능).
- 이미 새 인증서를 서빙 중이면 건드리지 않는다(멱등) — 재시도·타이머 반복 실행이 안전하다.
- 개인키·키스토어 내용은 로그·예외 메시지에 남기지 않는다.
"""
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional

from . import remote
from .bundle import Bundle, BundleError
from .config import Config, Target
from .handlers import KEY_KINDS, FileSpec
from .notify import NullNotifier
from .state import State
from .transport import LocalTransport, SSHTransport, Transport, TransportError
from .verify import VerifyError, tls_serial

log = logging.getLogger("certdeploy")


@dataclass
class TargetResult:
    name: str
    status: str            # deployed | skipped | failed | rolled_back | dry_run | not_run
    message: str = ""
    serial_before: Optional[int] = None


class DeployFailure(Exception):
    pass


def make_transport(tr: dict, timeout: int) -> Transport:
    if tr.get("kind") == "ssh":
        return SSHTransport(tr["host"], tr["user"], int(tr.get("port", 22)), tr.get("key_file"),
                            tr.get("known_hosts"), bool(tr.get("sudo", False)), timeout=int(tr.get("timeout", 15)))
    return LocalTransport(sudo=bool(tr.get("sudo", False)))


class Deployer:
    def __init__(self, cfg: Config, bundle: Bundle, state: State,
                 transport_factory: Optional[Callable[[dict], Transport]] = None,
                 verifier: Callable[..., int] = tls_serial, notifier=None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 environ=os.environ):
        self.cfg, self.bundle, self.state = cfg, bundle, state
        self.transport_factory = transport_factory or (lambda tr: make_transport(tr, cfg.options.command_timeout))
        self.verifier, self.notifier = verifier, notifier or NullNotifier()
        self.sleep, self.clock, self.environ = sleep, clock, environ

    # ---------------------------------------------------------------- 계획
    def ordered(self, only: Optional[List[str]] = None) -> List[Target]:
        ts = [t for t in self.cfg.targets if not only or t.name in only]
        return sorted(ts, key=lambda t: (not t.canary, t.order, t.name))

    def validate_targets(self) -> List[str]:
        """대상 호스트명이 인증서 SAN 에 포함되는지, 키스토어 비밀번호 환경변수가 있는지 점검(문제 목록 반환)."""
        problems = []
        for t in self.cfg.targets:
            if t.verify and not self.bundle.covers(t.verify.sni or t.verify.host):
                problems.append(f"{t.name}: 인증서 SAN 이 {t.verify.sni or t.verify.host} 를 포함하지 않습니다")
            for f in t.files:
                if f.password_env and not self.environ.get(f.password_env):
                    problems.append(f"{t.name}: 환경변수 {f.password_env} 가 설정되지 않았습니다")
        return problems

    def plan(self, only=None) -> List[str]:
        lines = [f"인증서 일련번호 {self.bundle.serial:x}, 만료 {self.bundle.not_after:%Y-%m-%d} (남은 {self.bundle.days_left():.0f}일), "
                 f"이름: {', '.join(self.bundle.names)}"]
        for t in self.ordered(only):
            where = t.transport.get("host") or "로컬"
            lines.append(f"[{t.name}] {t.type}@{where}" + (" (canary)" if t.canary else ""))
            for f in t.files:
                lines.append(f"    파일 {f.dest}  ← {f.content} ({f.mode})")
            lines.append(f"    점검: {t.check_cmd or '없음'}")
            lines.append(f"    재로드: {t.reload_cmd or '없음'}")
            lines.append(f"    확인: {('%s:%d' % (t.verify.host, t.verify.port)) if t.verify else '없음(TLS 확인을 하지 않음)'}")
        return lines

    # ---------------------------------------------------------------- 내용 생성
    def _content(self, f: FileSpec) -> bytes:
        b = self.bundle
        if f.content == "cert":
            return b.cert_pem()
        if f.content == "fullchain":
            return b.fullchain_pem()
        if f.content == "chain":
            return b.chain_pem()
        if f.content == "key":
            return b.key_pem()
        pw = self.environ.get(f.password_env or "")
        if not pw:
            raise DeployFailure(f"환경변수 {f.password_env} 가 설정되지 않았습니다")
        try:
            return b.pkcs12(pw, f.alias, f.legacy_pkcs12) if f.content == "pkcs12" else b.jks(pw, f.alias)
        except BundleError as e:
            raise DeployFailure(str(e))

    # ---------------------------------------------------------------- 실행
    def deploy(self, force=False, dry_run=False, only=None, continue_on_error=False) -> List[TargetResult]:
        results: List[TargetResult] = []
        stop = False
        for t in self.ordered(only):
            if stop:
                results.append(TargetResult(t.name, "not_run", "이전 대상 실패로 중단"))
                continue
            r = self._deploy_target(t, force, dry_run)
            results.append(r)
            if r.status in ("failed", "rolled_back") and not continue_on_error:
                stop = True
        if not dry_run:
            self.state.data["certificate"] = {"serial": f"{self.bundle.serial:x}",
                                              "not_after": self.bundle.not_after.isoformat()}
            self.state.save()
        return results

    def _served_serial(self, t: Target) -> Optional[int]:
        if not t.verify:
            return None
        try:
            return self.verifier(t.verify.host, t.verify.port, t.verify.sni)
        except VerifyError as e:
            log.info("[%s] 현재 서빙 인증서를 확인하지 못함: %s", t.name, e)
            return None

    def _deploy_target(self, t: Target, force: bool, dry_run: bool) -> TargetResult:
        new = self.bundle.serial
        before = self._served_serial(t)
        if before == new and not force:
            return TargetResult(t.name, "skipped", "이미 새 인증서를 서빙 중", before)
        # TLS 확인이 설정되지 않은 대상은 서빙 여부를 알 수 없으므로 마지막 배포 기록으로 멱등성을 보장한다
        rec = self.state.target(t.name)
        if not t.verify and not force and rec.get("status") == "ok" and rec.get("serial") == f"{new:x}":
            return TargetResult(t.name, "skipped", "이미 배포 기록이 있음(TLS 확인 미설정 대상)", before)
        if dry_run:
            return TargetResult(t.name, "dry_run", "실행하지 않음(계획만)", before)
        ts = self.clock().strftime("%Y%m%d%H%M%S")
        installed: List[remote.Installed] = []
        transport: Optional[Transport] = None
        try:
            transport = self.transport_factory(t.transport)
            self._install_all(t, transport, ts, installed)
            self._check_and_reload(t, transport)
            self._verify_new(t)
        except (DeployFailure, remote.RemoteError, TransportError) as e:
            return self._fail(t, transport, installed, before, str(e))
        try:                                         # 백업 정리 실패는 배포 성공을 뒤집지 않는다
            for f in t.files:
                remote.prune_backups(transport, f.dest, self.cfg.options.keep_backups)
        except TransportError as e:
            log.warning("[%s] 오래된 백업 정리 실패(무시): %s", t.name, e)
        finally:
            transport.close()
        self.state.set_target(t.name, serial=f"{new:x}", deployed_at=self.clock().isoformat(), status="ok", error="",
                              backups=[{"dest": i.dest, "backup": i.backup} for i in installed])
        self.state.save()
        self.notifier.resolve(t.name)
        return TargetResult(t.name, "deployed", "배포·확인 완료" if t.verify else "배포 완료(TLS 확인은 설정 안 됨)", before)

    def _install_all(self, t, transport, ts, installed):
        for f in t.files:
            data = self._content(f)
            installed.append(remote.install_file(transport, f.dest, data, f.mode, ts))
            del data     # 키 내용을 오래 들고 있지 않는다

    def _check_and_reload(self, t, transport):
        to = self.cfg.options.command_timeout
        if t.check_cmd:
            r = transport.run(t.check_cmd, timeout=to)
            if not r.ok:
                raise DeployFailure("설정 점검 실패: " + ((r.err or r.out).strip().splitlines() or ["원인 불명"])[-1][:200])
        if t.reload_cmd:
            r = transport.run(t.reload_cmd, timeout=to)
            if not r.ok:
                raise DeployFailure("재로드 실패: " + ((r.err or r.out).strip().splitlines() or ["원인 불명"])[-1][:200])

    def _verify_new(self, t):
        if not t.verify:
            return
        o = self.cfg.options
        last = "응답 없음"
        for i in range(o.verify_attempts):
            try:
                got = self.verifier(t.verify.host, t.verify.port, t.verify.sni)
                if got == self.bundle.serial:
                    return
                last = f"다른 인증서가 서빙됨(일련번호 {got:x})"
            except VerifyError as e:
                last = str(e)
            if i < o.verify_attempts - 1:
                self.sleep(o.verify_interval)
        raise DeployFailure(f"재로드 후 새 인증서가 확인되지 않음: {last}")

    def _fail(self, t, transport, installed, before, reason) -> TargetResult:
        """롤백 후 상태·알림 기록. 롤백까지 실패하면 수동 조치 필요를 명시한다."""
        rolled, problem = False, ""
        if transport is not None:
            try:
                for inst in reversed(installed):
                    remote.rollback_file(transport, inst)
                if installed and t.reload_cmd:
                    transport.run(t.reload_cmd, timeout=self.cfg.options.command_timeout)   # 이전 인증서로 재로드(best-effort)
                rolled = True
            except (remote.RemoteError, TransportError) as e:
                problem = f" / 롤백도 실패({e}) — 수동 조치 필요"
            finally:
                transport.close()
        status = "rolled_back" if (rolled and installed) else "failed"
        msg = f"{reason}" + (" → 이전 파일로 롤백함" if status == "rolled_back" else "") + problem
        self.state.set_target(t.name, status=status, error=msg, failed_at=self.clock().isoformat())
        self.state.save()
        self.notifier.fire(t.name, f"인증서 배포 실패: {t.name}", msg, "critical")
        log.error("[%s] %s", t.name, msg)
        return TargetResult(t.name, status, msg, before)

    # ---------------------------------------------------------------- 수동 롤백
    def rollback(self, name: str) -> TargetResult:
        t = next((x for x in self.cfg.targets if x.name == name), None)
        if t is None:
            raise KeyError(name)
        backups = self.state.target(name).get("backups") or []
        if not backups:
            return TargetResult(name, "failed", "되돌릴 백업 기록이 없습니다")
        transport = self.transport_factory(t.transport)
        try:
            for b in reversed(backups):
                remote.rollback_file(transport, remote.Installed(b["dest"], b["backup"]))
            if t.reload_cmd:
                transport.run(t.reload_cmd, timeout=self.cfg.options.command_timeout)
        except (remote.RemoteError, TransportError) as e:
            return TargetResult(name, "failed", f"롤백 실패: {e}")
        finally:
            transport.close()
        self.state.set_target(name, status="rolled_back", error="수동 롤백", backups=[])
        self.state.save()
        return TargetResult(name, "rolled_back", "이전 파일로 되돌리고 재로드함")
