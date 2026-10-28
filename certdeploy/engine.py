"""배포 엔진: 대상별로 [현재 상태 확인 → 백업·교체 → 점검 → 재로드 → TLS 확인] 을 수행하고 실패하면 롤백한다.

안전 원칙
- 한 번에 한 대(순차). canary 대상이 먼저이며 실패하면 이후 대상으로 넘어가지 않는다(continue_on_error 로 변경 가능).
- 이미 새 인증서를 서빙 중이면 건드리지 않는다(멱등) — 재시도·타이머 반복 실행이 안전하다.
- 개인키·키스토어 내용은 로그·예외 메시지에 남기지 않는다.
"""
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional

from certpilot_core import trace

from . import remote
from .bundle import Bundle, BundleError
from .config import Config, Target
from .handlers import KEY_KINDS, FileSpec
from .notify import NullNotifier
from .state import State
from .transport import LocalTransport, SSHTransport, Transport, TransportError
from .verify import VerifyError, http_health, tls_serial

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
                 health_checker: Callable[..., None] = http_health,
                 hook_runner: Optional[Callable] = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 environ=os.environ):
        self.cfg, self.bundle, self.state = cfg, bundle, state
        self.transport_factory = transport_factory or (lambda tr: make_transport(tr, cfg.options.command_timeout))
        self.verifier, self.notifier = verifier, notifier or NullNotifier()
        self.health_checker = health_checker
        self.hook_runner = hook_runner or self._run_hook
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
                if f.content in ("pkcs12", "jks"):
                    try:
                        ok = bool(self._password(f))
                    except DeployFailure as e:
                        problems.append(f"{t.name}: {e}")
                        continue
                    if not ok:
                        what = f"환경변수 {f.password_env}" if f.password_env else f"파일 {f.password_file}"
                        problems.append(f"{t.name}: 키스토어 비밀번호({what})를 얻을 수 없습니다")
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

    def _password(self, f: FileSpec) -> Optional[str]:
        if f.password_env and self.environ.get(f.password_env):
            return self.environ[f.password_env]
        if f.password_file:
            try:
                st = os.stat(f.password_file)
                if st.st_mode & 0o077:
                    raise DeployFailure(f"비밀번호 파일 권한이 너무 넓습니다(600 필요): {f.password_file}")
                with open(f.password_file, encoding="utf-8") as fh:
                    return fh.read().strip()
            except OSError:
                return None
        return None

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
        pw = self._password(f)
        if not pw:
            raise DeployFailure(f"키스토어 비밀번호를 얻을 수 없습니다({f.password_env or f.password_file})")
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
            with trace.span("deploy", "target", target=t.name, serial=f"{self.bundle.serial:x}", force=force, dry_run=dry_run) as ctx:
                r = self._deploy_target(t, force, dry_run)
                ctx.update(status=r.status, message=r.message, served_before=f"{r.serial_before:x}" if r.serial_before else None)
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
            return self._tls(t)
        except VerifyError as e:
            log.info("[%s] 현재 서빙 인증서를 확인하지 못함: %s", t.name, e)
            return None

    def _tls(self, t: Target) -> int:
        v = t.verify
        if v.strict:
            return self.verifier(v.host, v.port, v.sni, strict=True, cafile=v.ca_file, lenient=v.lenient_x509)
        return self.verifier(v.host, v.port, v.sni)

    def _hook_env(self, t: Target, status: str = "") -> dict:
        """훅에는 최소 환경만 전달한다. 키스토어 비밀번호 등 certdeploy 의 비밀 환경변수가 새지 않도록
        PATH/LANG 과 CERTDEPLOY_* 만 주고, 필요한 변수는 대상의 hook_env 에 이름을 적어 명시적으로 허용한다."""
        env = {k: self.environ[k] for k in ("PATH", "LANG", "HOME") if k in self.environ}
        env.update({k: self.environ[k] for k in t.hook_env if k in self.environ})
        env.update({"CERTDEPLOY_TARGET": t.name, "CERTDEPLOY_SERIAL": f"{self.bundle.serial:x}",
                    "CERTDEPLOY_STATUS": status, "CERTDEPLOY_HOST": t.transport.get("host", "")})
        return env

    @staticmethod
    def _last(out) -> str:
        lines = (out or "").strip().splitlines()
        return lines[-1][:200] if lines else "원인 불명"

    @staticmethod
    def _run_hook(cmd: str, env: dict, timeout: int):
        p = subprocess.run(["sh", "-c", cmd], env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stderr or p.stdout)

    def _post_hook(self, t: Target, status: str) -> str:
        """post_cmd 실행. 실패해도 배포 결과는 바꾸지 않고 경고 문구만 돌려준다."""
        if not t.post_cmd:
            return ""
        try:
            rc, out = self.hook_runner(t.post_cmd, self._hook_env(t, status), self.cfg.options.command_timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            return f" (post_cmd 실행 오류: {type(e).__name__})"
        return "" if rc == 0 else f" (post_cmd 실패: {self._last(out)})"

    def _deploy_target(self, t: Target, force: bool, dry_run: bool) -> TargetResult:
        new = self.bundle.serial
        with trace.span("deploy", "served_serial", target=t.name) as ctx:
            before = self._served_serial(t)
            ctx["served"] = f"{before:x}" if before else None
        if before == new and not force:
            return TargetResult(t.name, "skipped", "이미 새 인증서를 서빙 중", before)
        # TLS 확인이 설정되지 않은 대상은 서빙 여부를 알 수 없으므로 마지막 배포 기록으로 멱등성을 보장한다
        rec = self.state.target(t.name)
        if not t.verify and not force and rec.get("status") == "ok" and rec.get("serial") == f"{new:x}":
            return TargetResult(t.name, "skipped", "이미 배포 기록이 있음(TLS 확인 미설정 대상)", before)
        if dry_run:
            return TargetResult(t.name, "dry_run", "실행하지 않음(계획만)", before)
        if t.pre_cmd:                                 # 예: 로드밸런서에서 이 서버 제외. 실패하면 아무것도 바꾸지 않는다
            trace.event("deploy", "pre_cmd", target=t.name, cmd=t.pre_cmd)
            try:
                rc, out = self.hook_runner(t.pre_cmd, self._hook_env(t, "pre"), self.cfg.options.command_timeout)
            except (OSError, subprocess.TimeoutExpired) as e:
                rc, out = 1, type(e).__name__
            if rc != 0:
                msg = f"pre_cmd 실패 — 변경 없이 중단: {self._last(out)}"
                self.state.set_target(t.name, status="failed", error=msg, failed_at=self.clock().isoformat())
                self.state.save()
                self.notifier.fire(t.name, f"인증서 배포 중단: {t.name}", msg, "warning")
                return TargetResult(t.name, "failed", msg, before)
        ts = self.clock().strftime("%Y%m%d%H%M%S")
        installed: List[remote.Installed] = []
        transport: Optional[Transport] = None
        try:
            with trace.span("deploy", "connect", target=t.name, kind=t.transport.get("kind", "local"), host=t.transport.get("host")):
                transport = self.transport_factory(t.transport)
            self._install_all(t, transport, ts, installed)
            self._check_and_reload(t, transport)
            self._verify_new(t)
            self._health_and_soak(t)
        except (DeployFailure, remote.RemoteError, TransportError) as e:
            r = self._fail(t, transport, installed, before, str(e))
            r.message += self._post_hook(t, r.status)
            return r
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
        msg = "배포·확인 완료" if t.verify else "배포 완료(TLS 확인은 설정 안 됨)"
        return TargetResult(t.name, "deployed", msg + self._post_hook(t, "deployed"), before)

    def _health_and_soak(self, t: Target) -> None:
        """HTTP 헬스체크 → (설정 시) 소크: 일정 시간 동안 새 인증서와 헬스가 유지되는지 반복 확인."""
        def once():
            if t.health:
                try:
                    self.health_checker(t.health.url, t.health.expect, t.health.timeout, t.health.insecure)
                except VerifyError as e:
                    raise DeployFailure(f"헬스체크 실패: {e}")
        once()
        if not t.soak_seconds:
            return
        rounds = max(1, t.soak_seconds // max(1, t.soak_interval))
        for _ in range(rounds):
            self.sleep(t.soak_interval)
            try:
                got = self._tls(t)
            except VerifyError as e:
                raise DeployFailure(f"소크 중 TLS 확인 실패: {e}")
            if got != self.bundle.serial:
                raise DeployFailure(f"소크 중 서빙 인증서가 바뀜(일련번호 {got:x})")
            once()

    def _install_all(self, t, transport, ts, installed):
        for f in t.files:
            data = self._content(f)
            with trace.span("deploy", "install_file", dest=f.dest, mode=f.mode, bytes=len(data)):
                installed.append(remote.install_file(transport, f.dest, data, f.mode, ts))
            del data     # 키 내용을 오래 들고 있지 않는다

    @staticmethod
    def _traced_run(transport, step, t, cmd, timeout):
        t0 = time.monotonic()
        try:
            r = transport.run(cmd, timeout=timeout)
        except Exception as e:
            trace.event("deploy", step, "error", target=t.name, cmd=cmd, error=type(e).__name__, message=str(e))
            raise
        trace.event("deploy", step, "info" if r.ok else "error", target=t.name, cmd=cmd, rc=r.rc,
                    ms=round((time.monotonic() - t0) * 1000), output=(r.err or r.out)[-300:])
        return r

    def _check_and_reload(self, t, transport):
        to = self.cfg.options.command_timeout
        if t.check_cmd:
            r = self._traced_run(transport, "check_cmd", t, t.check_cmd, to)
            if not r.ok:
                raise DeployFailure("설정 점검 실패: " + ((r.err or r.out).strip().splitlines() or ["원인 불명"])[-1][:200])
        if t.reload_cmd:
            r = self._traced_run(transport, "reload_cmd", t, t.reload_cmd, to)
            if not r.ok:
                raise DeployFailure("재로드 실패: " + ((r.err or r.out).strip().splitlines() or ["원인 불명"])[-1][:200])

    def _verify_new(self, t):
        if not t.verify:
            return
        o = self.cfg.options
        last = "응답 없음"
        for i in range(o.verify_attempts):
            try:
                got = self._tls(t)
                trace.event("deploy", "verify_attempt", target=t.name, attempt=i + 1, served=f"{got:x}", expected=f"{self.bundle.serial:x}", match=got == self.bundle.serial)
                if got == self.bundle.serial:
                    return
                last = f"다른 인증서가 서빙됨(일련번호 {got:x})"
            except VerifyError as e:
                last = str(e)
                trace.event("deploy", "verify_attempt", "warning", target=t.name, attempt=i + 1, error=last)
            if i < o.verify_attempts - 1:
                self.sleep(o.verify_interval)
        raise DeployFailure(f"재로드 후 새 인증서가 확인되지 않음: {last}")

    def _fail(self, t, transport, installed, before, reason) -> TargetResult:
        """롤백 후 상태·알림 기록. 롤백까지 실패하면 수동 조치 필요를 명시한다."""
        rolled, problem = False, ""
        trace.event("deploy", "failure", "error", target=t.name, reason=reason, installed=len(installed))
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
