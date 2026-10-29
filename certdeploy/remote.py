"""원격 파일 교체: 백업 → 임시 파일에 쓰기(umask 077) → 권한 설정 → 원자적 mv → 롤백.

모든 동작은 Transport.run 위에서 이뤄지며, 파일 내용(개인키 포함)은 stdin 으로만 전달된다.
"""
import shlex
from dataclasses import dataclass
from typing import List

from .transport import Transport

q = shlex.quote


class RemoteError(Exception):
    pass


@dataclass
class Installed:
    dest: str
    backup: str        # 백업 파일 경로(기존 파일이 없었다면 빈 문자열)


def _must(res, what):
    if not res.ok:
        detail = (res.err or res.out).strip().splitlines()[-1:] or ["원인 불명"]
        raise RemoteError(f"{what} 실패: {detail[0][:200]}")
    return res


def ensure_dir_exists(t: Transport, dest: str) -> None:
    parent = dest.rsplit("/", 1)[0] or "/"
    _must(t.run(f"test -d {q(parent)}"), f"대상 디렉터리 확인({parent})")


def install_file(t: Transport, dest: str, data: bytes, mode: str, ts: str, restorecon: bool = True, owner: str = None) -> Installed:
    """dest 를 data 로 교체한다. 기존 파일은 `<dest>.bak-<ts>` 로 보존(소유자·권한 유지)."""
    if not mode.isdigit() or len(mode) not in (3, 4):
        raise RemoteError(f"파일 모드가 올바르지 않습니다: {mode}")
    tmp, bak = f"{dest}.new.{ts}", f"{dest}.bak-{ts}"
    ensure_dir_exists(t, dest)
    had = _must(t.run(f"if [ -e {q(dest)} ]; then cp -p {q(dest)} {q(bak)} && echo had; fi"), "기존 파일 백업").out.strip() == "had"
    try:
        _must(t.run(f"umask 077 && cat > {q(tmp)}", stdin=data), "임시 파일 쓰기")
        steps = [f"chmod {mode} {q(tmp)}",
                 f"{{ [ ! -e {q(dest)} ] || chown --reference={q(dest)} {q(tmp)} 2>/dev/null || true; }}"]
        if owner:        # 설정으로 지정한 소유자가 기존 파일의 소유자보다 우선(실패하면 배포 실패 — 서비스 계정이 못 읽는 키를 두지 않는다)
            steps.append(f"chown {q(owner)} {q(tmp)}")
        steps.append(f"mv -f {q(tmp)} {q(dest)}")
        if restorecon:
            steps.append(f"{{ command -v restorecon >/dev/null 2>&1 && restorecon -F {q(dest)} 2>/dev/null || true; }}")
        _must(t.run(" && ".join(steps)), "파일 교체")
    except RemoteError:
        t.run(f"rm -f {q(tmp)}" + (f"; rm -f {q(bak)}" if had else ""))   # 정리(best-effort)
        raise
    return Installed(dest, bak if had else "")


def rollback_file(t: Transport, inst: Installed) -> None:
    if inst.backup:
        _must(t.run(f"mv -f {q(inst.backup)} {q(inst.dest)}"), f"롤백({inst.dest})")
    else:
        _must(t.run(f"rm -f {q(inst.dest)}"), f"롤백(신규 파일 제거 {inst.dest})")


def prune_backups(t: Transport, dest: str, keep: int) -> None:
    """오래된 백업을 정리하고 최근 keep 개만 남긴다."""
    t.run(f"ls -1t -- {q(dest)}.bak-* 2>/dev/null | tail -n +{int(keep) + 1} | xargs -r rm -f --")


def installed_summary(items: List[Installed]) -> str:
    return ", ".join(i.dest for i in items)
