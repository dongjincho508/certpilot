"""배포 전 사전 점검: 실제 배포를 하지 않고 '지금 배포하면 성공할 조건이 갖춰졌는가'를 확인한다.

접속, 대상 디렉터리 존재·쓰기 권한, 여유 공간, 점검/재로드 명령의 존재(및 sudo 허용), 현재 서빙 상태,
헬스체크, 로컬 도구(keytool 등)를 읽기 전용 명령으로만 확인한다.
"""
import re
import shlex
import shutil
from dataclasses import dataclass
from typing import List, Optional

from .engine import Deployer
from .transport import TransportError
from .verify import VerifyError

MIN_FREE_KB = 1024
COMPLEX = re.compile(r"\|\||&&|;|\bif\b|\$\(|`|\|")


@dataclass
class Check:
    target: str
    name: str
    ok: bool
    detail: str = ""


def _first_command(cmd: str) -> Optional[str]:
    """명령의 실행 파일 이름. 복합 명령은 None(점검 생략)."""
    if not cmd or COMPLEX.search(cmd):
        return None
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return None
    while parts and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", parts[0]):
        parts.pop(0)
    return parts[0] if parts else None


def _check_command(t, label: str, cmd: Optional[str], out: List[Check], tr) -> None:
    if not cmd:
        return
    first = _first_command(cmd)
    if first is None:
        out.append(Check(t.name, f"{label} 명령", True, "복합 명령 — 존재 점검 생략"))
        return
    if first == "sudo":
        rest = re.sub(r"^sudo\s+(-n\s+)?", "", cmd.strip())
        r = tr.run(f"sudo -n -l {rest} >/dev/null 2>&1")      # -l: 실행하지 않고 허용 여부만 확인
        out.append(Check(t.name, f"{label} sudo 허용", r.ok,
                         "허용됨" if r.ok else "sudoers 에서 허용되지 않았거나 비밀번호가 필요합니다"))
        return
    r = tr.run(f"command -v {shlex.quote(first)} >/dev/null 2>&1")
    out.append(Check(t.name, f"{label} 명령({first})", r.ok, "있음" if r.ok else "원격 서버에서 찾을 수 없습니다"))


def _check_manual(d, t, out: List[Check]) -> None:
    import os
    m = t.manual
    folder = d._handoff_dir(t)
    parent = os.path.dirname(folder.rstrip("/"))
    while parent and not os.path.isdir(parent):
        parent = os.path.dirname(parent)
    out.append(Check(t.name, "교체용 파일 위치", bool(parent) and os.access(parent, os.W_OK), folder))
    if "pfx" in m["formats"]:
        out.append(Check(t.name, "PFX 비밀번호", bool(d.environ.get(m["pfx_password_env"] or "")), f"환경변수 {m['pfx_password_env']}"))
    if not t.verify:
        out.append(Check(t.name, "완료 확인", True, "verify 가 없어 교체 후 `confirm` 으로 완료를 기록해야 합니다"))
    else:
        try:
            got = d._tls(t)
            out.append(Check(t.name, "현재 TLS", True, f"서빙 중 일련번호 {got:x}" + (" (이미 최신)" if got == d.bundle.serial else " (교체 필요)")))
        except VerifyError as e:
            out.append(Check(t.name, "현재 TLS", False, str(e)))


def _check_api(d, t, out: List[Check]) -> None:
    """API 대상: 관리 주소의 TCP/TLS 도달성만 확인한다(로그인·변경 요청은 보내지 않는다)."""
    import socket
    import ssl
    import urllib.parse
    base = t.api.get("base_url") or next((s["url"] for s in t.api["steps"] if str(s["url"]).startswith("http")), "")
    u = urllib.parse.urlparse(base)
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        with socket.create_connection((u.hostname, port), timeout=8) as s:
            if u.scheme == "https":
                ctx = ssl.create_default_context(cafile=t.api.get("ca_file")) if t.api.get("verify_tls") is not False else ssl._create_unverified_context()  # nosec B323
                with ctx.wrap_socket(s, server_hostname=u.hostname):
                    pass
        out.append(Check(t.name, "API 관리 주소", True, f"{u.hostname}:{port} 도달"))
    except (OSError, ssl.SSLError) as e:
        out.append(Check(t.name, "API 관리 주소", False, f"{u.hostname}:{port} {type(e).__name__}: {e}"))
    if not t.api.get("rollback_steps"):
        out.append(Check(t.name, "롤백 설정", False, "rollback_steps 가 없어 실패 시 자동 롤백이 되지 않습니다(권장: 설정)"))
    if t.verify:
        try:
            got = d._tls(t)
            out.append(Check(t.name, "현재 TLS", True, f"서빙 중 일련번호 {got:x}" + (" (이미 최신)" if got == d.bundle.serial else "")))
        except VerifyError as e:
            out.append(Check(t.name, "현재 TLS", False, str(e)))


def run_preflight(d: Deployer, only=None) -> List[Check]:
    out: List[Check] = []
    for problem in d.validate_targets():
        name = problem.split(":", 1)[0]
        out.append(Check(name, "설정·인증서", False, problem.split(":", 1)[-1].strip()))
    for t in d.ordered(only):
        if any(f.content == "jks" for f in t.files):
            out.append(Check(t.name, "keytool(JKS 변환)", shutil.which("keytool") is not None,
                             "있음" if shutil.which("keytool") else "발급 서버에 JDK(keytool)가 없습니다"))
        for label, cmd in (("pre_cmd", t.pre_cmd), ("post_cmd", t.post_cmd)):
            first = _first_command(cmd) if cmd else None
            if first:
                out.append(Check(t.name, f"{label}({first})", shutil.which(first) is not None,
                                 "있음" if shutil.which(first) else "certdeploy 서버에서 찾을 수 없습니다"))
        if t.manual:
            _check_manual(d, t, out)
            continue
        if t.api:
            _check_api(d, t, out)
            continue
        try:
            tr = d.transport_factory(t.transport)
        except TransportError as e:
            out.append(Check(t.name, "접속", False, str(e)))
            continue
        try:
            out.append(Check(t.name, "접속", True, "성공"))
            seen = set()
            for f in t.files:
                parent = f.dest.rsplit("/", 1)[0] or "/"
                if parent not in seen:
                    seen.add(parent)
                    r = tr.run(f"test -d {shlex.quote(parent)} && test -w {shlex.quote(parent)}")
                    out.append(Check(t.name, f"디렉터리 쓰기({parent})", r.ok,
                                     "가능" if r.ok else "디렉터리가 없거나 쓰기 권한이 없습니다"))
                    df = tr.run(f"df -Pk {shlex.quote(parent)} 2>/dev/null | awk 'NR==2 {{print $4}}'")
                    if df.ok and df.out.strip().isdigit():
                        free = int(df.out.strip())
                        out.append(Check(t.name, f"여유 공간({parent})", free >= MIN_FREE_KB, f"{free} KB"))
            _check_command(t, "점검", t.check_cmd, out, tr)
            _check_command(t, "재로드", t.reload_cmd, out, tr)
        except TransportError as e:
            out.append(Check(t.name, "원격 점검", False, str(e)))
        finally:
            tr.close()
        if t.verify:
            try:
                got = d._tls(t)
                out.append(Check(t.name, "현재 TLS", True, f"서빙 중 일련번호 {got:x}" + (" (이미 최신)" if got == d.bundle.serial else "")))
            except VerifyError as e:
                out.append(Check(t.name, "현재 TLS", False, str(e)))
        if t.health:
            try:
                d.health_checker(t.health.url, t.health.expect, t.health.timeout, t.health.insecure)
                out.append(Check(t.name, "헬스체크", True, "정상"))
            except VerifyError as e:
                out.append(Check(t.name, "헬스체크", False, str(e)))
    return out
