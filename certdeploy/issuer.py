"""lego 호출(발급·갱신). ACME 자체는 lego 가 수행하고 여기서는 명령 구성과 결과 경로 계산만 한다.

주의: lego 바이너리를 이 저장소 개발 환경에서 직접 실행해 보지 못했다. 명령행 옵션과 산출 파일 이름 규칙은
설치한 버전의 `lego --help`, `lego dnshelp -c <provider>` 로 확인한다(스테이징 CA 로 먼저 시험).
"""
import os
import subprocess
from typing import Callable, Dict, List, Optional, Tuple

STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


class IssueError(Exception):
    pass


def lego_basename(domains: List[str]) -> str:
    """lego 는 산출 파일명을 첫 번째 도메인에서 만들며 '*' 는 '_' 로 바꾼다 (예: *.univ.example → _.univ.example)."""
    return domains[0].replace("*", "_")


def lego_output_paths(lego_cfg: dict) -> Tuple[str, str]:
    base = lego_basename(lego_cfg["domains"])
    d = os.path.join(lego_cfg.get("path", "/var/lib/lego"), "certificates")
    return os.path.join(d, base + ".crt"), os.path.join(d, base + ".key")


def parse_env_file(path: str) -> Dict[str, str]:
    """KEY=VALUE 형식(따옴표 허용, # 주석)만 읽는다. 셸로 source 하지 않는다."""
    env = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            env[k.strip()] = v
    return env


def build_command(lego_cfg: dict, action: str, staging: bool = False) -> List[str]:
    """action: 'run'(최초 발급) | 'renew'(갱신)"""
    for k in ("email", "dns_provider", "domains"):
        if not lego_cfg.get(k):
            raise IssueError(f"lego.{k} 가 필요합니다")
    cmd = [lego_cfg.get("binary", "lego"), "--accept-tos", "--email", lego_cfg["email"],
           "--dns", lego_cfg["dns_provider"], "--path", lego_cfg.get("path", "/var/lib/lego")]
    server = STAGING if staging else lego_cfg.get("server")
    if server:
        cmd += ["--server", server]
    for r in lego_cfg.get("dns_resolvers", []):
        cmd += ["--dns.resolvers", r]
    for d in lego_cfg["domains"]:
        cmd += ["--domains", d]
    if action == "run":
        cmd.append("run")
    elif action == "renew":
        cmd += ["renew", "--days", str(lego_cfg.get("renew_days", 30))]
    else:
        raise IssueError(f"알 수 없는 action: {action}")
    return cmd


class LegoIssuer:
    def __init__(self, lego_cfg: dict, runner: Optional[Callable] = None, timeout: int = 900):
        self.cfg = lego_cfg
        self.timeout = timeout
        self.runner = runner or self._run

    @staticmethod
    def _run(cmd, env, timeout):
        return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)

    def ensure(self, staging: bool = False, force_run: bool = False) -> str:
        """인증서가 없으면 run, 있으면 renew. 사용한 action 을 반환한다."""
        cert, _ = lego_output_paths(self.cfg)
        action = "run" if force_run or not os.path.exists(cert) else "renew"
        cmd = build_command(self.cfg, action, staging)
        env = dict(os.environ)
        if self.cfg.get("env_file"):
            try:
                env.update(parse_env_file(self.cfg["env_file"]))
            except OSError as e:
                raise IssueError(f"lego env_file 을 읽을 수 없습니다: {e}")
        try:
            r = self.runner(cmd, env, self.timeout)
        except FileNotFoundError:
            raise IssueError(f"lego 실행 파일을 찾을 수 없습니다: {cmd[0]}")
        except subprocess.TimeoutExpired:
            raise IssueError(f"lego 가 {self.timeout}초 안에 끝나지 않았습니다")
        if r.returncode != 0:
            tail = " | ".join((r.stderr or r.stdout or "").strip().splitlines()[-3:])
            raise IssueError(f"lego {action} 실패(종료 코드 {r.returncode}): {tail[:300]}")
        return action
