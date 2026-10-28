"""lego 호출(발급·갱신). ACME 자체는 lego 가 수행하고 여기서는 명령 구성과 결과 경로 계산만 한다.

주의: lego 바이너리를 이 저장소 개발 환경에서 직접 실행해 보지 못했다. 명령행 옵션과 산출 파일 이름 규칙은
설치한 버전의 `lego --help`, `lego dnshelp -c <provider>` 로 확인한다(스테이징 CA 로 먼저 시험).
"""
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple

STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


KEY_TYPES = ("rsa2048", "rsa3072", "rsa4096", "rsa8192", "ec256", "ec384")


class IssueError(Exception):
    pass


class BackoffActive(IssueError):
    """직전 발급 실패 후 대기 시간이 지나지 않아 lego 호출을 건너뜀(속도 제한 보호)."""

    def __init__(self, retry_after: datetime, failures: int):
        super().__init__(f"직전 발급 실패(연속 {failures}회) 후 대기 중 — {retry_after:%Y-%m-%d %H:%M UTC} 이후 재시도")
        self.retry_after, self.failures = retry_after, failures


class IssueBackoff:
    """발급 실패 횟수·시각 기록. Let's Encrypt 의 실패 속도 제한(계정/호스트명별 시간당 실패 한도)을 보호한다."""

    def __init__(self, state_dir: str, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.path = os.path.join(state_dir, "lego.json")
        self.clock = clock
        self.data = {"failures": 0, "last_failure": None}
        try:
            with open(self.path, encoding="utf-8") as f:
                self.data.update(json.load(f))
        except (OSError, ValueError):
            pass

    @property
    def failures(self) -> int:
        return int(self.data.get("failures", 0))

    def _save(self):
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        os.replace(tmp, self.path)

    def check(self, minutes: int) -> None:
        last = self.data.get("last_failure")
        if not last or not self.failures:
            return
        retry_after = datetime.fromisoformat(last) + timedelta(minutes=minutes)
        if self.clock() < retry_after:
            raise BackoffActive(retry_after, self.failures)

    def record_failure(self):
        self.data = {"failures": self.failures + 1, "last_failure": self.clock().isoformat()}
        self._save()

    def record_success(self):
        if self.failures:
            self.data = {"failures": 0, "last_failure": None}
            self._save()


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
    """action: 'run'(최초 발급) | 'renew'(갱신). 옵션 이름은 lego 버전에 따라 다를 수 있으니 설치본으로 확인한다."""
    for k in ("email", "domains"):
        if not lego_cfg.get(k):
            raise IssueError(f"lego.{k} 가 필요합니다")
    webroot = lego_cfg.get("http_webroot")
    if not webroot and not lego_cfg.get("dns_provider"):
        raise IssueError("lego.dns_provider 또는 lego.http_webroot 가 필요합니다")
    if any(d.startswith("*.") for d in lego_cfg["domains"]) and webroot:
        raise IssueError("와일드카드 도메인은 DNS-01 만 가능합니다(http_webroot 와 함께 쓸 수 없음)")
    cmd = [lego_cfg.get("binary", "lego"), "--accept-tos", "--email", lego_cfg["email"],
           "--path", lego_cfg.get("path", "/var/lib/lego")]
    cmd += ["--http", "--http.webroot", webroot] if webroot else ["--dns", lego_cfg["dns_provider"]]
    if lego_cfg.get("key_type"):
        if lego_cfg["key_type"] not in KEY_TYPES:
            raise IssueError(f"lego.key_type 은 {', '.join(KEY_TYPES)} 중 하나여야 합니다")
        cmd += ["--key-type", lego_cfg["key_type"]]
    if lego_cfg.get("dns_propagation_wait"):
        cmd += ["--dns.propagation-wait", str(lego_cfg["dns_propagation_wait"])]
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

    def ensure(self, staging: bool = False, force_run: bool = False, backoff: Optional[IssueBackoff] = None,
               backoff_minutes: int = 60, ignore_backoff: bool = False) -> str:
        """인증서가 없으면 run, 있으면 renew. 사용한 action 을 반환한다.
        backoff 를 주면 직전 실패 후 대기 시간 안에는 lego 를 호출하지 않고(BackoffActive), 결과를 기록한다."""
        if backoff and not ignore_backoff:
            backoff.check(backoff_minutes)
        try:
            action = self._ensure(staging, force_run)
        except IssueError:
            if backoff:
                backoff.record_failure()
            raise
        if backoff:
            backoff.record_success()
        return action

    def _ensure(self, staging: bool, force_run: bool) -> str:
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
