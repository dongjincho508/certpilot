"""원격(또는 로컬) 명령 실행 계층. 파일 교체는 모두 `run(cmd, stdin)` 위에서 수행한다.

개인키는 명령행 인자나 로그에 절대 나타나지 않고 stdin 으로만 전달된다.
"""
import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import Optional


class TransportError(Exception):
    """연결·인증·호스트 키 등 전송 계층 오류."""


@dataclass
class Result:
    rc: int
    out: str = ""
    err: str = ""

    @property
    def ok(self) -> bool:
        return self.rc == 0


class Transport:
    def run(self, cmd: str, stdin: Optional[bytes] = None, timeout: int = 60) -> Result:
        raise NotImplementedError

    def close(self) -> None:
        pass


def _wrap_sudo(cmd: str, sudo: bool) -> str:
    return f"sudo -n sh -c {shlex.quote(cmd)}" if sudo else cmd


class LocalTransport(Transport):
    """같은 호스트에 배포(발급 서버 자신이 웹서버인 경우, 또는 시험)."""

    def __init__(self, sudo: bool = False):
        self.sudo = sudo

    def run(self, cmd, stdin=None, timeout=60):
        try:
            p = subprocess.run(["sh", "-c", _wrap_sudo(cmd, self.sudo)], input=stdin, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return Result(124, "", f"timeout {timeout}s")
        return Result(p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"))


class SSHTransport(Transport):
    """paramiko 기반 SSH. 호스트 키는 known_hosts 로 엄격하게 검증한다(미등록·불일치 시 거부)."""

    def __init__(self, host: str, user: str, port: int = 22, key_file: Optional[str] = None,
                 known_hosts: Optional[str] = None, sudo: bool = False, timeout: int = 15, pkey=None):
        import paramiko
        self._pm = paramiko
        self.sudo = sudo
        self.client = paramiko.SSHClient()
        kh = known_hosts or os.path.expanduser("~/.ssh/known_hosts")
        try:
            self.client.load_host_keys(kh)
        except OSError:
            raise TransportError(f"known_hosts 를 읽을 수 없습니다: {kh}")
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            self.client.connect(host, port=port, username=user, key_filename=key_file, pkey=pkey,
                                allow_agent=key_file is None and pkey is None, look_for_keys=False,
                                timeout=timeout, auth_timeout=timeout, banner_timeout=timeout)
        except paramiko.BadHostKeyException:
            raise TransportError(f"{host}: 호스트 키가 known_hosts 와 다릅니다(중단)")
        except paramiko.SSHException as e:
            raise TransportError(f"{host}: SSH 접속 실패({type(e).__name__}: {str(e)[:120]})")
        except OSError as e:
            raise TransportError(f"{host}: 연결 실패({str(e)[:120]})")

    def run(self, cmd, stdin=None, timeout=60):
        try:
            si, so, se = self.client.exec_command(_wrap_sudo(cmd, self.sudo), timeout=timeout)  # nosec B601 — 명령은 운영자 설정
            if stdin is not None:
                si.write(stdin)
            si.channel.shutdown_write()
            out, err = so.read(), se.read()
            rc = so.channel.recv_exit_status()
        except (self._pm.SSHException, OSError) as e:
            raise TransportError(f"명령 실행 실패({type(e).__name__})")
        return Result(rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))

    def close(self):
        self.client.close()
