"""원격 실행 계층 (PRD §3.1.2, §3.1.3, S-2, S-3, B-5)

- CommandPolicy: 고정 읽기 전용 명령 세트 + 경로 화이트리스트 강제
- RemoteExecutor: 실행 인터페이스. 서비스 코드는 이것에만 의존한다.
- SandboxExecutor: 로컬 디렉터리를 원격 파일시스템처럼 쓰는 테스트/개발용 구현
- ParamikoExecutor: 실제 SSH (ssh-agent 인증, TOFU, 패스워드 미지원)
"""
import hashlib
import os
import posixpath
import re
import shlex
import socket
from enum import Enum
from typing import Callable, Dict, List, Optional, Sequence, Tuple


class FailureCause(str, Enum):
    DNS = "DNS"
    TIMEOUT = "TIMEOUT"
    AUTH = "AUTH"
    HOSTKEY = "HOSTKEY"
    PERMISSION = "PERMISSION"
    COMMAND = "COMMAND"


# 화면에 노출하는 것은 분류와 조치 방향뿐 (S-8)
CAUSE_INFO = {
    FailureCause.DNS: ("네임 확인(DNS) 실패", "네트워크·DNS 설정을 확인하세요."),
    FailureCause.TIMEOUT: ("연결 시간 초과", "방화벽·라우팅을 확인하세요."),
    FailureCause.AUTH: ("인증 실패", "조회 계정과 키 발급 상태를 확인하세요."),
    FailureCause.HOSTKEY: ("호스트 키 불일치", "접근 정책을 확인하세요. 보안 이벤트일 수 있습니다."),
    FailureCause.PERMISSION: ("접속 권한 거부", "조회 계정에 파일 읽기 권한을 부여하세요."),
    FailureCause.COMMAND: ("원격 명령 실행 실패", "원격 환경 상태를 확인하세요."),
}
RETRYABLE = {FailureCause.DNS, FailureCause.TIMEOUT}


class RemoteError(Exception):
    """분류된 원격 오류. detail(원문)은 감사 로그 전용이며 화면에 노출하지 않는다."""

    def __init__(self, cause: FailureCause, detail: str = ""):
        super().__init__(f"{cause.value}: {detail}")
        self.cause = cause
        self.detail = detail


class PolicyViolation(Exception):
    pass


# ---------------------------------------------------------------- 명령 정책
_META = re.compile(r"[;&|`$<>()\\\n\r\"'*?{}\[\]~!#]")
_NUM = re.compile(r"^\d+$")

# 명령별 허용 플래그. 값이 필요한 플래그는 VALUE_FLAGS 에 따로 둔다.
ALLOWED_FLAGS: Dict[str, set] = {
    "cat": set(),
    "head": {"-n", "-c"},
    "tail": {"-n", "-c"},
    "grep": {"-n", "-i", "-h", "-H", "-o", "-E", "-e"},
    "ls": {"-1", "-l", "-a", "-p", "-L"},
    "find": {"-maxdepth", "-type", "-name", "-iname", "-L"},
    "sha256sum": set(),
}
VALUE_FLAGS = {
    "head": {"-n", "-c"}, "tail": {"-n", "-c"}, "grep": {"-e"},
    "find": {"-maxdepth", "-type", "-name", "-iname"},
}
OPENSSL_X509_FLAGS = {"-noout", "-dates", "-subject", "-issuer", "-serial"}


def _normalize(path: str) -> str:
    return posixpath.normpath(path)


_PATH_BAD = re.compile(r"[;&|`$<>()\\\s\"'*?{}\[\]~!#]")


def is_key_path(path: str) -> bool:
    """개인키로 보이는 경로(.key, privkey*, private/ 디렉터리) — 어떤 경우에도 열지 않는다 (S-3)"""
    parts = [x.lower() for x in path.split("/") if x]
    base = parts[-1] if parts else ""
    return "private" in parts or base.startswith("privkey") or base.endswith(".key")


def is_safe_path(path: str) -> bool:
    """등록·제안 가능한 경로인지(문법 검증): 절대 경로, '..' 없음, 셸 메타문자·공백 없음, 개인키 경로 아님"""
    return isinstance(path, str) and path.startswith("/") and ".." not in path.split("/") \
        and not _PATH_BAD.search(path) and not is_key_path(path)


def path_allowed(path: str, whitelist: Sequence[str]) -> bool:
    """절대 경로이며 '..' 이탈이 없고 화이트리스트 디렉터리/파일 하위일 때만 허용 (S-3)"""
    if not path.startswith("/") or ".." in path.split("/"):
        return False
    norm = _normalize(path)
    return any(norm == w or norm.startswith(w.rstrip("/") + "/") for w in map(_normalize, whitelist))


class CommandPolicy:
    def __init__(self, whitelist: Sequence[str]):
        self.whitelist = list(whitelist)

    def validate(self, argv: Sequence[str]) -> None:
        if not argv:
            raise PolicyViolation("빈 명령")
        cmd, args = argv[0], list(argv[1:])
        for a in argv:
            if _META.search(a):
                raise PolicyViolation("셸 메타문자 금지")
        if cmd == "openssl":
            self._validate_openssl(args)
            return
        if cmd not in ALLOWED_FLAGS:
            raise PolicyViolation(f"허용되지 않은 명령: {cmd}")
        allowed = ALLOWED_FLAGS[cmd]
        i, positional = 0, 0
        while i < len(args):
            a = args[i]
            if a.startswith("-"):
                if a not in allowed:
                    raise PolicyViolation(f"허용되지 않은 옵션: {cmd} {a}")
                if a in VALUE_FLAGS.get(cmd, ()):
                    i += 1
                    if i >= len(args):
                        raise PolicyViolation("옵션 값 누락")
                    val = args[i]
                    if cmd != "grep" and a in ("-n", "-c", "-maxdepth") and not _NUM.match(val):
                        raise PolicyViolation("숫자 값 필요")
                    if a == "-type" and val not in ("f", "d", "l"):
                        raise PolicyViolation("find -type 값 제한")
            elif a.startswith("/"):
                if not path_allowed(a, self.whitelist):
                    raise PolicyViolation("화이트리스트 밖 경로")
                if is_key_path(a):
                    raise PolicyViolation("개인키 경로 접근 금지")
            elif cmd == "grep" and positional == 0:
                positional += 1  # 패턴
            else:
                raise PolicyViolation(f"허용되지 않은 인자: {a}")
            i += 1

    def _validate_openssl(self, args: List[str]) -> None:
        if not args or args[0] != "x509":
            raise PolicyViolation("openssl x509 만 허용")
        for a in args[1:]:
            if a in OPENSSL_X509_FLAGS:
                continue
            if a.startswith("/") and path_allowed(a, self.whitelist) and not is_key_path(a):
                continue
            raise PolicyViolation(f"openssl 인자 거부: {a}")


# ---------------------------------------------------------------- 인터페이스
class RemoteExecutor:
    """원격 읽기 전용 명령 실행기. run() 은 (rc, stdout, stderr) 를 반환하고,
    연결·인증 계열 실패는 RemoteError 로 올린다."""

    server_version: str = ""

    def run(self, argv: Sequence[str], timeout: int = 30) -> Tuple[int, str, str]:
        raise NotImplementedError

    def close(self) -> None:
        pass


class PolicyExecutor(RemoteExecutor):
    """어떤 실행기든 정책 검증을 거치게 하는 래퍼"""

    def __init__(self, inner: RemoteExecutor, whitelist: Sequence[str]):
        self.inner = inner
        self.policy = CommandPolicy(whitelist)
        self.server_version = inner.server_version

    def run(self, argv, timeout=30):
        self.policy.validate(argv)
        return self.inner.run(argv, timeout)

    def close(self):
        self.inner.close()


# ---------------------------------------------------------------- 테스트/개발용
class SandboxExecutor(RemoteExecutor):
    """root 디렉터리를 원격 '/' 로 간주하는 실행기. 네트워크 없이 스캐너를 검증한다."""

    def __init__(self, root: str, denied: Sequence[str] = (), server_version: str = "OpenSSH_9.6"):
        self.root = os.path.abspath(root)
        self.denied = set(denied)
        self.server_version = server_version
        self.history: List[Tuple[str, ...]] = []

    def _real(self, path: str) -> str:
        return os.path.join(self.root, _normalize(path).lstrip("/"))

    def run(self, argv, timeout=30):
        self.history.append(tuple(argv))
        cmd, args = argv[0], list(argv[1:])
        paths = [a for a in args if a.startswith("/")]
        for p in paths:
            if p in self.denied:
                return 1, "", f"{cmd}: {p}: Permission denied"
        if cmd == "cat":
            return self._cat(paths[0])
        if cmd == "head":
            rc, out, err = self._cat(paths[0])
            if "-c" in args and rc == 0:
                out = out[: int(args[args.index("-c") + 1])]
            return rc, out, err
        if cmd == "sha256sum":
            rc, out, err = self._cat(paths[0], binary=True)
            return (rc, f"{hashlib.sha256(out).hexdigest()}  {paths[0]}\n", err) if rc == 0 else (rc, "", err)
        if cmd == "ls":
            return self._ls(args, paths[0])
        return 127, "", f"{cmd}: not supported by sandbox"

    def _cat(self, path, binary=False):
        real = self._real(path)
        if not os.path.exists(real):
            return 1, "" if not binary else b"", f"cat: {path}: No such file or directory"
        if os.path.isdir(real):
            return 1, "" if not binary else b"", f"cat: {path}: Is a directory"
        data = open(real, "rb").read()
        return 0, data if binary else data.decode("utf-8", errors="replace"), ""

    def _ls(self, args, path):
        real = self._real(path)
        if not os.path.lexists(real):
            return 2, "", f"ls: cannot access '{path}': No such file or directory"
        if "-l" in args:
            if os.path.islink(real):
                target = os.readlink(real)
                if not target.startswith("/") and False:
                    pass
                return 0, f"lrwxrwxrwx 1 root root 0 Jan 1 00:00 {path} -> {target}\n", ""
            kind = "d" if os.path.isdir(real) else "-"
            return 0, f"{kind}rw-r--r-- 1 root root 0 Jan 1 00:00 {path}\n", ""
        if os.path.isdir(real):
            names = sorted(os.listdir(real))
            if "-p" in args:
                names = [n + "/" if os.path.isdir(os.path.join(real, n)) else n for n in names]
            return 0, "\n".join(names) + ("\n" if names else ""), ""
        return 0, path + "\n", ""


# ---------------------------------------------------------------- 실제 SSH
def parse_openssh_version(banner: str) -> Optional[Tuple[int, int]]:
    m = re.search(r"OpenSSH_(\d+)\.(\d+)", banner or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


class HostKeyStore:
    """TOFU 저장소 인터페이스: get(host_id) -> 지문 또는 None / put(host_id, fp)"""

    def get(self, host_id: str) -> Optional[str]:
        raise NotImplementedError

    def put(self, host_id: str, fingerprint: str) -> None:
        raise NotImplementedError


class ParamikoExecutor(RemoteExecutor):
    """paramiko 기반. 인증은 ssh-agent(또는 테스트용 pkey)만 사용하고 패스워드는 받지 않는다."""

    def __init__(self, host: str, port: int, username: str, hostkeys: HostKeyStore,
                 pkey=None, connect_timeout: int = 10):
        import paramiko  # 지연 임포트
        self._paramiko = paramiko
        self.host, self.port, self.username = host, port, username
        self.hostkeys = hostkeys
        self.pkey = pkey
        self.connect_timeout = connect_timeout
        self.client = None

    def connect(self) -> "ParamikoExecutor":
        pm = self._paramiko
        store, host_id = self.hostkeys, f"{self.host}:{self.port}"

        class _Tofu(pm.MissingHostKeyPolicy):
            def missing_host_key(self_, client, hostname, key):
                fp = hashlib.sha256(key.asbytes()).hexdigest()
                known = store.get(host_id)
                if known is None:
                    store.put(host_id, fp)  # 최초 접속은 신뢰 (TOFU)
                elif known != fp:
                    raise RemoteError(FailureCause.HOSTKEY, f"host key changed for {host_id}")

        client = pm.SSHClient()
        client.set_missing_host_key_policy(_Tofu())
        try:
            client.connect(
                self.host, port=self.port, username=self.username, pkey=self.pkey,
                allow_agent=self.pkey is None, look_for_keys=False,
                timeout=self.connect_timeout, auth_timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout)
        except RemoteError:
            client.close()
            raise
        except socket.gaierror as e:
            raise RemoteError(FailureCause.DNS, str(e))
        except (socket.timeout, TimeoutError, ConnectionError, pm.ssh_exception.NoValidConnectionsError) as e:
            raise RemoteError(FailureCause.TIMEOUT, str(e))
        except pm.AuthenticationException as e:
            raise RemoteError(FailureCause.AUTH, str(e))
        except pm.SSHException as e:
            raise RemoteError(FailureCause.COMMAND, str(e))
        except OSError as e:
            raise RemoteError(FailureCause.TIMEOUT, str(e))
        self.client = client
        transport = client.get_transport()
        self.server_version = getattr(transport, "remote_version", "") if transport else ""
        return self

    def run(self, argv, timeout=30):
        if self.client is None:
            raise RemoteError(FailureCause.COMMAND, "not connected")
        cmd = " ".join(shlex.quote(a) for a in argv)
        try:
            _, out, err = self.client.exec_command(cmd, timeout=timeout)  # nosec B601 — 화이트리스트 정책·shlex.quote 통과분만
            rc = out.channel.recv_exit_status()
            return rc, out.read().decode("utf-8", "replace"), err.read().decode("utf-8", "replace")
        except socket.timeout as e:
            raise RemoteError(FailureCause.TIMEOUT, str(e))
        except self._paramiko.SSHException as e:
            raise RemoteError(FailureCause.COMMAND, str(e))

    def close(self):
        if self.client:
            self.client.close()
            self.client = None


ExecutorFactory = Callable[[dict], RemoteExecutor]
