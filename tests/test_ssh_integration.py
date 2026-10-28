"""프로세스 내 paramiko SSH 서버로 ParamikoExecutor 의 TOFU·인증·오류 분류를 실제 검증한다."""
import socket
import threading
import time

import paramiko
import pytest

from certpilot_core.remote import FailureCause, ParamikoExecutor, RemoteError
from certpilot_core.store import Store

pytestmark = pytest.mark.integration


class _Server(paramiko.ServerInterface):
    def __init__(self, authorized_key, outputs):
        self.authorized_key, self.outputs = authorized_key, outputs

    def check_auth_publickey(self, username, key):
        ok = key == self.authorized_key and username == "certscan"
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED  # 패스워드 미지원

    def get_allowed_auths(self, username):
        return "publickey"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode() if isinstance(command, bytes) else command
        out = self.outputs.get(cmd, "")
        rc = 0 if cmd in self.outputs else 1

        def reply():
            time.sleep(0.2)  # 서버가 exec 성공 응답을 보낸 뒤에 출력하도록 대기
            channel.sendall(out.encode() if rc == 0 else b"")
            if rc != 0:
                channel.sendall_stderr(b"cat: no such file")
            channel.send_exit_status(rc)
            channel.close()
        threading.Thread(target=reply, daemon=True).start()
        return True


class SSHFixture:
    def __init__(self, outputs):
        self.host_key = paramiko.RSAKey.generate(2048)
        self.client_key = paramiko.RSAKey.generate(2048)
        self.outputs = outputs
        self.transports = []  # GC 로 연결이 닫히지 않도록 참조 유지
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(self.host_key)
            t.start_server(server=_Server(self.client_key, self.outputs))
            self.transports.append(t)

    def rotate_host_key(self):
        self.host_key = paramiko.RSAKey.generate(2048)

    def close(self):
        self.sock.close()


@pytest.fixture
def ssh():
    f = SSHFixture({"cat /etc/ssl/a.pem": "PEMDATA"})
    yield f
    f.close()


def executor(ssh, store, user="certscan", pkey="default"):
    return ParamikoExecutor("127.0.0.1", ssh.port, user, store,
                            pkey=ssh.client_key if pkey == "default" else pkey, connect_timeout=5)


def test_connect_run_and_version(ssh):
    ex = executor(ssh, Store()).connect()
    rc, out, _ = ex.run(["cat", "/etc/ssl/a.pem"])
    assert (rc, out) == (0, "PEMDATA") and "paramiko" in ex.server_version.lower()
    rc, _, err = ex.run(["cat", "/etc/ssl/none.pem"])
    assert rc == 1 and "no such file" in err
    ex.close()


def test_tofu_records_then_detects_change(ssh):  # Q-HOSTKEY
    store = Store()
    executor(ssh, store).connect().close()
    assert store.get(f"127.0.0.1:{ssh.port}")  # 최초 접속은 신뢰하고 저장
    executor(ssh, store).connect().close()      # 같은 키는 계속 허용
    ssh.rotate_host_key()
    with pytest.raises(RemoteError) as e:
        executor(ssh, store).connect()
    assert e.value.cause == FailureCause.HOSTKEY
    store.forget_hostkey(f"127.0.0.1:{ssh.port}")  # 명시적 재확인 후에는 다시 허용
    executor(ssh, store).connect().close()


def test_wrong_key_is_auth_failure(ssh):
    with pytest.raises(RemoteError) as e:
        executor(ssh, Store(), pkey=paramiko.RSAKey.generate(2048)).connect()
    assert e.value.cause == FailureCause.AUTH


def test_wrong_account_is_auth_failure(ssh):
    with pytest.raises(RemoteError) as e:
        executor(ssh, Store(), user="root").connect()
    assert e.value.cause == FailureCause.AUTH


def test_refused_port_is_timeout_class():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    with pytest.raises(RemoteError) as e:
        ParamikoExecutor("127.0.0.1", port, "certscan", Store(), pkey=paramiko.RSAKey.generate(2048),
                         connect_timeout=2).connect()
    assert e.value.cause == FailureCause.TIMEOUT


def test_unresolvable_host_is_dns():
    with pytest.raises(RemoteError) as e:
        ParamikoExecutor("no-such-host.invalid", 22, "certscan", Store(),
                         pkey=paramiko.RSAKey.generate(2048), connect_timeout=2).connect()
    assert e.value.cause == FailureCause.DNS
