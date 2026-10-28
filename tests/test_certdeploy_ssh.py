"""프로세스 내 SSH 서버(실제 셸 실행)로 SSHTransport 와 SSH 경유 배포를 끝까지 시험한다."""
import os
import socket
import subprocess
import threading

import paramiko
import pytest

from certdeploy.bundle import load_bundle
from certdeploy.config import parse_config
from certdeploy.engine import Deployer, make_transport
from certdeploy.state import State
from certdeploy.transport import SSHTransport, TransportError
from pki_helpers import make_pki

pytestmark = pytest.mark.integration


class ExecServer(paramiko.ServerInterface):
    def __init__(self, authorized):
        self.authorized = authorized
        self.commands = []

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL if (username == "deploy" and key == self.authorized) else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "publickey"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode() if isinstance(command, bytes) else command
        self.commands.append(cmd)

        def run():
            data = b""
            while True:                               # 클라이언트가 stdin 을 닫을 때까지 수신
                chunk = channel.recv(65536)
                if not chunk:
                    break
                data += chunk
            p = subprocess.run(["sh", "-c", cmd], input=data, capture_output=True)
            channel.sendall(p.stdout)
            if p.stderr:
                channel.sendall_stderr(p.stderr)
            channel.send_exit_status(p.returncode)
            channel.close()
        threading.Thread(target=run, daemon=True).start()
        return True


class Sshd:
    def __init__(self, tmp_path):
        self.host_key = paramiko.RSAKey.generate(2048)
        self.client_key = paramiko.RSAKey.generate(2048)
        self.srv = ExecServer(self.client_key)
        self.transports = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.known_hosts = str(tmp_path / "known_hosts")
        self.write_known_hosts(self.host_key)
        self.key_file = str(tmp_path / "id_rsa")
        self.client_key.write_private_key_file(self.key_file)
        threading.Thread(target=self._serve, daemon=True).start()

    def write_known_hosts(self, key):
        with open(self.known_hosts, "w") as f:
            f.write(f"[127.0.0.1]:{self.port} {key.get_name()} {key.get_base64()}\n")

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(self.host_key)
            t.start_server(server=self.srv)
            self.transports.append(t)

    def close(self):
        self.sock.close()


@pytest.fixture
def sshd(tmp_path):
    s = Sshd(tmp_path)
    yield s
    s.close()


def connect(s, **kw):
    return SSHTransport("127.0.0.1", "deploy", port=s.port, key_file=s.key_file, known_hosts=s.known_hosts, **kw)


def test_run_with_stdin_and_exit_codes(sshd):
    t = connect(sshd)
    r = t.run("cat | tr a-z A-Z", stdin=b"hello")
    assert r.ok and r.out == "HELLO"
    assert t.run("echo oops >&2; exit 3").rc == 3
    assert "oops" in t.run("echo oops >&2; exit 3").err
    t.close()


def test_unknown_or_changed_host_key_is_rejected(sshd, tmp_path):
    empty = tmp_path / "empty_known_hosts"
    empty.write_text("")
    with pytest.raises(TransportError, match="SSH 접속 실패"):
        SSHTransport("127.0.0.1", "deploy", port=sshd.port, key_file=sshd.key_file, known_hosts=str(empty))   # 미등록 거부
    sshd.write_known_hosts(paramiko.RSAKey.generate(2048))                                                     # 다른 키
    with pytest.raises(TransportError, match="호스트 키"):
        connect(sshd)


def test_wrong_key_and_refused_port_are_transport_errors(sshd, tmp_path):
    other = tmp_path / "other"
    paramiko.RSAKey.generate(2048).write_private_key_file(str(other))
    with pytest.raises(TransportError):
        SSHTransport("127.0.0.1", "deploy", port=sshd.port, key_file=str(other), known_hosts=sshd.known_hosts)
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    free = s.getsockname()[1]
    s.close()
    with pytest.raises(TransportError):
        SSHTransport("127.0.0.1", "deploy", port=free, key_file=sshd.key_file, known_hosts=sshd.known_hosts, timeout=3)


def test_deploy_over_ssh_end_to_end(sshd, tmp_path):
    cert, key, leaf, _ = make_pki(tmp_path)
    web = tmp_path / "remote_web"
    web.mkdir()
    (web / "site.crt").write_text("OLD")
    cfg = parse_config({
        "certificate": {"cert_file": str(cert), "key_file": str(key)}, "state_dir": str(tmp_path / "st"),
        "targets": [{"name": "web1", "type": "generic",
                     "transport": {"kind": "ssh", "host": "127.0.0.1", "port": sshd.port, "user": "deploy",
                                   "key_file": sshd.key_file, "known_hosts": sshd.known_hosts},
                     "files": [{"path": str(web / "site.crt"), "content": "fullchain"},
                               {"path": str(web / "site.key"), "content": "key", "mode": "0600"}],
                     "check_cmd": "true", "reload_cmd": "true"}]})
    d = Deployer(cfg, load_bundle(str(cert), str(key)), State(cfg.state_dir), verifier=lambda *a, **k: 0)
    (r,) = d.deploy()
    assert r.status == "deployed", r.message
    assert (web / "site.crt").read_bytes() == d.bundle.fullchain_pem()
    assert oct(os.stat(web / "site.key").st_mode & 0o777) == "0o600"
    assert any(p.startswith("site.crt.bak-") for p in os.listdir(web))
    # 개인키가 원격 명령행에 노출되지 않았는지(stdin 으로만 전달) 확인
    key_body = d.bundle.key_pem().decode().splitlines()[1]
    assert not any(key_body in c for c in sshd.srv.commands)
    assert any("umask 077 && cat >" in c for c in sshd.srv.commands)


def test_make_transport_builds_ssh_and_local(sshd):
    t = make_transport({"kind": "ssh", "host": "127.0.0.1", "port": sshd.port, "user": "deploy",
                        "key_file": sshd.key_file, "known_hosts": sshd.known_hosts}, 30)
    assert isinstance(t, SSHTransport)
    t.close()
    from certdeploy.transport import LocalTransport
    assert isinstance(make_transport({"kind": "local"}, 30), LocalTransport)
