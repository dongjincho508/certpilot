import socket
import ssl
import threading

import pytest
from cryptography.hazmat.primitives import serialization

from certpilot_core.cert_parser import parse_der_certificate
from certpilot_core.remote import FailureCause, RemoteError
from certpilot_core.scanner import TlsProbe
from conftest import make_cert

pytestmark = pytest.mark.integration


@pytest.fixture
def tls_server(tmp_path):
    key, cert = make_cert("localhost", -1, 90, ["localhost"])
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); sock.listen(5)

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
                ctx.wrap_socket(conn, server_side=True).close()
            except OSError:
                if sock.fileno() == -1:
                    return
    threading.Thread(target=serve, daemon=True).start()
    yield sock.getsockname()[1], cert
    sock.close()


def test_fetch_returns_server_certificate(tls_server):
    port, cert = tls_server
    der = TlsProbe().fetch("127.0.0.1", port, sni="localhost", timeout=5)
    assert parse_der_certificate(der).fingerprint_sha256 == cert.fingerprint(
        __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()).hex()


def test_non_tls_port_is_classified(tmp_path):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1); port = s.getsockname()[1]
    threading.Thread(target=lambda: (s.accept()[0].close()), daemon=True).start()
    with pytest.raises(RemoteError) as e:
        TlsProbe().fetch("127.0.0.1", port, timeout=3)
    s.close()
    assert e.value.cause in (FailureCause.COMMAND, FailureCause.TIMEOUT)


def test_closed_port_is_timeout_class():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    with pytest.raises(RemoteError) as e:
        TlsProbe().fetch("127.0.0.1", port, timeout=2)
    assert e.value.cause == FailureCause.TIMEOUT
