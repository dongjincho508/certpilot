"""공용 fixture: 테스트 인증서를 코드로 생성한다 (별도 인증서 세트 불필요)."""
import datetime as dt
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

NOW = dt.datetime.now(dt.timezone.utc)


def make_cert(cn="test.example.com", days_from=-1, days_to=90, san=None):
    """days_from/days_to: 현재 기준 유효 시작/종료까지의 일수. (key, cert) 반환."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW + dt.timedelta(days=days_from))
        .not_valid_after(NOW + dt.timedelta(days=days_to))
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False)
    return key, builder.sign(key, hashes.SHA256())


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def cert_dir(tmp_path):
    """상태별 샘플 PEM: valid / expiring / expired / not_yet_valid / corrupt."""
    samples = {
        "valid": make_cert("valid.test", -1, 90, ["valid.test"]),
        "expiring": make_cert("expiring.test", -60, 10),
        "expired": make_cert("expired.test", -100, -1),
        "not_yet_valid": make_cert("future.test", 5, 100),
    }
    for name, (_, c) in samples.items():
        (tmp_path / f"{name}.pem").write_bytes(pem(c))
    (tmp_path / "corrupt.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----\n")
    return tmp_path


@pytest.fixture
def pkcs12_file(tmp_path):
    key, cert = make_cert("p12.test")
    path = tmp_path / "bundle.p12"
    path.write_bytes(pkcs12.serialize_key_and_certificates(
        b"p12", key, cert, None, serialization.BestAvailableEncryption(b"changeit")))
    return path


@pytest.fixture
def jks_file(tmp_path):
    path = tmp_path / "store.jks"
    r = subprocess.run(
        ["keytool", "-genkeypair", "-alias", "a", "-keyalg", "RSA", "-keysize", "2048",
         "-dname", "CN=jks.test", "-validity", "90", "-keystore", str(path),
         "-storetype", "JKS", "-storepass", "changeit", "-keypass", "changeit"],
        capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"keytool unavailable: {r.stderr}")
    return path


@pytest.fixture
def sandbox(tmp_path):
    """원격 파일시스템 역할의 디렉터리. put(path, content) 로 파일을 심는다."""
    root = tmp_path / "remote"
    root.mkdir()

    class Box:
        path = str(root)

        def put(self, remote_path, content):
            f = root / remote_path.lstrip("/")
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(content if isinstance(content, bytes) else content.encode())
            return f

        def link(self, remote_path, target):
            f = root / remote_path.lstrip("/")
            f.parent.mkdir(parents=True, exist_ok=True)
            f.symlink_to(target)

    return Box()


@pytest.fixture(autouse=True)
def _isolated_trace():
    """진단 추적기는 프로세스 전역이라, 앞선 시험이 설정한 파일 경로·작업 ID 가 다음 시험에 새지 않게 매번 초기화한다."""
    from certpilot_core import trace
    trace.TRACER.clear()
    trace.TRACER.configure(path="", echo=None)
    trace.run_id_var.set(None)
    yield
    trace.TRACER.configure(path="", echo=None)
