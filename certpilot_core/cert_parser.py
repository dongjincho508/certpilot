"""
CertPilot Core - Certificate Parser Module
PEM/PKCS#12/JKS 인증서 파싱 모듈
"""
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

_PEM_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


@dataclass
class CertificateInfo:
    """인증서 정보 데이터 클래스"""
    subject: str
    issuer: str
    serial: str
    not_before: datetime
    not_after: datetime
    version: int
    signature_algorithm: str
    public_key_algorithm: str
    public_key_bits: int
    is_expired: bool
    is_not_yet_valid: bool
    subject_alt_name: List[str] = None
    fingerprint_sha256: str = ""

    def __post_init__(self):
        if self.subject_alt_name is None:
            self.subject_alt_name = []


def _to_info(cert: x509.Certificate, now: Optional[datetime] = None) -> CertificateInfo:
    """cryptography 인증서 객체를 CertificateInfo 로 변환 (시각은 UTC naive)"""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    not_before = cert.not_valid_before_utc.replace(tzinfo=None)
    not_after = cert.not_valid_after_utc.replace(tzinfo=None)
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        algo = "rsaEncryption"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        algo = "id-ecPublicKey"
    else:
        algo = type(pub).__name__
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [f"DNS:{n}" for n in san_ext.value.get_values_for_type(x509.DNSName)]
        sans += [f"IP:{n}" for n in san_ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []
    sig = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial=format(cert.serial_number, "x"),
        not_before=not_before,
        not_after=not_after,
        version=cert.version.value + 1,
        signature_algorithm=sig,
        public_key_algorithm=algo,
        public_key_bits=getattr(pub, "key_size", 0),
        is_expired=not_after < now,
        is_not_yet_valid=not_before > now,
        subject_alt_name=sans,
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
    )


def parse_pem_blocks(pem_text: str) -> List[Optional[CertificateInfo]]:
    """PEM 문자열의 CERTIFICATE 블록마다 파싱 결과를 반환. 깨진 블록은 None.
    인증서 외 블록(개인키 등)은 읽지도 반환하지도 않는다."""
    out = []
    for block in _PEM_BLOCK.findall(pem_text):
        try:
            out.append(_to_info(x509.load_pem_x509_certificate(block.encode())))
        except ValueError:
            out.append(None)
    return out


def parse_pem_text(pem_text: str) -> List[CertificateInfo]:
    """PEM 문자열(멀티파트 가능)에서 인증서를 파싱. 깨진 블록은 건너뛴다."""
    return [c for c in parse_pem_blocks(pem_text) if c is not None]


def extract_pem_certs(text: str) -> str:
    """텍스트에서 CERTIFICATE 블록만 이어 붙여 반환 (S-4 해시 대상 원문)."""
    return "\n".join(_PEM_BLOCK.findall(text))


def parse_der_certificate(der: bytes) -> Optional[CertificateInfo]:
    """DER 인증서 1건 파싱 (TLS 핸드셰이크로 받은 인증서용)"""
    try:
        return _to_info(x509.load_der_x509_certificate(der))
    except ValueError:
        return None


def parse_pem_certificates(cert_path: str) -> List[CertificateInfo]:
    """PEM 파일 경로에서 인증서 파싱 (개인키 블록은 읽지 않는다)"""
    with open(cert_path, "r", errors="replace") as f:
        return parse_pem_text(f.read())


def parse_pkcs12(pfx_path: str, pfx_password: str = None) -> List[CertificateInfo]:
    """PKCS#12 (.pfx/.p12) 에서 인증서만 추출 (개인키는 메모리에서도 사용하지 않고 버린다)"""
    try:
        with open(pfx_path, "rb") as f:
            data = f.read()
        pw = pfx_password.encode() if pfx_password else None
        p12 = pkcs12.load_pkcs12(data, pw)
    except (ValueError, OSError):
        return []
    certs = []
    if p12.cert:
        certs.append(_to_info(p12.cert.certificate))
    certs.extend(_to_info(c.certificate) for c in p12.additional_certs)
    return certs


def parse_jks(jks_path: str, keytool_path: str = "keytool",
              password: str = "changeit") -> List[CertificateInfo]:
    """JKS 에서 인증서만 추출 (keytool 로 임시 PKCS#12 변환 후 파싱)"""
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "out.p12")
        cmd = [keytool_path, "-importkeystore",
               "-srckeystore", jks_path, "-srcstoretype", "JKS", "-srcstorepass", password,
               "-destkeystore", dest, "-deststoretype", "PKCS12", "-deststorepass", password,
               "-noprompt"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return []
        if r.returncode != 0 or not os.path.exists(dest):
            return []
        return parse_pkcs12(dest, password)


if __name__ == "__main__":
    # 테스트
    import sys
    if len(sys.argv) > 1:
        cert_path = sys.argv[1]
        if cert_path.endswith('.pem'):
            certs = parse_pem_certificates(cert_path)
        elif cert_path.endswith(('.pfx', '.p12')):
            certs = parse_pkcs12(cert_path, pfx_password='changeit')
        else:
            certs = parse_pem_certificates(cert_path)
        
        for i, cert in enumerate(certs):
            print(f"=== 인증서 {i+1} ===")
            print(f"Subject: {cert.subject}")
            print(f"Issuer: {cert.issuer}")
            print(f"Serial: {cert.serial}")
            print(f"Not Before: {cert.not_before}")
            print(f"Not After: {cert.not_after}")
            print(f"Version: {cert.version}")
            print(f"Signature Algorithm: {cert.signature_algorithm}")
            print(f"Public Key: {cert.public_key_algorithm} ({cert.public_key_bits} bit)")
            print(f"Expired: {cert.is_expired}")
            print(f"Not Yet Valid: {cert.is_not_yet_valid}")
            print()