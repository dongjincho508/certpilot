"""인증서 묶음(리프+체인+개인키) 로드·검증·형식 변환."""
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12


class BundleError(Exception):
    """사용자가 조치해야 하는 인증서/키 문제 (메시지에 키 내용은 포함하지 않는다)."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _pub_der(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def hostname_matches(pattern: str, host: str) -> bool:
    """SAN dNSName 매칭: 정확히 같거나, '*.' 와일드카드가 왼쪽 한 레이블만 대체한다(RFC 6125)."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern == host:
        return True
    if pattern.startswith("*."):
        return "." in host and host.split(".", 1)[1] == pattern[2:] and host.split(".", 1)[0] != ""
    return False


@dataclass
class Bundle:
    leaf: x509.Certificate
    chain: List[x509.Certificate]          # 중간 CA (리프 제외, 서버 → 루트 방향)
    key: object
    warnings: List[str] = field(default_factory=list)

    # ---- 식별
    @property
    def serial(self) -> int:
        return self.leaf.serial_number

    @property
    def not_after(self) -> datetime:
        return self.leaf.not_valid_after_utc

    @property
    def not_before(self) -> datetime:
        return self.leaf.not_valid_before_utc

    @property
    def names(self) -> List[str]:
        try:
            ext = self.leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return list(ext.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            return []

    def covers(self, host: str) -> bool:
        return any(hostname_matches(n, host) for n in self.names)

    def days_left(self, now: Optional[datetime] = None) -> float:
        return (self.not_after - (now or _utcnow())).total_seconds() / 86400

    # ---- PEM
    @staticmethod
    def _pem(cert) -> bytes:
        return cert.public_bytes(serialization.Encoding.PEM)

    def cert_pem(self) -> bytes:
        return self._pem(self.leaf)

    def chain_pem(self) -> bytes:
        return b"".join(self._pem(c) for c in self.chain)

    def fullchain_pem(self) -> bytes:
        return self.cert_pem() + self.chain_pem()

    def key_pem(self) -> bytes:
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())

    # ---- 키스토어
    def pkcs12(self, password: str, alias: str = "server", legacy: bool = False) -> bytes:
        """PKCS#12 키스토어. legacy=True 는 구형 JVM(Java 8 초기 등)이 읽는 3DES/SHA1 방식."""
        if not password:
            raise BundleError("키스토어 비밀번호가 비어 있습니다")
        if legacy:
            enc = (serialization.PrivateFormat.PKCS12.encryption_builder()
                   .kdf_rounds(2048).key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                   .hmac_hash(hashes.SHA1()).build(password.encode()))
        else:
            enc = serialization.BestAvailableEncryption(password.encode())
        return pkcs12.serialize_key_and_certificates(alias.encode(), self.key, self.leaf, self.chain or None, enc)

    def jks(self, password: str, alias: str = "server", keytool: str = "keytool") -> bytes:
        """JKS 키스토어 (JDK 의 keytool 필요). 비밀번호는 명령행이 아닌 환경변수로 전달한다."""
        if shutil.which(keytool) is None:
            raise BundleError("JKS 변환에 keytool(JDK)이 필요합니다")
        with tempfile.TemporaryDirectory(prefix="certdeploy-") as tmp:
            os.chmod(tmp, 0o700)
            src, dst = os.path.join(tmp, "in.p12"), os.path.join(tmp, "out.jks")
            with open(os.open(src, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
                f.write(self.pkcs12(password, alias, legacy=True))
            env = dict(os.environ, CERTDEPLOY_KS_PASS=password)
            r = subprocess.run(
                [keytool, "-importkeystore", "-noprompt", "-srckeystore", src, "-srcstoretype", "PKCS12",
                 "-srcstorepass:env", "CERTDEPLOY_KS_PASS", "-destkeystore", dst, "-deststoretype", "JKS",
                 "-deststorepass:env", "CERTDEPLOY_KS_PASS", "-destkeypass:env", "CERTDEPLOY_KS_PASS"],
                capture_output=True, text=True, env=env, timeout=60)
            if r.returncode != 0 or not os.path.exists(dst):
                raise BundleError("keytool 변환 실패: " + (r.stderr.strip().splitlines() or ["원인 불명"])[-1][:200])
            with open(dst, "rb") as f:
                return f.read()


def load_bundle(cert_path: str, key_path: str, key_password: Optional[str] = None) -> Bundle:
    """lego 산출물(`*.crt` 는 서버 인증서 + 중간 CA, `*.key`)을 읽는다. 문제가 있으면 BundleError."""
    try:
        with open(cert_path, "rb") as f:
            certs = x509.load_pem_x509_certificates(f.read())
    except FileNotFoundError:
        raise BundleError(f"인증서 파일이 없습니다: {cert_path}")
    except ValueError:
        raise BundleError(f"인증서 PEM 을 해석할 수 없습니다: {cert_path}")
    if not certs:
        raise BundleError("인증서 파일에 인증서가 없습니다")
    try:
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), key_password.encode() if key_password else None)
    except FileNotFoundError:
        raise BundleError(f"개인키 파일이 없습니다: {key_path}")
    except TypeError:
        raise BundleError("개인키가 암호로 보호되어 있습니다(key_password_env 설정 필요)")
    except ValueError:
        raise BundleError("개인키를 해석할 수 없습니다(형식 오류 또는 암호 불일치)")
    leaf, chain = certs[0], certs[1:]
    b = Bundle(leaf=leaf, chain=chain, key=key)
    validate(b)
    return b


def validate(b: Bundle, min_days: float = 1.0, now: Optional[datetime] = None) -> None:
    """배포하면 안 되는 문제는 BundleError, 주의 사항은 b.warnings 에 추가한다."""
    now = now or _utcnow()
    if _pub_der(b.leaf.public_key()) != _pub_der(b.key.public_key()):
        raise BundleError("개인키가 인증서와 일치하지 않습니다")
    if now < b.not_before:
        raise BundleError("인증서가 아직 유효하지 않습니다(유효 시작 전)")
    if b.days_left(now) <= 0:
        raise BundleError("인증서가 이미 만료되었습니다")
    if b.days_left(now) < min_days:
        raise BundleError(f"인증서 만료까지 {b.days_left(now):.1f}일 — 배포 의미가 없습니다")
    # 체인 순서: 각 인증서의 발급자가 다음 인증서의 주체여야 한다
    prev = b.leaf
    for c in b.chain:
        if prev.issuer != c.subject:
            b.warnings.append("체인 순서가 올바르지 않습니다(중간 CA 가 발급 순서대로 이어지지 않음)")
            break
        prev = c
    if not b.chain:
        b.warnings.append("중간 CA 체인이 없습니다 — 일부 클라이언트에서 신뢰 오류가 날 수 있습니다")
    if not b.names:
        b.warnings.append("SAN(dNSName)이 없습니다")
