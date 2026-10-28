"""certdeploy 시험용 PKI: 루트 → 중간 CA → 서버 인증서(체인 포함 PEM)를 즉석 생성한다."""
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, pub, signer, days_from, days_to, san=None, ca=False):
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer)).public_key(pub)
         .serial_number(x509.random_serial_number())
         .not_valid_before(now + dt.timedelta(days=days_from)).not_valid_after(now + dt.timedelta(days=days_to))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False))
    if ca:   # Python 3.13 의 엄격 검증(VERIFY_X509_STRICT)은 CA 인증서의 KeyUsage 확장을 요구한다
        b = b.add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                          crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False)
    return b.sign(signer, hashes.SHA256())


def make_pki(tmp_path, name="issued", san=("univ.example", "*.univ.example"), days_from=-1, days_to=90,
             algo="rsa", chain=True, key_to=None, shared_ca=None):
    """tmp_path 에 `<name>.crt`(서버+중간CA) / `<name>.key` 를 쓰고 (cert_path, key_path, leaf, key) 반환.
    shared_ca(dict)를 넘기면 같은 루트/중간 CA 로 여러 번 발급한다(갱신 시나리오: 신뢰 루트는 그대로)."""
    if shared_ca is not None and shared_ca:
        root_key, inter_key, root, inter = (shared_ca[k] for k in ("root_key", "inter_key", "root", "inter"))
    else:
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root = _cert("Test Root", "Test Root", root_key.public_key(), root_key, -3000, 3000, ca=True)
        inter = _cert("Test Intermediate", "Test Root", inter_key.public_key(), root_key, -2000, 2000, ca=True)
        if shared_ca is not None:
            shared_ca.update(root_key=root_key, inter_key=inter_key, root=root, inter=inter)
    key = ec.generate_private_key(ec.SECP256R1()) if algo == "ec" else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _cert(san[0], "Test Intermediate", key.public_key(), inter_key, days_from, days_to, san=list(san))
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM)
    (tmp_path / f"{name}.root.pem").write_bytes(pem(root))          # strict TLS 검증용 신뢰 CA
    cert_path, key_path = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    cert_path.write_bytes(pem(leaf) + (pem(inter) if chain else b""))
    key_path.write_bytes((key_to or key).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    return cert_path, key_path, leaf, key
