"""수동 발급 인증서(상용 CA 구매 등) 지원: CSR 생성, CA 가 준 파일(PEM/DER/PKCS#7/PFX) 정리·검증·설치.

흐름: `csr` 로 키+CSR 생성(키는 대기 디렉터리에 0600) → CA 에 CSR 제출 → 받은 파일을 `import` 로 검증·정리해
설정된 cert_file/key_file 위치에 원자적으로 설치 → `deploy` 로 자동 배포. 개인키는 이 서버를 벗어나지 않는다.
"""
import os
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID

from .bundle import Bundle, BundleError, validate

KEY_TYPES = ("rsa2048", "rsa3072", "rsa4096", "ec256", "ec384")


class ManualError(Exception):
    """사용자가 조치해야 하는 입력 문제(키 내용은 메시지에 포함하지 않는다)."""


# ------------------------------------------------------------------ CSR
def generate_key(key_type: str = "rsa2048"):
    if key_type not in KEY_TYPES:
        raise ManualError(f"key_type 은 {', '.join(KEY_TYPES)} 중 하나여야 합니다")
    if key_type.startswith("rsa"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(key_type[3:]))
    return ec.generate_private_key(ec.SECP256R1() if key_type == "ec256" else ec.SECP384R1())


def generate_csr(domains: List[str], key_type: str = "rsa2048", subject: Optional[Dict[str, str]] = None) -> Tuple[bytes, bytes]:
    """(키 PEM, CSR PEM). CN 은 첫 도메인, SAN 에 모든 도메인. subject 로 C/ST/L/O/OU 를 추가할 수 있다."""
    domains = [d.strip() for d in domains if d.strip()]
    if not domains:
        raise ManualError("도메인이 필요합니다")
    for d in domains:
        if " " in d or "/" in d or d.count("*") > 1 or ("*" in d and not d.startswith("*.")):
            raise ManualError(f"도메인 형식이 올바르지 않습니다: {d!r} (와일드카드는 맨 앞 '*.' 만 가능)")
    key = generate_key(key_type)
    attrs = []
    oids = {"C": NameOID.COUNTRY_NAME, "ST": NameOID.STATE_OR_PROVINCE_NAME, "L": NameOID.LOCALITY_NAME,
            "O": NameOID.ORGANIZATION_NAME, "OU": NameOID.ORGANIZATIONAL_UNIT_NAME}
    for k, v in (subject or {}).items():
        if k not in oids:
            raise ManualError(f"subject 항목은 {', '.join(oids)} 만 지원합니다: {k}")
        if v:
            attrs.append(x509.NameAttribute(oids[k], v))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, domains[0]))
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False)
           .sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            csr.public_bytes(serialization.Encoding.PEM))


def encrypt_key_pem(key_pem: bytes, password: str) -> bytes:
    """개인키 PEM 을 암호(PKCS#8, AES-256)로 보호한 PEM 으로 바꾼다."""
    key = serialization.load_pem_private_key(key_pem, None)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password.encode()))


def decrypt_key_pem(key_pem: bytes, password: Optional[str]) -> bytes:
    try:
        key = serialization.load_pem_private_key(key_pem, password.encode() if password else None)
    except TypeError:
        raise ManualError("개인키가 암호로 보호되어 있습니다(암호 환경변수 필요)")
    except ValueError:
        raise ManualError("개인키를 해석할 수 없습니다(형식 오류 또는 암호 불일치)")
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def convert_key_file(key_file: str, password: str, encrypt: bool, now: Optional[datetime] = None, keep_backup: bool = True) -> Tuple[bool, Optional[str]]:
    """저장된 개인키 파일을 암호화/평문으로 바꾼다. (변경 여부, 변환 전 백업 경로) 반환. 이미 원하는 상태면 (False, None).
    변환 전 원본은 `.bak-<시각>`(0600)으로 보존한다(새 키로 정상 동작을 확인한 뒤 shred 로 삭제)."""
    try:
        data = open(key_file, "rb").read()
    except OSError as e:
        raise ManualError(f"개인키 파일을 읽을 수 없습니다: {e.strerror}")
    if encrypt == (b"ENCRYPTED" in data):
        return False, None
    out = encrypt_key_pem(data, password) if encrypt else decrypt_key_pem(data, password)
    bak = f"{key_file}.bak-{(now or datetime.now(timezone.utc)):%Y%m%d%H%M%S}"
    _write_private(bak, data, 0o600)
    _write_private(key_file, out, 0o600)
    if not keep_backup:                                   # 새 파일이 원래 키와 같은 키임을 확인한 뒤에만 원본 사본을 덮어써 지운다
        plain = lambda blob: decrypt_key_pem(blob, password if b"ENCRYPTED" in blob else None)    # noqa: E731 — 암호화 여부에 맞게 평문 PEM 으로 정규화
        if plain(out) == plain(data):
            shred_file(bak)
            return True, None
    return True, bak


def shred_file(path: str) -> None:
    """파일 내용을 0 으로 덮어쓴 뒤 삭제(키 사본 정리용, 최선의 노력 — SSD·스냅샷에는 흔적이 남을 수 있다)."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(b"\0" * size)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.remove(path)
    except OSError:
        pass


def rekey_file(key_file: str, old_password: str, new_password: str) -> None:
    """암호화된 개인키의 암호를 바꾼다(원본 사본은 남기지 않되, 검증 후 교체)."""
    data = open(key_file, "rb").read()
    plain = decrypt_key_pem(data, old_password)
    out = encrypt_key_pem(plain, new_password)
    if decrypt_key_pem(out, new_password) != plain:
        raise ManualError("암호 변경 검증에 실패했습니다")
    _write_private(key_file, out, 0o600)


def pending_dir(state_dir: str, name: str) -> str:
    return os.path.join(state_dir, "pending", name)


def _write_private(path: str, data: bytes, mode: int = 0o600) -> None:
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def save_pending(state_dir: str, name: str, key_pem: bytes, csr_pem: bytes, force: bool = False, key_password: Optional[str] = None) -> Tuple[str, str]:
    """대기 키/CSR 저장. 이미 대기 중인 키가 있으면 덮어쓰지 않는다(CA 에 이미 제출한 CSR 의 키를 잃지 않도록)."""
    d = pending_dir(state_dir, name)
    kp, cp = os.path.join(d, "key.pem"), os.path.join(d, f"{name}.csr")
    if os.path.exists(kp) and not force:
        raise ManualError(f"이미 대기 중인 키가 있습니다({kp}). 새로 만들려면 --force (제출한 CSR 의 키를 잃게 됩니다)")
    _write_private(kp, encrypt_key_pem(key_pem, key_password) if key_password else key_pem, 0o600)
    _write_private(cp, csr_pem, 0o644)
    return kp, cp


# ------------------------------------------------------------------ 인증서 수집(PEM / DER / PKCS#7 / PFX)
def _load_certs_from_bytes(data: bytes) -> List[x509.Certificate]:
    if b"-----BEGIN" in data:
        for loader in (x509.load_pem_x509_certificates, pkcs7.load_pem_pkcs7_certificates):
            try:
                certs = loader(data)
                if certs:
                    return list(certs)
            except ValueError:
                continue
    else:
        try:
            return [x509.load_der_x509_certificate(data)]
        except ValueError:
            pass
        try:
            return list(pkcs7.load_der_pkcs7_certificates(data))
        except ValueError:
            pass
    return []


def collect_certs(paths: List[str]) -> List[x509.Certificate]:
    """여러 파일(서버 인증서, 중간 CA 번들 등)에서 인증서를 모은다. 중복(같은 지문)은 하나로."""
    out: Dict[bytes, x509.Certificate] = {}
    for p in paths:
        try:
            with open(p, "rb") as f:
                data = f.read()
        except OSError as e:
            raise ManualError(f"파일을 읽을 수 없습니다: {p} ({e.strerror})")
        certs = _load_certs_from_bytes(data)
        if not certs:
            raise ManualError(f"인증서를 해석할 수 없습니다(PEM/DER/PKCS#7 형식이 아님): {p}")
        for c in certs:
            out[c.fingerprint(hashes.SHA256())] = c
    return list(out.values())


def load_pfx(path: str, password: Optional[str]) -> Tuple[object, List[x509.Certificate]]:
    try:
        with open(path, "rb") as f:
            key, cert, extra = pkcs12.load_key_and_certificates(f.read(), password.encode() if password else None)
    except OSError as e:
        raise ManualError(f"파일을 읽을 수 없습니다: {path} ({e.strerror})")
    except (ValueError, TypeError):
        raise ManualError("PFX 를 열 수 없습니다(비밀번호가 다르거나 형식 오류)")
    if key is None or cert is None:
        raise ManualError("PFX 에 개인키 또는 서버 인증서가 없습니다")
    return key, [cert] + list(extra or [])


def load_key_file(path: str, password: Optional[str] = None):
    try:
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password.encode() if password else None)
    except OSError as e:
        raise ManualError(f"개인키 파일을 읽을 수 없습니다: {path} ({e.strerror})")
    except TypeError:
        raise ManualError("개인키가 암호로 보호되어 있습니다")
    except ValueError:
        raise ManualError("개인키를 해석할 수 없습니다(형식 오류 또는 암호 불일치)")


def _pub(c_or_k) -> bytes:
    pk = c_or_k.public_key()
    return pk.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def build_bundle(certs: List[x509.Certificate], key) -> Tuple[Bundle, List[str]]:
    """섞여 있는 인증서들에서 키와 일치하는 서버 인증서를 찾고, 발급 관계를 따라 중간 CA 체인을 정렬한다.
    자체 서명 루트는 제외한다(클라이언트가 이미 신뢰). (Bundle, 안내 목록)을 반환."""
    notes: List[str] = []
    leaves = [c for c in certs if _pub(c) == _pub(key)]
    if not leaves:
        raise ManualError("개인키와 일치하는 서버 인증서가 없습니다 — CSR 을 만들 때의 키가 맞는지, 다른 인증서 파일인지 확인하세요")
    leaf = max(leaves, key=lambda c: c.not_valid_after_utc)
    pool = [c for c in certs if c is not leaf and c.fingerprint(hashes.SHA256()) != leaf.fingerprint(hashes.SHA256())]
    chain, cur = [], leaf
    while True:
        nxt = next((c for c in pool if c.subject == cur.issuer and c.subject != c.issuer), None)
        if nxt is None:
            break
        chain.append(nxt)
        pool.remove(nxt)
        cur = nxt
    roots = [c for c in pool if c.subject == c.issuer]
    unused = [c for c in pool if c not in roots]
    if roots:
        notes.append(f"자체 서명 루트 인증서 {len(roots)}개는 체인에서 제외했습니다(클라이언트가 이미 신뢰)")
    if unused:
        notes.append(f"서버 인증서와 연결되지 않는 인증서 {len(unused)}개는 제외했습니다")
    if not chain:
        notes.append("중간 CA 가 없습니다 — CA 가 제공한 중간 인증서(번들)를 함께 지정했는지 확인하세요")
    b = Bundle(leaf=leaf, chain=chain, key=key)
    try:
        validate(b)
    except BundleError as e:
        raise ManualError(str(e))
    return b, notes + b.warnings


# ------------------------------------------------------------------ 설치
def install_bundle(cert_file: str, key_file: str, b: Bundle, now: Optional[datetime] = None, key_password: Optional[str] = None) -> List[str]:
    """fullchain(서버+중간 CA)과 키를 설정된 위치에 원자적으로 설치한다. 기존 파일은 `.bak-<시각>` 으로 보존."""
    now = now or datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%d%H%M%S")
    backups = []
    for path in (cert_file, key_file):
        if os.path.exists(path):
            bak = f"{path}.bak-{ts}"
            data = open(path, "rb").read()
            _write_private(bak, data, 0o600)          # 백업에 키가 있을 수 있으므로 600
            backups.append(bak)
    _write_private(cert_file, b.fullchain_pem(), 0o644)
    _write_private(key_file, encrypt_key_pem(b.key_pem(), key_password) if key_password else b.key_pem(), 0o600)    # 암호 지정 시 저장본은 암호화(배포 때만 메모리에서 복호화)
    return backups
