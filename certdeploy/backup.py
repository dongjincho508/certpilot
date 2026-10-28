"""발급 서버 상태의 암호화 백업·복원: lego 계정/인증서, certdeploy 상태, 설정 파일.

형식: b"CDBK1" + salt(16) + nonce(12) + AES-256-GCM(tar.gz). 키는 passphrase 에서 scrypt 로 유도한다.
개인키가 들어 있으므로 반드시 암호화해서 보관하고, 복원 시 경로 이탈(../, 절대 경로, 링크)을 거부한다.
"""
import io
import os
import tarfile
from typing import Dict, List

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CDBK1"
SCRYPT = dict(n=2 ** 15, r=8, p=1)


class BackupError(Exception):
    pass


def _key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12:
        raise BackupError("백업 비밀번호는 12자 이상이어야 합니다")
    return Scrypt(salt=salt, length=32, **SCRYPT).derive(passphrase.encode())


def create_backup(sources: Dict[str, str], passphrase: str) -> bytes:
    """sources: {보관 이름: 경로(파일 또는 디렉터리)}. 존재하지 않는 경로는 건너뛴다."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, path in sources.items():
            if os.path.exists(path):
                tar.add(path, arcname=name)
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_key(passphrase, salt)).encrypt(nonce, buf.getvalue(), MAGIC)
    return MAGIC + salt + nonce + ct


def _safe(member: tarfile.TarInfo, dest: str) -> None:
    target = os.path.realpath(os.path.join(dest, member.name))
    if not (target == os.path.realpath(dest) or target.startswith(os.path.realpath(dest) + os.sep)):
        raise BackupError(f"경로 이탈이 감지되어 복원을 중단합니다: {member.name}")
    if member.issym() or member.islnk() or member.isdev():
        raise BackupError(f"링크/장치 파일은 복원하지 않습니다: {member.name}")
    if os.path.isabs(member.name):
        raise BackupError(f"절대 경로는 복원하지 않습니다: {member.name}")


def restore_backup(blob: bytes, passphrase: str, dest: str) -> List[str]:
    """복원한 최상위 항목 이름 목록을 반환한다. 비밀번호 오류·변조는 BackupError."""
    if len(blob) < len(MAGIC) + 28 or not blob.startswith(MAGIC):
        raise BackupError("certdeploy 백업 파일이 아닙니다")
    salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
    try:
        plain = AESGCM(_key(passphrase, salt)).decrypt(nonce, ct, MAGIC)
    except InvalidTag:
        raise BackupError("복호화 실패: 비밀번호가 다르거나 파일이 변조되었습니다")
    os.makedirs(dest, mode=0o700, exist_ok=True)
    names = set()
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        members = tar.getmembers()
        for m in members:
            _safe(m, dest)
        for m in members:
            tar.extract(m, dest, filter="data")
            names.add(m.name.split("/")[0])
    return sorted(names)
