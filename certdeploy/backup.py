"""발급 서버 상태의 암호화 백업·복원: lego 계정/인증서, certdeploy 상태, 설정 파일.

형식: b"CDBK1" + salt(16) + nonce(12) + AES-256-GCM(tar.gz). 키는 passphrase 에서 scrypt 로 유도한다.
개인키가 들어 있으므로 반드시 암호화해서 보관하고, 복원 시 경로 이탈(../, 절대 경로, 링크)을 거부한다.
"""
import fnmatch
import io
import os
import tarfile
import time
from typing import Dict, Iterable, List, Optional

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


def _excluded(path: str, patterns: Iterable[str]) -> bool:
    base = os.path.basename(path)
    return any(fnmatch.fnmatch(base, p) or fnmatch.fnmatch(path, p) for p in patterns)


def _add_tree(tar: tarfile.TarFile, path: str, arc: str, exclude: Iterable[str], skipped: List[str]) -> None:
    """파일/디렉터리를 하나씩 추가한다. 읽을 수 없는 항목(권한 등)은 전체를 멈추지 않고 skipped 에 기록한다."""
    if _excluded(path, exclude):
        return
    try:
        if os.path.islink(path):
            skipped.append(f"{path} (심볼릭 링크는 백업하지 않음)")
            return
        if os.path.isdir(path):
            tar.add(path, arcname=arc, recursive=False)
            for name in sorted(os.listdir(path)):
                _add_tree(tar, os.path.join(path, name), f"{arc}/{name}", exclude, skipped)
        elif os.path.isfile(path):
            tar.add(path, arcname=arc, recursive=False)
    except OSError as e:
        skipped.append(f"{path} ({type(e).__name__})")


def create_backup(sources: Dict[str, str], passphrase: str, extra: Optional[Dict[str, bytes]] = None,
                  exclude: Iterable[str] = (), skipped: Optional[List[str]] = None, mtime: Optional[float] = None) -> bytes:
    """sources: {보관 이름: 경로(파일 또는 디렉터리)}. 존재하지 않는 경로는 건너뛴다.
    extra: {보관 이름: 바이트} — 메모리에서 만든 항목(SQLite 일관 스냅샷, 목록 등).
    skipped 를 넘기면 읽을 수 없는 항목을 거기에 모으고 계속 진행한다(넘기지 않으면 첫 오류에서 중단)."""
    own: List[str] = skipped if skipped is not None else []
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, path in sources.items():
            if os.path.exists(path):
                _add_tree(tar, path, name, exclude, own)
        for name, data in (extra or {}).items():
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o600, int(mtime if mtime is not None else time.time())
            tar.addfile(info, io.BytesIO(data))
    if skipped is None and own:
        raise BackupError("읽을 수 없는 항목이 있어 백업을 중단합니다: " + "; ".join(own[:3]))
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_key(passphrase, salt)).encrypt(nonce, buf.getvalue(), MAGIC)
    return MAGIC + salt + nonce + ct


def decrypt_backup(blob: bytes, passphrase: str) -> bytes:
    """복호화한 tar.gz 바이트. 비밀번호 오류·변조는 BackupError."""
    if len(blob) < len(MAGIC) + 28 or not blob.startswith(MAGIC):
        raise BackupError("certdeploy 백업 파일이 아닙니다")
    salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
    try:
        return AESGCM(_key(passphrase, salt)).decrypt(nonce, ct, MAGIC)
    except InvalidTag:
        raise BackupError("복호화 실패: 비밀번호가 다르거나 파일이 변조되었습니다")


def list_members(blob: bytes, passphrase: str) -> List[dict]:
    """백업 안의 항목 목록(이름·크기·종류). 경로 이탈 등 위험한 항목이 있으면 BackupError."""
    plain = decrypt_backup(blob, passphrase)
    out = []
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        for m in tar.getmembers():
            _safe(m, "/restore-check")
            out.append({"name": m.name, "size": m.size, "type": "dir" if m.isdir() else "file", "mode": m.mode})
    return out


def read_member(blob: bytes, passphrase: str, name: str) -> Optional[bytes]:
    plain = decrypt_backup(blob, passphrase)
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        try:
            f = tar.extractfile(name)
        except KeyError:
            return None
        return f.read() if f else None


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
    plain = decrypt_backup(blob, passphrase)
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
