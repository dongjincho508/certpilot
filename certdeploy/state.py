"""배포 상태 저장(JSON, 원자적 기록)과 동시 실행 방지(파일 잠금)."""
import fcntl
import json
import os
import tempfile
from contextlib import contextmanager


class LockedError(Exception):
    pass


class State:
    def __init__(self, state_dir: str):
        self.dir = state_dir
        self.path = os.path.join(state_dir, "state.json")
        self.data = {"certificate": None, "targets": {}}

    def load(self) -> "State":
        try:
            with open(self.path, encoding="utf-8") as f:
                self.data = json.load(f)
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            raise RuntimeError(f"상태 파일을 읽을 수 없습니다: {self.path}")
        return self

    def save(self) -> None:
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".state-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def target(self, name: str) -> dict:
        return self.data["targets"].get(name, {})

    def set_target(self, name: str, **fields) -> None:
        self.data["targets"].setdefault(name, {}).update(fields)


@contextmanager
def exclusive_lock(state_dir: str):
    """같은 상태 디렉터리에서 배포가 동시에 두 번 돌지 않게 한다(타이머 중복 실행 방지)."""
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(state_dir, "lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LockedError("다른 certdeploy 작업이 실행 중입니다")
        yield
    finally:
        os.close(fd)
