"""전 과정 공용 진단 트레이스: 단계별 이벤트(성공·실패·소요시간)를 링 버퍼와 JSONL 파일에 남긴다.

- 모든 값은 기록 전에 마스킹한다(개인키 PEM, 비밀번호·토큰류 키, Bearer 토큰).
- run_id 로 한 번의 작업(연결 테스트·조회·발급·배포)에 속한 이벤트를 묶어 본다.
- 보기: python -m certpilot_core.trace FILE [--run ID] [--errors] [-n 50]
"""
import contextvars
import json
import os
import re
import sys
import threading
import time
import traceback
import uuid
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

_PEM_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)
_BEARER = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.I)
_SENSITIVE_KEY = re.compile(r"pass(word|phrase)?|secret|token|private|authorization|cookie|credential|api[_-]?key", re.I)
_SAFE_SUFFIX = ("_file", "_env", "_path", "_ref", "_name")
MAX_STR = 600

run_id_var: contextvars.ContextVar = contextvars.ContextVar("cp_run_id", default=None)


def redact(value, key: str = ""):
    """사전·목록·문자열을 재귀적으로 마스킹한 사본을 돌려준다."""
    if key and _SENSITIVE_KEY.search(key) and not key.lower().endswith(_SAFE_SUFFIX):
        return "[REDACTED]" if value not in (None, "", False) else value
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [redact(v) for v in value]
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, str):
        s = _BEARER.sub(r"\1[REDACTED]", _PEM_KEY.sub("[REDACTED PRIVATE KEY]", value))
        return s if len(s) <= MAX_STR else s[:MAX_STR] + f"…(+{len(s) - MAX_STR}자)"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact(str(value))


class Tracer:
    def __init__(self, ring: int = 2000, path: Optional[str] = None, max_bytes: int = 5_000_000,
                 echo: Optional[Callable[[str], None]] = None):
        self._ring: deque = deque(maxlen=ring)
        self._lock = threading.Lock()
        self._seq = 0
        self.path, self.max_bytes, self.echo = path, max_bytes, echo

    def configure(self, path: Optional[str] = None, echo: Optional[Callable[[str], None]] = None,
                  max_bytes: Optional[int] = None) -> None:
        with self._lock:
            if path is not None:
                self.path = path or None
            if echo is not None:
                self.echo = echo
            if max_bytes:
                self.max_bytes = max_bytes

    # ---- 기록
    def event(self, component: str, step: str, level: str = "info", **fields) -> dict:
        with self._lock:
            self._seq += 1
            ev = {"seq": self._seq, "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                  "run_id": run_id_var.get(), "component": component, "step": step, "level": level,
                  **redact(fields)}
            self._ring.append(ev)
            self._write(ev)
        if self.echo:
            try:
                self.echo(format_event(ev))
            except Exception:   # noqa: BLE001 — 진단 출력이 본 작업을 깨뜨리지 않게 한다
                pass
        return ev

    def _write(self, ev: dict) -> None:
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            if os.path.exists(self.path) and os.path.getsize(self.path) > self.max_bytes:
                os.replace(self.path, self.path + ".1")
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        except OSError:
            pass

    @contextmanager
    def span(self, component: str, step: str, **fields):
        """with 블록의 성공/실패와 소요시간을 기록한다. 블록 안에서 ctx[...] 로 결과 필드를 더할 수 있다."""
        ctx: Dict = {}
        t0 = time.monotonic()
        self.event(component, step + ".start", "debug", **fields)
        try:
            yield ctx
        except BaseException as e:
            tb = traceback.extract_tb(e.__traceback__)[-1:] if e.__traceback__ else []
            self.event(component, step, "error", ms=round((time.monotonic() - t0) * 1000), **fields, **ctx,
                       error=type(e).__name__, message=str(e),
                       where=[f"{os.path.basename(f.filename)}:{f.lineno} {f.name}" for f in tb])
            raise
        self.event(component, step, "info", ms=round((time.monotonic() - t0) * 1000), **fields, **ctx)

    # ---- 조회
    def events(self, limit: int = 200, component: Optional[str] = None, level: Optional[str] = None,
               run_id: Optional[str] = None, since_seq: int = 0) -> List[dict]:
        order = {"debug": 0, "info": 1, "warning": 2, "error": 3}
        with self._lock:
            evs = list(self._ring)
        out = [e for e in evs if e["seq"] > since_seq
               and (not component or e["component"] == component)
               and (not run_id or e["run_id"] == run_id)
               and (not level or order.get(e["level"], 1) >= order.get(level, 0))]
        return out[-limit:]

    def clear(self) -> None:
        with self._lock:
            self._ring.clear()


TRACER = Tracer()


def event(component: str, step: str, level: str = "info", **fields) -> dict:
    return TRACER.event(component, step, level, **fields)


def span(component: str, step: str, **fields):
    return TRACER.span(component, step, **fields)


@contextmanager
def run(prefix: str = "run", run_id: Optional[str] = None):
    """한 번의 작업에 속한 이벤트를 같은 run_id 로 묶는다(이미 있으면 그대로 재사용)."""
    if run_id_var.get() and not run_id:
        yield run_id_var.get()
        return
    rid = run_id or f"{prefix}-{uuid.uuid4().hex[:8]}"
    tok = run_id_var.set(rid)
    try:
        yield rid
    finally:
        run_id_var.reset(tok)


def configure_from_env(env=os.environ, prefix: str = "CERTPILOT") -> None:
    """<PREFIX>_TRACE_FILE 로 파일 기록, <PREFIX>_DEBUG=1 이면 stderr 에 실시간 출력."""
    path = env.get(f"{prefix}_TRACE_FILE")
    echo = (lambda s: print(s, file=sys.stderr, flush=True)) if env.get(f"{prefix}_DEBUG") == "1" else None
    TRACER.configure(path=path, echo=echo)


# ---------------------------------------------------------------- 보기
_ICON = {"debug": "·", "info": "✓", "warning": "!", "error": "✗"}
_META = {"seq", "ts", "run_id", "component", "step", "level", "ms"}


def format_event(e: dict) -> str:
    extra = " ".join(f"{k}={json.dumps(v, ensure_ascii=False)}" for k, v in e.items() if k not in _META)
    ms = f" {e['ms']}ms" if "ms" in e else ""
    return f"{e['ts'][11:23]} {_ICON.get(e['level'], '?')} [{e.get('run_id') or '-'}] {e['component']}/{e['step']}{ms} {extra}".rstrip()


def read_file(path: str) -> List[dict]:
    out = []
    for p in (path + ".1", path):
        try:
            with open(p, encoding="utf-8") as f:
                for line in f:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        continue
        except OSError:
            continue
    return out


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="트레이스 파일 보기")
    ap.add_argument("file")
    ap.add_argument("--run")
    ap.add_argument("--component")
    ap.add_argument("--errors", action="store_true", help="오류만")
    ap.add_argument("--debug", action="store_true", help=".start 같은 상세 이벤트 포함")
    ap.add_argument("-n", type=int, default=100)
    a = ap.parse_args(argv)
    evs = read_file(a.file)
    evs = [e for e in evs if (not a.run or e.get("run_id") == a.run) and (not a.component or e["component"] == a.component)
           and (not a.errors or e["level"] == "error") and (a.debug or e["level"] != "debug")]
    for e in evs[-a.n:]:
        print(format_event(e))
    return 0


if __name__ == "__main__":
    sys.exit(main())
