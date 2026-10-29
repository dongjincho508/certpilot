"""백업 자동화: 관리 서버 전체(설정·상태·관리자 DB·감시 비밀·nginx)를 한 번에 암호화 백업하고, 검증·보관 정리·외부 복사·상태 기록·복구까지 다룬다.

- 일관성: 관리자 DB(SQLite)는 파일을 그대로 복사하지 않고 SQLite 백업 API 로 일관된 스냅샷을 만든다.
- 안전: 읽을 수 없는 항목은 건너뛰고 '부분 백업'으로 경고한다. 새 백업은 복호화·목록 검증을 통과해야 보관 정리(오래된 것 삭제)가 실행된다.
- 비밀번호는 환경변수/파일로만 받는다(설정 파일에 쓰지 않음). 백업 파일은 AES-256-GCM(scrypt) 암호화, 권한 600.
"""
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import socket
import sqlite3
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__
from .backup import BackupError, create_backup, decrypt_backup, list_members
from .transport import SSHTransport, TransportError

NAME_RE = re.compile(r"^certdeploy-(\d{8})-(\d{6})\.cdbk$")
MANIFEST = "manifest.json"
DEFAULTS = {"dir": "/var/backups/certdeploy", "keep_daily": 7, "keep_weekly": 4, "keep_monthly": 6, "verify": True,
            "etc_dir": "/etc/certdeploy", "admin_data_dir": "/var/lib/certdeploy-admin",
            "monitoring_dir": "/opt/cert-monitor/src/monitoring",
            "nginx_files": ["/etc/nginx/conf.d/grafana.conf", "/etc/nginx/conf.d/certdeploy-admin.conf",
                            "/etc/pki/tls/certs/mgmt.crt", "/etc/pki/tls/private/mgmt.key"],
            "include": [], "exclude": ["trace.jsonl", "trace.jsonl.1", "*.new.*", "lock", "approvals.lock", "*.tmp", ".tmp-*", ".state-*"],
            "copy_to": []}
# 감시 스택에서 저장소(git)로 복구할 수 없는, 이 서버에서만 만들어진 파일(상대 경로)
MONITORING_FILES = [".env", "alertmanager/secrets", "alertmanager/alertmanager.local.yml", "docker-compose.override.yml",
                    "prometheus/targets/servers.yml"]


def parse_backup(raw, problems: List[str]) -> Optional[dict]:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        problems.append("backup 은 매핑이어야 합니다")
        return None
    unknown = set(raw) - set(DEFAULTS) - {"passphrase_env", "passphrase_file"}
    if unknown:
        problems.append(f"backup 의 알 수 없는 키: {', '.join(sorted(unknown))}")
    b = {**DEFAULTS, **{k: v for k, v in raw.items() if k in DEFAULTS}}
    b["passphrase_env"], b["passphrase_file"] = raw.get("passphrase_env"), raw.get("passphrase_file")
    if not (b["passphrase_env"] or b["passphrase_file"]):
        problems.append("backup: passphrase_env(또는 passphrase_file)가 필요합니다 — 비밀번호를 설정 파일에 쓰지 않는다")
    for k in ("dir", "etc_dir", "admin_data_dir", "monitoring_dir"):
        if not isinstance(b[k], str) or not b[k].startswith("/") or ".." in b[k].split("/"):
            problems.append(f"backup.{k}: 절대 경로여야 합니다")
    for k in ("keep_daily", "keep_weekly", "keep_monthly"):
        if not isinstance(b[k], int) or isinstance(b[k], bool) or not 0 <= b[k] <= 400:
            problems.append(f"backup.{k} 는 0~400 정수여야 합니다")
    if not isinstance(b["verify"], bool):
        problems.append("backup.verify 는 true/false 여야 합니다")
    for k in ("include", "nginx_files", "exclude"):
        if not isinstance(b[k], list) or not all(isinstance(x, str) for x in b[k]):
            problems.append(f"backup.{k} 는 문자열 목록이어야 합니다")
    for p in b["include"] if isinstance(b["include"], list) else []:
        if not str(p).startswith("/") or ".." in str(p).split("/"):
            problems.append(f"backup.include: 절대 경로여야 합니다: {p}")
    names = set()
    for i, t in enumerate(b["copy_to"] if isinstance(b["copy_to"], list) else [], 1):
        if not isinstance(t, dict) or t.get("kind") not in ("dir", "ssh"):
            problems.append(f"backup.copy_to[{i}]: kind 는 dir 또는 ssh 여야 합니다")
            continue
        name = str(t.get("name") or f"{t['kind']}{i}")
        if name in names:
            problems.append(f"backup.copy_to: 이름이 중복됩니다: {name}")
        names.add(name)
        if not str(t.get("path", "")).startswith("/"):
            problems.append(f"backup.copy_to[{i}].path: 절대 경로여야 합니다")
        if t["kind"] == "ssh" and not (t.get("host") and t.get("user") and t.get("known_hosts")):
            problems.append(f"backup.copy_to[{i}]: ssh 에는 host, user, known_hosts 가 필요합니다")
        t["name"] = name
    if not isinstance(b["copy_to"], list):
        problems.append("backup.copy_to 는 목록이어야 합니다")
    return b


def passphrase_of(b: dict, environ=os.environ) -> str:
    pw = environ.get(b["passphrase_env"] or "") if b.get("passphrase_env") else None
    if not pw and b.get("passphrase_file"):
        try:
            st = os.stat(b["passphrase_file"])
            if st.st_mode & 0o077:
                raise BackupError(f"비밀번호 파일 권한이 너무 넓습니다(600 필요): {b['passphrase_file']}")
            pw = open(b["passphrase_file"], encoding="utf-8").read().strip()
        except OSError:
            pw = None
    if not pw:
        raise BackupError("백업 비밀번호를 얻을 수 없습니다(환경변수/파일 확인)")
    return pw


# ------------------------------------------------------------------ 대상 수집
def snapshot_sqlite(path: str) -> bytes:
    """실행 중인 SQLite DB 의 일관된 스냅샷(백업 API). 파일을 그냥 복사하면 쓰는 도중의 불완전한 상태가 될 수 있다."""
    fd, tmp = tempfile.mkstemp(prefix=".dbsnap-")
    os.close(fd)
    try:
        src = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        dst = sqlite3.connect(tmp)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        with open(tmp, "rb") as f:
            return f.read()
    finally:
        os.unlink(tmp)


def _owner(path: str) -> dict:
    try:
        st = os.lstat(path)
        return {"user": pwd.getpwuid(st.st_uid).pw_name, "group": grp.getgrgid(st.st_gid).gr_name, "mode": oct(st.st_mode & 0o7777)}
    except (OSError, KeyError):
        return {}


def collect(cfg, config_path: str, b: dict) -> Tuple[Dict[str, str], Dict[str, bytes], Dict[str, dict], List[str]]:
    """(디렉터리/파일 원본, 메모리 항목, 보관이름→원래 경로·소유자 지도, 안내)"""
    sources: Dict[str, str] = {}
    extra: Dict[str, bytes] = {}
    notes: List[str] = []
    add = lambda arc, path: sources.__setitem__(arc, path) if os.path.exists(path) else notes.append(f"없음(건너뜀): {path}")  # noqa: E731
    add("etc/certdeploy", b["etc_dir"])
    if os.path.isfile(config_path) and not config_path.startswith(b["etc_dir"].rstrip("/") + "/"):
        add("etc/certdeploy-config/" + os.path.basename(config_path), config_path)
    # 전역 상태 폴더 전체(설정 화면 값 settings.json, 배포용 SSH 키, 승인·티켓·알림 기록, 인증서별 하위 폴더). 인증서가 여러 개여도 한 번에 담긴다.
    add("state", cfg.state_dir)
    for cs in cfg.certs:
        if not (cs.state_dir == cfg.state_dir or cs.state_dir.startswith(cfg.state_dir.rstrip("/") + "/")):
            add(f"state-{cs.name}", cs.state_dir)
        if cs.lego:
            add(f"lego/{cs.name}", cs.lego.get("path", "/var/lib/lego"))
    dbdir = b["admin_data_dir"]
    if os.path.isdir(dbdir):
        for name in sorted(os.listdir(dbdir)):
            p = os.path.join(dbdir, name)
            if name.endswith((".db", ".sqlite")) and os.path.isfile(p):
                try:
                    extra[f"admin-data/{name}"] = snapshot_sqlite(p)
                except sqlite3.Error as e:
                    notes.append(f"DB 스냅샷 실패(건너뜀): {p} ({type(e).__name__})")
            elif not name.endswith(("-wal", "-shm", "-journal")):
                add(f"admin-data/{name}", p)
    else:
        notes.append(f"없음(건너뜀): {dbdir}")
    for rel in MONITORING_FILES:
        add("monitoring/" + rel, os.path.join(b["monitoring_dir"], rel))
    for p in b["nginx_files"]:
        add("nginx/" + p.lstrip("/").replace("/", "__"), p)
    for p in b["include"]:
        add("extra/" + p.lstrip("/").replace("/", "__"), p)
    origin: Dict[str, dict] = {}
    for arc, path in sources.items():
        origin[arc] = {"path": path, **_owner(path)}
    for name in extra:
        origin[name] = {"path": os.path.join(dbdir, os.path.basename(name)), **_owner(os.path.join(dbdir, os.path.basename(name)))}
    return sources, extra, origin, notes


# ------------------------------------------------------------------ 보관 정리(GFS)
def parse_name(name: str) -> Optional[datetime]:
    m = NAME_RE.match(name)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def to_keep(names: List[str], daily: int, weekly: int, monthly: int) -> List[str]:
    """최근 daily 일은 매일 1개, 최근 weekly 주는 주 1개, 최근 monthly 개월은 월 1개(각 구간의 가장 최근 것)를 남긴다. 가장 최근 1개는 항상 남긴다."""
    items = sorted(((parse_name(n), n) for n in names if parse_name(n)), reverse=True)
    keep = set()
    if items:
        keep.add(items[0][1])
    for label, count, key in (("d", daily, lambda d: d.strftime("%Y-%m-%d")), ("w", weekly, lambda d: "%d-W%02d" % d.isocalendar()[:2]),
                              ("m", monthly, lambda d: d.strftime("%Y-%m"))):
        seen = []
        for d, n in items:
            k = key(d)
            if k not in seen:
                if len(seen) >= count:
                    break
                seen.append(k)
                keep.add(n)
    return sorted(keep)


# ------------------------------------------------------------------ 저장 대상(로컬 폴더 / 마운트 / SSH)
class DirStore:
    def __init__(self, path: str):
        self.path = path

    def label(self):
        return self.path

    def list(self) -> List[str]:
        try:
            return sorted(n for n in os.listdir(self.path) if NAME_RE.match(n) or NAME_RE.match(n.replace(".manifest.json", "")))
        except OSError:
            return []

    def put(self, name: str, data: bytes) -> None:
        os.makedirs(self.path, mode=0o700, exist_ok=True)
        tmp = os.path.join(self.path, f".tmp-{name}-{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, os.path.join(self.path, name))

    def get(self, name: str) -> bytes:
        with open(os.path.join(self.path, name), "rb") as f:
            return f.read()

    def delete(self, name: str) -> None:
        try:
            os.unlink(os.path.join(self.path, name))
        except FileNotFoundError:
            pass

    def close(self):
        pass


class SshStore:
    """외부 서버(SFTP 대신 SSH 명령)에 복사한다. 호스트 키는 known_hosts 로 엄격히 검증한다."""

    def __init__(self, spec: dict, factory: Optional[Callable] = None):
        self.spec = spec
        self.path = spec["path"].rstrip("/")
        self.t = (factory or (lambda s: SSHTransport(s["host"], s["user"], int(s.get("port", 22)), s.get("key_file"), s.get("known_hosts"))))(spec)

    def label(self):
        return f"{self.spec['user']}@{self.spec['host']}:{self.path}"

    def _run(self, cmd, stdin=None, timeout=300):
        r = self.t.run(cmd, stdin=stdin, timeout=timeout)
        if not r.ok:
            raise BackupError(f"원격 명령 실패: {(r.err or r.out).strip().splitlines()[-1:] or ['원인 불명']}")
        return r

    def list(self) -> List[str]:
        import shlex
        r = self.t.run(f"ls -1 {shlex.quote(self.path)} 2>/dev/null")
        return sorted(n for n in r.out.split() if NAME_RE.match(n) or NAME_RE.match(n.replace(".manifest.json", "")))

    def put(self, name: str, data: bytes) -> None:
        import shlex
        d, tmp = shlex.quote(self.path), shlex.quote(f"{self.path}/.tmp-{name}")
        self._run(f"umask 077 && mkdir -p {d} && cat > {tmp} && mv -f {tmp} {shlex.quote(self.path + '/' + name)}", stdin=data)

    def delete(self, name: str) -> None:
        import shlex
        self.t.run(f"rm -f -- {shlex.quote(self.path + '/' + name)}")

    def close(self):
        self.t.close()


def make_stores(b: dict, factory: Optional[Callable] = None) -> List:
    out = []
    for t in b["copy_to"]:
        out.append(DirStore(t["path"]) if t["kind"] == "dir" else SshStore(t, factory))
    return out


# ------------------------------------------------------------------ 실행
@dataclass
class Result:
    ok: bool = False
    name: str = ""
    size: int = 0
    members: int = 0
    skipped: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    local_dir: str = ""
    copies: List[dict] = field(default_factory=list)       # [{name, label, ok, error}]
    pruned: List[str] = field(default_factory=list)
    verified: bool = False
    error: str = ""
    started: str = ""
    finished: str = ""
    duration_s: float = 0.0

    @property
    def partial(self) -> bool:
        return bool(self.skipped)

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["partial"] = self.partial
        return d


STATUS_FILE = "backup-status.json"


def save_status(state_dir: str, res: Result) -> None:
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=state_dir, prefix=".bkstatus-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(res.as_dict(), f, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o640)
    os.replace(tmp, os.path.join(state_dir, STATUS_FILE))


def load_status(state_dir: str) -> Optional[dict]:
    try:
        with open(os.path.join(state_dir, STATUS_FILE), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _prune(store, b: dict) -> List[str]:
    names = [n for n in store.list() if n.endswith(".cdbk")]
    keep = set(to_keep(names, b["keep_daily"], b["keep_weekly"], b["keep_monthly"]))
    gone = []
    for n in names:
        if n not in keep:
            store.delete(n)
            store.delete(n + ".manifest.json")
            gone.append(n)
    return gone


def run_backup(cfg, config_path: str, b: dict, passphrase: str, now: Optional[datetime] = None,
               ssh_factory: Optional[Callable] = None, hostname: Optional[str] = None) -> Result:
    """수집 → 암호화 → 검증 → 로컬 저장 → 외부 복사 → 보관 정리. 예외 없이 Result 로 보고한다."""
    now = now or datetime.now(timezone.utc)
    t0 = time.monotonic()
    res = Result(started=now.isoformat(), local_dir=b["dir"])
    res.name = f"certdeploy-{now:%Y%m%d-%H%M%S}.cdbk"
    try:
        sources, extra, origin, res.notes = collect(cfg, config_path, b)
        if not sources and not extra:
            raise BackupError("백업할 대상이 하나도 없습니다(경로 설정 확인)")
        manifest = {"created_at": now.isoformat(), "host": hostname or socket.gethostname(), "certdeploy": __version__, "origin": origin}
        extra = {**extra, MANIFEST: json.dumps(manifest, ensure_ascii=False, indent=1).encode()}
        blob = create_backup(sources, passphrase, extra=extra, exclude=[*b["exclude"], b["dir"].rstrip("/")], skipped=res.skipped, mtime=now.timestamp())
        res.size = len(blob)
        if b["verify"]:
            members = list_members(blob, passphrase)
            res.members = len(members)
            names = {m["name"] for m in members}
            if MANIFEST not in names or "state" not in names:
                raise BackupError("검증 실패: 백업에 필수 항목(state, manifest)이 없습니다")
            res.verified = True
        side = json.dumps({"name": res.name, "created_at": now.isoformat(), "size": res.size, "sha256": hashlib.sha256(blob).hexdigest(),
                           "members": res.members, "partial": res.partial, "skipped": res.skipped[:50], "certdeploy": __version__}, ensure_ascii=False, indent=1).encode()
        local = DirStore(b["dir"])
        local.put(res.name, blob)
        local.put(res.name + ".manifest.json", side)
        for st, spec in zip(make_stores_safe(b, ssh_factory, res), b["copy_to"]):
            if st is None:
                continue
            try:
                st.put(res.name, blob)
                st.put(res.name + ".manifest.json", side)
                res.pruned += [f"{spec['name']}:{n}" for n in _prune(st, b)]
                res.copies.append({"name": spec["name"], "label": st.label(), "ok": True, "error": ""})
            except (OSError, BackupError, TransportError) as e:
                res.copies.append({"name": spec["name"], "label": st.label(), "ok": False, "error": f"{type(e).__name__}: {str(e)[:150]}"})
            finally:
                st.close()
        res.pruned += _prune(local, b)
        res.ok = all(c["ok"] for c in res.copies)
        if not res.ok:
            res.error = "외부 복사 실패: " + ", ".join(c["name"] for c in res.copies if not c["ok"])
    except (BackupError, OSError) as e:
        res.ok, res.error = False, f"{type(e).__name__}: {e}"
    now2 = datetime.now(timezone.utc)
    res.finished, res.duration_s = now2.isoformat(), round(time.monotonic() - t0, 2)
    return res


def make_stores_safe(b: dict, factory: Optional[Callable], res: Result) -> List:
    """접속에 실패한 외부 대상은 None 으로 두고 실패로 기록한다(나머지 대상은 계속)."""
    out = []
    for t in b["copy_to"]:
        try:
            out.append(DirStore(t["path"]) if t["kind"] == "dir" else SshStore(t, factory))
        except (TransportError, OSError, KeyError) as e:
            res.copies.append({"name": t["name"], "label": t.get("path", ""), "ok": False, "error": f"{type(e).__name__}: {str(e)[:150]}"})
            out.append(None)
    return out


def metrics_text(res: Result) -> str:
    def g(name, help_, val):
        return f"# HELP {name} {help_}\n# TYPE {name} gauge\n{name} {val}\n"
    ts = int(datetime.fromisoformat(res.finished).timestamp()) if res.finished else 0
    out = g("certdeploy_backup_ok", "마지막 백업 실행 성공 여부(1=성공, 외부 복사 포함).", int(res.ok))
    out += g("certdeploy_backup_last_run_timestamp_seconds", "마지막 백업 실행 시각.", ts)
    if res.ok:
        out += g("certdeploy_backup_last_success_timestamp_seconds", "마지막 백업 성공 시각.", ts)
    out += g("certdeploy_backup_size_bytes", "마지막 백업 파일 크기.", res.size)
    out += g("certdeploy_backup_partial", "읽지 못해 빠진 항목이 있으면 1.", int(res.partial))
    out += g("certdeploy_backup_copies_failed", "외부 복사에 실패한 대상 수.", sum(1 for c in res.copies if not c["ok"]))
    return out


def list_backups(b: dict) -> List[dict]:
    out = []
    for n in DirStore(b["dir"]).list():
        if not n.endswith(".cdbk"):
            continue
        p = os.path.join(b["dir"], n)
        try:
            out.append({"name": n, "size": os.path.getsize(p), "created": parse_name(n).isoformat() if parse_name(n) else None})
        except OSError:
            pass
    return sorted(out, key=lambda x: x["name"], reverse=True)


# ------------------------------------------------------------------ 검증(심층)·복구
def deep_verify(blob: bytes, passphrase: str) -> dict:
    """복호화 → 임시 폴더에 풀어 인증서·키 짝, 관리자 DB 무결성, 목록 일치를 확인하고 임시 파일은 지운다."""
    from .bundle import BundleError, load_bundle
    plain = decrypt_backup(blob, passphrase)
    report = {"certs": [], "databases": [], "problems": []}
    tmp = tempfile.mkdtemp(prefix="cd-verify-")
    try:
        os.chmod(tmp, 0o700)
        import io
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
            for m in tar.getmembers():
                from .backup import _safe
                _safe(m, tmp)
            tar.extractall(tmp, filter="data")                      # nosec B202 - 위에서 경로·링크 검사
        for root, _, files in os.walk(tmp):
            for f in files:
                p = os.path.join(root, f)
                if f.endswith(".db"):
                    try:
                        c = sqlite3.connect(p)
                        res = c.execute("PRAGMA integrity_check").fetchone()[0]
                        c.close()
                        report["databases"].append({"name": os.path.relpath(p, tmp), "ok": res == "ok"})
                        if res != "ok":
                            report["problems"].append(f"DB 무결성 오류: {os.path.relpath(p, tmp)}")
                    except sqlite3.Error as e:
                        report["problems"].append(f"DB 열기 실패: {os.path.relpath(p, tmp)} ({type(e).__name__})")
                elif f.endswith(".crt") and os.path.exists(p[:-4] + ".key"):
                    try:
                        raw = open(p[:-4] + ".key", "rb").read(400)
                        if b"ENCRYPTED" in raw:
                            report["certs"].append({"name": os.path.relpath(p, tmp), "ok": True, "note": "개인키 암호화됨(짝 확인 생략)"})
                            continue
                        b_ = load_bundle(p, p[:-4] + ".key")
                        report["certs"].append({"name": os.path.relpath(p, tmp), "ok": True, "serial": f"{b_.serial:x}", "days_left": round(b_.days_left(), 1)})
                    except BundleError as e:
                        report["certs"].append({"name": os.path.relpath(p, tmp), "ok": False, "error": str(e)[:120]})
                        report["problems"].append(f"인증서/키 확인 실패: {os.path.relpath(p, tmp)}")
        if not os.path.exists(os.path.join(tmp, MANIFEST)):
            report["problems"].append("manifest.json 이 없습니다")
        return report
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def restore_apply(blob: bytes, passphrase: str, root: str = "/", dry_run: bool = True) -> List[dict]:
    """백업을 원래 위치(root 기준)에 되돌린다. manifest 의 원래 경로·소유자를 사용한다.
    기본은 계획만 반환(dry_run). 적용 시 기존 파일은 `<경로>.pre-restore-<시각>` 로 옮겨 둔다."""
    import io
    plain = decrypt_backup(blob, passphrase)
    tmp = tempfile.mkdtemp(prefix="cd-restore-")
    plan: List[dict] = []
    try:
        os.chmod(tmp, 0o700)
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
            from .backup import _safe
            for m in tar.getmembers():
                _safe(m, tmp)
            tar.extractall(tmp, filter="data")                      # nosec B202 - 위에서 경로·링크 검사
        mf = json.load(open(os.path.join(tmp, MANIFEST), encoding="utf-8"))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        for arc, o in sorted(mf["origin"].items()):
            src = os.path.join(tmp, arc)
            if not os.path.exists(src):
                continue
            dest = os.path.join(root, o["path"].lstrip("/"))
            plan.append({"archive": arc, "dest": dest, "owner": f"{o.get('user', '?')}:{o.get('group', '?')}", "exists": os.path.exists(dest)})
            if dry_run:
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if os.path.lexists(dest):
                os.replace(dest, f"{dest}.pre-restore-{stamp}")
            if os.path.isdir(src):
                shutil.copytree(src, dest, symlinks=False)
            else:
                shutil.copy2(src, dest)
            _chown_tree(dest, o.get("user"), o.get("group"))
        return plan
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _chown_tree(path: str, user: Optional[str], group: Optional[str]) -> None:
    try:
        uid, gid = pwd.getpwnam(user).pw_uid if user else -1, grp.getgrnam(group).gr_gid if group else -1
    except KeyError:
        return                                                      # 이 서버에 없는 계정이면 소유자는 그대로 둔다(수동 조정)
    for root, dirs, files in os.walk(path):
        for n in dirs + files:
            try:
                os.chown(os.path.join(root, n), uid, gid)
            except OSError:
                pass
    try:
        os.chown(path, uid, gid)
    except OSError:
        pass


def age_hours(res: dict, now: Optional[datetime] = None) -> Optional[float]:
    try:
        return ((now or datetime.now(timezone.utc)) - datetime.fromisoformat(res["finished"])).total_seconds() / 3600
    except (KeyError, ValueError, TypeError):
        return None
