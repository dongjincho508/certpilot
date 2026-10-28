"""SQLite 영속화: 서버, 최신 조회 결과, 호스트 키(TOFU), 사용자, 세션"""
import json
import sqlite3
import threading
from contextlib import contextmanager
from typing import Dict, List, Optional

from .remote import HostKeyStore

SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
  id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, hostname TEXT NOT NULL,
  port INTEGER NOT NULL, account TEXT NOT NULL, paths TEXT NOT NULL, tls_ports TEXT NOT NULL,
  warn_days INTEGER NOT NULL, grp TEXT, memo TEXT, created_at TEXT NOT NULL,
  os_type TEXT NOT NULL DEFAULT 'auto');
CREATE TABLE IF NOT EXISTS scans (
  server_id TEXT PRIMARY KEY, scanned_at TEXT NOT NULL, status TEXT NOT NULL,
  result TEXT NOT NULL, file_hashes TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS hostkeys (
  host_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, first_seen TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL,
  failed_count INTEGER NOT NULL DEFAULT 0, locked_until TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, created_at TEXT NOT NULL, last_seen TEXT NOT NULL);
"""

USER_COLUMNS = frozenset({"password_hash", "role", "failed_count", "locked_until"})


class Store(HostKeyStore):
    def __init__(self, path: str = ":memory:"):
        self.path = path
        self._lock = threading.RLock()
        self._mem = sqlite3.connect(path, check_same_thread=False) if path == ":memory:" else None
        with self._conn() as c:
            c.executescript(SCHEMA)
            self._migrate(c)

    @staticmethod
    def _migrate(c) -> None:
        """이미 배포된 DB(영구 디스크)에 새 컬럼을 추가한다. 기존 서버는 OS '자동 감지'로 간주."""
        cols = {r["name"] for r in c.execute("PRAGMA table_info(servers)")}
        if "os_type" not in cols:
            c.execute("ALTER TABLE servers ADD COLUMN os_type TEXT NOT NULL DEFAULT 'auto'")

    @contextmanager
    def _conn(self):
        with self._lock:
            conn = self._mem or sqlite3.connect(self.path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                if self._mem is None:
                    conn.close()

    # ---- 서버
    @staticmethod
    def _server(row) -> dict:
        d = dict(row)
        d["paths"], d["tls_ports"] = json.loads(d["paths"]), json.loads(d["tls_ports"])
        d["group"] = d.pop("grp")
        return d

    def add_server(self, s: dict) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO servers (id, name, hostname, port, account, paths, tls_ports, warn_days,"
                " grp, memo, created_at, os_type) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                    s["id"], s["name"], s["hostname"], s["port"], s["account"],
                    json.dumps(s["paths"]), json.dumps(s["tls_ports"]), s["warn_days"],
                    s.get("group"), s.get("memo"), s["created_at"], s.get("os_type", "auto")))

    def get_server(self, server_id: str) -> Optional[dict]:
        with self._conn() as c:
            r = c.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()
        return self._server(r) if r else None

    def list_servers(self) -> List[dict]:
        with self._conn() as c:
            return [self._server(r) for r in c.execute("SELECT * FROM servers ORDER BY name")]

    def delete_server(self, server_id: str) -> bool:
        with self._conn() as c:
            c.execute("DELETE FROM scans WHERE server_id=?", (server_id,))
            return c.execute("DELETE FROM servers WHERE id=?", (server_id,)).rowcount > 0

    # ---- 조회 결과 (서버당 최신 1건)
    def save_scan(self, server_id: str, scanned_at: str, status: str, result: dict,
                  file_hashes: Dict[str, str]) -> None:
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?)", (
                server_id, scanned_at, status, json.dumps(result), json.dumps(file_hashes)))

    def get_scan(self, server_id: str) -> Optional[dict]:
        with self._conn() as c:
            r = c.execute("SELECT * FROM scans WHERE server_id=?", (server_id,)).fetchone()
        if not r:
            return None
        return {"result": json.loads(r["result"]), "file_hashes": json.loads(r["file_hashes"])}

    # ---- 호스트 키 (TOFU)
    def get(self, host_id: str) -> Optional[str]:
        with self._conn() as c:
            r = c.execute("SELECT fingerprint FROM hostkeys WHERE host_id=?", (host_id,)).fetchone()
        return r["fingerprint"] if r else None

    def put(self, host_id: str, fingerprint: str) -> None:
        from .status import iso_z, utcnow
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO hostkeys VALUES (?,?,?)",
                      (host_id, fingerprint, iso_z(utcnow())))

    def forget_hostkey(self, host_id: str) -> bool:
        with self._conn() as c:
            return c.execute("DELETE FROM hostkeys WHERE host_id=?", (host_id,)).rowcount > 0

    # ---- 사용자·세션
    def add_user(self, username, password_hash, role, created_at) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO users VALUES (?,?,?,0,NULL,?)",
                      (username, password_hash, role, created_at))

    def get_user(self, username) -> Optional[dict]:
        with self._conn() as c:
            r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(r) if r else None

    def list_users(self) -> List[dict]:
        with self._conn() as c:
            return [{"username": r["username"], "role": r["role"], "locked_until": r["locked_until"]}
                    for r in c.execute("SELECT * FROM users ORDER BY username")]

    def update_user(self, username, **fields) -> None:
        bad = set(fields) - USER_COLUMNS
        if bad:
            raise ValueError(f"허용되지 않는 사용자 컬럼: {sorted(bad)}")
        cols = ", ".join(f"{k}=?" for k in fields)    # 컬럼명은 위 허용 목록만 통과 → 값은 바인딩
        with self._conn() as c:
            c.execute(f"UPDATE users SET {cols} WHERE username=?", (*fields.values(), username))  # nosec B608

    def delete_user(self, username) -> bool:
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE username=?", (username,))
            return c.execute("DELETE FROM users WHERE username=?", (username,)).rowcount > 0

    def add_session(self, token_hash, username, now) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO sessions VALUES (?,?,?,?)", (token_hash, username, now, now))

    def get_session(self, token_hash) -> Optional[dict]:
        with self._conn() as c:
            r = c.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
        return dict(r) if r else None

    def touch_session(self, token_hash, now) -> None:
        with self._conn() as c:
            c.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, token_hash))

    def delete_session(self, token_hash) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))

    def user_sessions(self, username) -> List[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM sessions WHERE username=? ORDER BY created_at", (username,))]
