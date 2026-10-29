"""서비스 유형별 배포 파일 명세와 기본 점검·재로드 명령.

apache / nginx / nodejs / tomcat 은 관례적인 기본값을 제공하고, WebtoB·JEUS·그 밖의 제품은 `generic`
유형으로 파일 목록과 명령을 직접 지정한다(제품별 경로·명령은 제품 문서로 확인해 설정에 적는다).
"""
import re
from dataclasses import dataclass
from typing import List, Optional

CONTENT_KINDS = ("cert", "fullchain", "chain", "key", "key_encrypted", "key_encrypted_traditional", "pkcs12", "jks")
KEY_KINDS = ("key", "key_encrypted", "key_encrypted_traditional", "pkcs12", "jks")        # 개인키가 들어 있어 0600 으로 다룬다
PASSWORD_KINDS = ("key_encrypted", "key_encrypted_traditional", "pkcs12", "jks")           # 비밀번호(password_env/password_file)가 필요한 내용

APACHE_CHECK = ("if command -v apachectl >/dev/null 2>&1; then apachectl configtest; "
                "elif command -v httpd >/dev/null 2>&1; then httpd -t; else apache2ctl configtest; fi")
APACHE_RELOAD = "systemctl reload httpd 2>/dev/null || systemctl reload apache2"

TYPES = ("apache", "nginx", "nodejs", "tomcat", "webtob", "jeus", "generic")
OWNER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}(:[a-z_][a-z0-9_-]{0,31})?$")


@dataclass
class FileSpec:
    dest: str
    content: str                        # CONTENT_KINDS 중 하나
    mode: str = "0644"
    password_env: Optional[str] = None  # pkcs12/jks 비밀번호를 담은 환경변수 이름
    password_file: Optional[str] = None  # 또는 비밀번호를 담은 파일(권한 600, 예: systemd credentials)
    alias: str = "server"
    legacy_pkcs12: bool = False         # 구형 JVM 용 PKCS#12(3DES)
    owner: Optional[str] = None         # 'user' 또는 'user:group' — 새 파일의 소유자(기존 파일이 있으면 그 소유자를 유지)


class SpecError(ValueError):
    pass


def _need_password(raw) -> None:
    if not (raw.get("password_env") or raw.get("password_file")):
        raise SpecError("키스토어에는 password_env 또는 password_file 이 필요합니다(비밀번호를 설정 파일에 직접 쓰지 않는다)")


def _pem_pair(raw) -> List[FileSpec]:
    for k in ("cert_path", "key_path"):
        if not raw.get(k):
            raise SpecError(f"{k} 가 필요합니다")
    files = [FileSpec(raw["cert_path"], "fullchain", "0644"), FileSpec(raw["key_path"], "key", "0600")]
    if raw.get("chain_path"):
        files.append(FileSpec(raw["chain_path"], "chain", "0644"))
    return files


def _owner(raw) -> Optional[str]:
    o = raw.get("owner")
    if o is None:
        return None
    if not isinstance(o, str) or not OWNER_RE.match(o):
        raise SpecError("owner 는 'user' 또는 'user:group' 형식이어야 합니다(영문 소문자·숫자·_-)")
    return o


def _with_owner(files: List[FileSpec], raw) -> List[FileSpec]:
    o = _owner(raw)
    for f in files:
        f.owner = o
    return files


def _webtob(raw) -> List[FileSpec]:
    """WebtoB: http.m 의 *SSL 절이 가리키는 PEM 파일들(서버 인증서·개인키·체인). 개인키는 암호화(패스프레이즈)할 수도 있다."""
    for k in ("cert_path", "key_path"):
        if not raw.get(k):
            raise SpecError(f"{k} 가 필요합니다")
    cert_kind = raw.get("cert_content", "cert")
    if cert_kind not in ("cert", "fullchain"):
        raise SpecError("cert_content 는 cert(서버 인증서만) 또는 fullchain 이어야 합니다")
    files = [FileSpec(raw["cert_path"], cert_kind, "0644")]
    key_fmt = raw.get("key_format", "traditional")
    if raw.get("password_env") or raw.get("password_file"):
        if key_fmt not in ("traditional", "pkcs8"):
            raise SpecError("key_format 은 traditional(RSA PRIVATE KEY, 구형 OpenSSL 호환) 또는 pkcs8 이어야 합니다")
        files.append(FileSpec(raw["key_path"], "key_encrypted_traditional" if key_fmt == "traditional" else "key_encrypted", "0600",
                              raw.get("password_env"), raw.get("password_file")))
    else:
        files.append(FileSpec(raw["key_path"], "key", "0600"))
    if raw.get("chain_path"):
        files.append(FileSpec(raw["chain_path"], "chain", "0644"))
    return files


def _jeus(raw) -> List[FileSpec]:
    """JEUS: SSL 리스너가 읽는 키스토어(JKS 기본, PKCS12 가능). 키스토어 비밀번호는 JEUS 설정의 keypass 와 같아야 한다."""
    fmt = raw.get("format", "jks")
    if fmt not in ("jks", "pkcs12"):
        raise SpecError("jeus format 은 jks 또는 pkcs12 여야 합니다")
    if not raw.get("keystore_path"):
        raise SpecError("keystore_path 가 필요합니다")
    _need_password(raw)
    return [FileSpec(raw["keystore_path"], fmt, "0600", raw.get("password_env"), raw.get("password_file"),
                     raw.get("alias", "server"), bool(raw.get("legacy_pkcs12", False)))]


def build_files(raw: dict) -> List[FileSpec]:
    return _with_owner(_build_files(raw), raw)


def _build_files(raw: dict) -> List[FileSpec]:
    t = raw.get("type")
    if t == "webtob":
        return _webtob(raw)
    if t == "jeus":
        return _jeus(raw)
    if t in ("apache", "nginx", "nodejs"):
        return _pem_pair(raw)
    if t == "tomcat":
        fmt = raw.get("format", "pkcs12")
        if fmt == "pem":
            return _pem_pair(raw)
        if fmt not in ("pkcs12", "jks"):
            raise SpecError("tomcat format 은 pkcs12, jks, pem 중 하나여야 합니다")
        if not raw.get("keystore_path"):
            raise SpecError("keystore_path 가 필요합니다")
        _need_password(raw)
        return [FileSpec(raw["keystore_path"], fmt, "0600", raw.get("password_env"), raw.get("password_file"),
                         raw.get("alias", "tomcat"), bool(raw.get("legacy_pkcs12", False)))]
    if t == "generic":
        entries = raw.get("files")
        if not entries or not isinstance(entries, list):
            raise SpecError("generic 유형은 files 목록이 필요합니다")
        out = []
        for e in entries:
            c = e.get("content")
            if c not in CONTENT_KINDS or not e.get("path"):
                raise SpecError(f"files 항목에는 path 와 content({'/'.join(CONTENT_KINDS)})가 필요합니다")
            if c in PASSWORD_KINDS:
                _need_password(e)
            out.append(FileSpec(e["path"], c, str(e.get("mode", "0600" if c in KEY_KINDS else "0644")),
                                e.get("password_env"), e.get("password_file"), e.get("alias", "server"),
                                bool(e.get("legacy_pkcs12", False))))
        return out
    raise SpecError(f"알 수 없는 type: {t!r} ({', '.join(TYPES)})")


def default_check(raw: dict) -> Optional[str]:
    return {"apache": APACHE_CHECK, "nginx": "nginx -t"}.get(raw.get("type"))


def default_reload(raw: dict) -> Optional[str]:
    return {"apache": APACHE_RELOAD, "nginx": "systemctl reload nginx"}.get(raw.get("type"))
