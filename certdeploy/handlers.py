"""서비스 유형별 배포 파일 명세와 기본 점검·재로드 명령.

apache / nginx / nodejs / tomcat 은 관례적인 기본값을 제공하고, WebtoB·JEUS·그 밖의 제품은 `generic`
유형으로 파일 목록과 명령을 직접 지정한다(제품별 경로·명령은 제품 문서로 확인해 설정에 적는다).
"""
from dataclasses import dataclass
from typing import List, Optional

CONTENT_KINDS = ("cert", "fullchain", "chain", "key", "pkcs12", "jks")
KEY_KINDS = ("key", "pkcs12", "jks")        # 개인키가 들어 있어 0600 으로 다룬다

APACHE_CHECK = ("if command -v apachectl >/dev/null 2>&1; then apachectl configtest; "
                "elif command -v httpd >/dev/null 2>&1; then httpd -t; else apache2ctl configtest; fi")
APACHE_RELOAD = "systemctl reload httpd 2>/dev/null || systemctl reload apache2"

TYPES = ("apache", "nginx", "nodejs", "tomcat", "generic")


@dataclass
class FileSpec:
    dest: str
    content: str                        # CONTENT_KINDS 중 하나
    mode: str = "0644"
    password_env: Optional[str] = None  # pkcs12/jks 비밀번호를 담은 환경변수 이름
    password_file: Optional[str] = None  # 또는 비밀번호를 담은 파일(권한 600, 예: systemd credentials)
    alias: str = "server"
    legacy_pkcs12: bool = False         # 구형 JVM 용 PKCS#12(3DES)


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


def build_files(raw: dict) -> List[FileSpec]:
    t = raw.get("type")
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
            if c in ("pkcs12", "jks"):
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
