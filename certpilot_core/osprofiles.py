"""OS 계열별 인증서 표준 경로 프로필 (PRD §3.1.4 Q-PATH: 표준 경로 자동 탐지 + 서버별 예외).

경로는 '미리 정의된 후보의 존재 여부만 확인'하는 목록이며 find/전체 탐색은 하지 않는다 (B-6).
OS 를 '자동 감지'로 두면 /etc/os-release 의 ID/ID_LIKE 로 계열을 판별하고, 판별 못 하면 모든 계열의 합집합(generic)을 쓴다.
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

OS_RELEASE = "/etc/os-release"
# OS 가 기본으로 설치하는 CA 번들(심볼릭 링크 포함) — 서버 인증서가 아니므로 조회 대상에서 제외
SYSTEM_CA_FILES = {"ca-bundle.crt", "ca-bundle.trust.crt", "ca-certificates.crt", "cert.pem", "ca-bundle.pem",
                   "tls-ca-bundle.pem", "ca-bundle.trust.p12", "java"}


@dataclass(frozen=True)
class OSProfile:
    id: str
    label: str
    candidates: Tuple[str, ...]        # 자동 조회하는 표준 경로 (파일 또는 디렉터리)
    webcfg_files: Tuple[str, ...]      # 인증서 경로를 추출할 웹 서버 설정 파일
    webcfg_dirs: Tuple[str, ...]       # 위와 같은 설정 디렉터리(파일 최대 20개)
    roots: Tuple[str, ...]             # 설정에서 추출한 경로가 '표준 위치 안'인지 판단하는 루트

    def whitelist(self) -> List[str]:
        """이 프로필로 접속할 때 원격 명령이 접근할 수 있는 경로 (후보 + 설정 + 루트 + os-release)"""
        seen: List[str] = []
        for p in (*self.candidates, *self.webcfg_files, *self.webcfg_dirs, *self.roots, OS_RELEASE):
            if p not in seen:
                seen.append(p)
        return seen


DEBIAN = OSProfile(
    "debian", "Ubuntu / Debian 계열",
    ("/etc/nginx/ssl", "/etc/apache2/ssl", "/etc/letsencrypt/live", "/etc/ssl/local",
     "/usr/local/share/ca-certificates"),
    ("/etc/nginx/nginx.conf", "/etc/apache2/apache2.conf"),
    ("/etc/nginx/conf.d", "/etc/nginx/sites-enabled", "/etc/apache2/sites-enabled", "/etc/apache2/conf-enabled"),
    ("/etc/ssl", "/etc/letsencrypt", "/etc/nginx", "/etc/apache2", "/opt", "/usr/local/share/ca-certificates"))

RHEL = OSProfile(
    "rhel", "RHEL / CentOS / Rocky / Alma / Fedora / Amazon Linux 계열",
    ("/etc/pki/tls/certs", "/etc/pki/nginx", "/etc/nginx/ssl", "/etc/httpd/conf/ssl", "/etc/httpd/ssl",
     "/etc/letsencrypt/live", "/etc/pki/ca-trust/source/anchors"),
    ("/etc/nginx/nginx.conf", "/etc/httpd/conf/httpd.conf"),
    ("/etc/nginx/conf.d", "/etc/httpd/conf.d"),
    ("/etc/pki", "/etc/ssl", "/etc/letsencrypt", "/etc/nginx", "/etc/httpd", "/opt"))

SUSE = OSProfile(
    "suse", "SUSE / openSUSE 계열",
    ("/etc/apache2/ssl.crt", "/etc/nginx/ssl", "/etc/ssl/servercerts", "/etc/letsencrypt/live",
     "/etc/pki/trust/anchors"),
    ("/etc/nginx/nginx.conf", "/etc/apache2/httpd.conf"),
    ("/etc/nginx/vhosts.d", "/etc/apache2/vhosts.d", "/etc/apache2/conf.d"),
    ("/etc/ssl", "/etc/pki", "/etc/apache2", "/etc/nginx", "/etc/letsencrypt", "/opt"))

ALPINE = OSProfile(
    "alpine", "Alpine Linux",
    ("/etc/nginx/ssl", "/etc/apache2/ssl", "/etc/letsencrypt/live", "/usr/local/share/ca-certificates"),
    ("/etc/nginx/nginx.conf", "/etc/apache2/httpd.conf"),
    ("/etc/nginx/http.d", "/etc/nginx/conf.d", "/etc/apache2/conf.d"),
    ("/etc/ssl", "/etc/nginx", "/etc/apache2", "/etc/letsencrypt", "/usr/local/share/ca-certificates", "/opt"))


def _union(profiles) -> OSProfile:
    def merge(attr):
        out: List[str] = []
        for p in profiles:
            out += [x for x in getattr(p, attr) if x not in out]
        return tuple(out)
    return OSProfile("generic", "기타 Linux (모든 계열 경로 확인)", merge("candidates"), merge("webcfg_files"),
                     merge("webcfg_dirs"), merge("roots"))


GENERIC = _union([DEBIAN, RHEL, SUSE, ALPINE])
PROFILES: Dict[str, OSProfile] = {p.id: p for p in (DEBIAN, RHEL, SUSE, ALPINE, GENERIC)}
AUTO = "auto"
VALID_OS_TYPES = (AUTO, *PROFILES.keys())

_FAMILY_IDS = {
    "debian": {"debian", "ubuntu", "linuxmint", "raspbian", "kali", "pop"},
    "rhel": {"rhel", "centos", "fedora", "rocky", "almalinux", "amzn", "ol", "scientific", "anolis", "centos-stream"},
    "suse": {"suse", "sles", "sled", "opensuse", "opensuse-leap", "opensuse-tumbleweed"},
    "alpine": {"alpine"},
}


def parse_os_release(text: str) -> Dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.match(r'^([A-Z_]+)=(.*)$', line.strip())
        if m:
            out[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    return out


def detect_profile(os_release_text: str) -> Tuple[OSProfile, Optional[str]]:
    """os-release 내용 → (프로필, 표시용 OS 이름). 판별 불가면 generic."""
    info = parse_os_release(os_release_text or "")
    name = info.get("PRETTY_NAME") or info.get("NAME")
    tokens = {info.get("ID", "").lower(), *info.get("ID_LIKE", "").lower().split()}
    for family, ids in _FAMILY_IDS.items():
        if tokens & ids:
            return PROFILES[family], name
    return GENERIC, name


def list_profiles() -> List[dict]:
    return [{"id": AUTO, "label": "자동 감지 (권장)", "candidates": []}] + \
           [{"id": p.id, "label": p.label, "candidates": list(p.candidates)} for p in PROFILES.values()]
