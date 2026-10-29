"""Windows IIS 배포: SSH(Windows OpenSSH) + PowerShell 로 인증서를 LocalMachine 저장소에 가져오고 사이트 바인딩에 연결한다.

- 서버에 에이전트를 두지 않는다. Windows 에는 OpenSSH Server 와 배포용 계정(관리자 권한)만 필요하다.
- PFX(일회용 임시 비밀번호)와 스크립트는 SSH 표준 입력(stdin)으로만 전달된다 — 명령행·로그·디스크에 남기지 않는다.
- 바인딩마다 이전 인증서 지문을 읽어 두었다가 실패 시 되돌린다. 사이트/바인딩이 없으면 만들지 않고 실패한다.
"""
import base64
import hashlib
import re
import secrets
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import serialization

SITE_RE = re.compile(r"^[A-Za-z0-9가-힣][A-Za-z0-9가-힣 ._()\-]{0,127}$")
HOST_HEADER_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$")
IP_RE = re.compile(r"^(\*|(\d{1,3}\.){3}\d{1,3})$")
STORE_RE = re.compile(r"^[A-Za-z]{1,32}$")
THUMB_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
PS_RE = re.compile(r"^(powershell|pwsh)(\.exe)?$")


class IisError(Exception):
    pass


def validate_iis(raw, label: str, problems: List[str]) -> Optional[dict]:
    if not isinstance(raw, dict):
        problems.append(f"{label}: type: iis 에는 iis 설정(bindings)이 필요합니다")
        return None
    unknown = set(raw) - {"bindings", "store", "powershell", "legacy_pkcs12"}
    if unknown:
        problems.append(f"{label}: iis 의 알 수 없는 키: {', '.join(sorted(unknown))}")
    out = {"store": str(raw.get("store", "My")), "powershell": str(raw.get("powershell", "powershell")),
           "legacy_pkcs12": bool(raw.get("legacy_pkcs12", True)), "bindings": []}
    if not STORE_RE.match(out["store"]):
        problems.append(f"{label}: iis.store 형식이 올바르지 않습니다")
    if not PS_RE.match(out["powershell"]):
        problems.append(f"{label}: iis.powershell 은 powershell 또는 pwsh 여야 합니다")
    binds = raw.get("bindings")
    if not isinstance(binds, list) or not binds:
        problems.append(f"{label}: iis.bindings 가 필요합니다(예: - {{site: Default Web Site, port: 443}})")
        return None
    ok = True
    for i, b in enumerate(binds, 1):
        if not isinstance(b, dict):
            problems.append(f"{label}: iis.bindings[{i}] 는 매핑이어야 합니다")
            ok = False
            continue
        site, port, hh, ip = str(b.get("site", "")), b.get("port", 443), str(b.get("host_header", "") or ""), str(b.get("ip", "*"))
        if not SITE_RE.match(site):
            problems.append(f"{label}: iis.bindings[{i}].site 형식이 올바르지 않습니다(사이트 이름만; 따옴표·세미콜론 불가)")
            ok = False
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            problems.append(f"{label}: iis.bindings[{i}].port 는 1~65535 정수여야 합니다")
            ok = False
        if hh and not HOST_HEADER_RE.match(hh):
            problems.append(f"{label}: iis.bindings[{i}].host_header 형식이 올바르지 않습니다")
            ok = False
        if not IP_RE.match(ip):
            problems.append(f"{label}: iis.bindings[{i}].ip 는 * 또는 IPv4 여야 합니다")
            ok = False
        out["bindings"].append({"site": site, "port": port, "host_header": hh, "ip": ip})
    return out if ok else None


def thumbprint(bundle) -> str:
    return hashlib.sha1(bundle.leaf.public_bytes(serialization.Encoding.DER), usedforsecurity=False).hexdigest().upper()  # nosec B324 - 윈도우 인증서 식별자(지문)


def _q(s: str) -> str:
    """PowerShell 작은따옴표 문자열 리터럴(입력은 위 정규식으로 이미 제한됨)"""
    return "'" + str(s).replace("'", "''") + "'"


def _bind_list(iis: dict, prev: Optional[dict] = None) -> str:
    rows = []
    for b in iis["bindings"]:
        key = binding_key(b)
        rows.append("@(" + ",".join(_q(x) for x in (b["site"], str(b["port"]), b["host_header"], b["ip"], (prev or {}).get(key, ""))) + ")")
    return "@(" + ",".join(rows) + ")"


def binding_key(b: dict) -> str:
    return f"{b['site']}|{b['port']}|{b['host_header']}"


_PRELUDE = """$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
Import-Module WebAdministration
"""

_FIND = """  $found = @(Get-WebBinding -Name $site -Protocol https -Port $port | Where-Object {
    $p = $_.bindingInformation.Split(':'); ($p[2] -eq $hh) -and (($ip -eq '*' -and $p[0] -eq '*') -or $p[0] -eq $ip) })
  if ($found.Count -ne 1) { throw ('바인딩을 찾을 수 없거나 여러 개입니다: ' + $site + ' ' + $port + ' ' + $hh) }
  $b = $found[0]
"""

_TAIL = """Write-Output 'OK'
} catch {
Write-Output ('ERR|' + ($_.Exception.Message -replace '[\\r\\n]+', ' '))
exit 1
}
exit 0
"""


def build_deploy_script(iis: dict, pfx: bytes, password: str, thumb: str) -> str:
    """PFX 를 저장소에 넣고 바인딩에 연결한다. 출력: BIND|사이트|포트|호스트헤더|이전지문|새지문 ... OK"""
    return (_PRELUDE
            + f"$bytes = [Convert]::FromBase64String({_q(base64.b64encode(pfx).decode())})\n"
            + f"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($bytes, {_q(password)}, 'MachineKeySet,PersistKeySet')\n"
            + f"if ($cert.Thumbprint -ne {_q(thumb)}) {{ throw '가져온 인증서 지문이 예상과 다릅니다' }}\n"
            + f"$store = New-Object System.Security.Cryptography.X509Certificates.X509Store({_q(iis['store'])}, 'LocalMachine')\n"
            + "$store.Open('ReadWrite'); $store.Add($cert); $store.Close()\n"
            + f"foreach ($row in {_bind_list(iis)}) {{\n  $site = $row[0]; $port = [int]$row[1]; $hh = $row[2]; $ip = $row[3]\n"
            + _FIND
            + "  $prev = [string]$b.certificateHash\n"
            + f"  $b.AddSslCertificate({_q(thumb)}, {_q(iis['store'])})\n"
            + f"  Write-Output ('BIND|' + $site + '|' + $port + '|' + $hh + '|' + $prev + '|' + {_q(thumb)})\n}}\n"
            + _TAIL)


def build_rollback_script(iis: dict, prev: dict) -> str:
    """바인딩을 이전 지문으로 되돌린다(이전 지문이 저장소에 없으면 해당 바인딩은 실패로 보고)."""
    for v in prev.values():
        if v and not THUMB_RE.match(v):
            raise IisError("이전 인증서 지문 형식이 올바르지 않습니다")
    return (_PRELUDE
            + f"foreach ($row in {_bind_list(iis, prev)}) {{\n  $site = $row[0]; $port = [int]$row[1]; $hh = $row[2]; $ip = $row[3]; $old = $row[4]\n"
            + "  if (-not $old) { throw ('이전 지문 기록이 없어 되돌릴 수 없습니다: ' + $site) }\n"
            + f"  if (-not (Test-Path ('Cert:\\LocalMachine\\' + {_q(iis['store'])} + '\\' + $old))) {{ throw ('이전 인증서가 저장소에 없습니다: ' + $old) }}\n"
            + _FIND
            + f"  $b.AddSslCertificate($old, {_q(iis['store'])})\n"
            + "  Write-Output ('REVERT|' + $site + '|' + $port + '|' + $hh + '|' + $old)\n}\n"
            + _TAIL)


def build_inspect_script(iis: dict) -> str:
    """읽기 전용 점검: 모듈·바인딩 존재 확인과 현재 지문 출력(preflight 용)"""
    return (_PRELUDE
            + f"foreach ($row in {_bind_list(iis)}) {{\n  $site = $row[0]; $port = [int]$row[1]; $hh = $row[2]; $ip = $row[3]\n"
            + _FIND
            + "  Write-Output ('BIND|' + $site + '|' + $port + '|' + $hh + '|' + [string]$b.certificateHash)\n}\n"
            + _TAIL)


def command(iis: dict) -> str:
    """표준 입력으로 스크립트를 읽어 실행(파일을 만들지 않는다)"""
    return f"{iis['powershell']} -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -"


def parse_output(out: str) -> Tuple[dict, List[str], bool, Optional[str]]:
    """(바인딩별 이전 지문, 변경된 바인딩 키 목록, OK 여부, 오류 메시지)"""
    prev, done, ok, err = {}, [], False, None
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith("BIND|"):
            parts = line.split("|")
            if len(parts) >= 5:
                key = "|".join(parts[1:4])
                prev[key] = parts[4].upper()
                done.append(key)
        elif line.startswith("ERR|"):
            err = line[4:]
        elif line == "OK":
            ok = True
    return prev, done, ok, err


def new_password() -> str:
    return secrets.token_urlsafe(18)


def plan_lines(iis: dict) -> List[str]:
    out = [f"    IIS(SSH+PowerShell): LocalMachine\\{iis['store']} 에 PFX 가져오기 → 바인딩 연결(실패 시 이전 지문으로 복구)"]
    for b in iis["bindings"]:
        out.append(f"      바인딩 {b['site']} {b['ip']}:{b['port']}" + (f" ({b['host_header']}, SNI)" if b["host_header"] else ""))
    return out
