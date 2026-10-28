"""설정 파일(YAML) 로드와 검증. 비밀번호·토큰은 설정에 쓰지 않고 환경변수 이름으로만 참조한다."""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import yaml

from .handlers import FileSpec, SpecError, build_files, default_check, default_reload

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
PATH_BAD = re.compile(r"[\x00-\x1f\n]")


class ConfigError(Exception):
    def __init__(self, problems: List[str]):
        super().__init__("설정 오류:\n- " + "\n- ".join(problems))
        self.problems = problems


@dataclass
class Verify:
    host: str
    port: int = 443
    sni: Optional[str] = None


@dataclass
class Target:
    name: str
    type: str
    transport: dict
    files: List[FileSpec]
    check_cmd: Optional[str]
    reload_cmd: Optional[str]
    verify: Optional[Verify]
    order: int = 100
    canary: bool = False


@dataclass
class Options:
    verify_attempts: int = 6
    verify_interval: float = 5.0
    keep_backups: int = 3
    min_days: float = 1.0
    command_timeout: int = 60


@dataclass
class Config:
    state_dir: str
    cert_file: str
    key_file: str
    key_password_env: Optional[str]
    targets: List[Target]
    options: Options = field(default_factory=Options)
    alertmanager_url: Optional[str] = None
    lego: Optional[dict] = None


def _abs(path, what, problems):
    if not isinstance(path, str) or not path.startswith("/") or PATH_BAD.search(path):
        problems.append(f"{what}: 절대 경로여야 합니다: {path!r}")


def parse_config(data: dict) -> Config:
    problems: List[str] = []
    if not isinstance(data, dict):
        raise ConfigError(["최상위가 매핑이 아닙니다"])
    cert = data.get("certificate") or {}
    lego = data.get("lego")
    cert_file, key_file = cert.get("cert_file"), cert.get("key_file")
    if lego and not (cert_file and key_file):
        from .issuer import lego_output_paths
        cert_file, key_file = lego_output_paths(lego)
    if not cert_file or not key_file:
        problems.append("certificate.cert_file / key_file 가 필요합니다(또는 lego 설정)")
    else:
        _abs(cert_file, "certificate.cert_file", problems)
        _abs(key_file, "certificate.key_file", problems)
    state_dir = data.get("state_dir", "/var/lib/certdeploy")
    _abs(state_dir, "state_dir", problems)

    opts = Options()
    for k, v in (data.get("options") or {}).items():
        if not hasattr(opts, k):
            problems.append(f"options.{k}: 알 수 없는 옵션")
        else:
            setattr(opts, k, type(getattr(opts, k))(v))

    targets, seen = [], set()
    for i, raw in enumerate(data.get("targets") or [], start=1):
        label = f"targets[{i}]"
        name = raw.get("name", "") if isinstance(raw, dict) else ""
        if not isinstance(raw, dict) or not NAME_RE.match(str(name)):
            problems.append(f"{label}: name 은 영문·숫자·._- 64자 이내여야 합니다")
            continue
        label = f"target {name}"
        if name in seen:
            problems.append(f"{label}: 이름이 중복됩니다")
        seen.add(name)
        tr = raw.get("transport") or {"kind": "local"}
        kind = tr.get("kind")
        if kind == "ssh":
            if not tr.get("host") or not HOST_RE.match(str(tr.get("host", ""))) or not tr.get("user"):
                problems.append(f"{label}: ssh transport 에는 host, user 가 필요합니다")
        elif kind != "local":
            problems.append(f"{label}: transport.kind 는 local 또는 ssh 여야 합니다")
        try:
            files = build_files(raw)
        except SpecError as e:
            problems.append(f"{label}: {e}")
            continue
        for f in files:
            _abs(f.dest, f"{label} 파일 경로", problems)
        check = raw.get("check_cmd", default_check(raw))
        reload_cmd = raw.get("reload_cmd", default_reload(raw))
        if raw["type"] in ("nodejs", "tomcat", "generic") and "reload_cmd" not in raw:
            problems.append(f"{label}: reload_cmd 가 필요합니다(없으면 'none' 으로 명시)")
        if str(reload_cmd).lower() == "none":
            reload_cmd = None
        if str(check).lower() == "none":
            check = None
        verify = None
        if raw.get("verify"):
            v = raw["verify"]
            if not v.get("host"):
                problems.append(f"{label}: verify.host 가 필요합니다")
            else:
                verify = Verify(v["host"], int(v.get("port", 443)), v.get("sni"))
        targets.append(Target(name, raw["type"], tr, files, check, reload_cmd, verify,
                              int(raw.get("order", 100)), bool(raw.get("canary", False))))
    if not targets:
        problems.append("targets 가 비어 있습니다")
    if problems:
        raise ConfigError(problems)
    return Config(state_dir, cert_file, key_file, cert.get("key_password_env"), targets, opts,
                  (data.get("notify") or {}).get("alertmanager_url"), lego)


def load_config(path: str) -> Config:
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except OSError as e:
        raise ConfigError([f"설정 파일을 읽을 수 없습니다: {e}"])
    except yaml.YAMLError as e:
        raise ConfigError([f"YAML 문법 오류: {e}"])
    return parse_config(data)
