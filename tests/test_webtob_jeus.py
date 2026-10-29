"""WebtoB / JEUS 전용 유형: 설정 검증, 암호화 개인키(패스프레이즈), 소유자 지정, 키스토어, 재로드 실패 시 롤백"""
import getpass
import os
import stat

import pytest
import yaml
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from certdeploy.bundle import load_bundle
from certdeploy.cli import main
from certdeploy.config import ConfigError, parse_config
from certdeploy.engine import Deployer
from certdeploy.notify import NullNotifier
from certdeploy.state import State
from pki_helpers import make_pki

ME = getpass.getuser()


def cfg_of(target, tmp=None):
    return {"certificate": {"cert_file": "/a.crt", "key_file": "/a.key"}, "targets": [target]}


def webtob(tmp, **over):
    t = {"name": "wtb", "type": "webtob", "cert_path": str(tmp / "ssl/server.crt"), "key_path": str(tmp / "ssl/server.key"),
         "chain_path": str(tmp / "ssl/chain.crt"), "reload_cmd": "true"}
    t.update(over)
    return t


def jeus(tmp, **over):
    t = {"name": "jeus1", "type": "jeus", "keystore_path": str(tmp / "ssl/jeus.p12"), "format": "pkcs12", "password_env": "KS_PW", "reload_cmd": "true"}
    t.update(over)
    return t


# ------------------------------------------------------------------ 설정
def test_webtob_defaults(tmp_path):
    t = parse_config(cfg_of(webtob(tmp_path))).targets[0]
    kinds = {f.dest.rsplit("/", 1)[1]: (f.content, f.mode) for f in t.files}
    assert kinds == {"server.crt": ("cert", "0644"), "server.key": ("key", "0600"), "chain.crt": ("chain", "0644")}
    assert t.reload_cmd == "true"


def test_webtob_encrypted_key_options(tmp_path):
    f = {x.dest.rsplit("/", 1)[1]: x for x in parse_config(cfg_of(webtob(tmp_path, password_env="WTB_PW"))).targets[0].files}
    assert f["server.key"].content == "key_encrypted_traditional" and f["server.key"].password_env == "WTB_PW"
    g = {x.dest.rsplit("/", 1)[1]: x for x in parse_config(cfg_of(webtob(tmp_path, password_env="WTB_PW", key_format="pkcs8"))).targets[0].files}
    assert g["server.key"].content == "key_encrypted"
    h = parse_config(cfg_of(webtob(tmp_path, cert_content="fullchain", owner="webtob:webtob"))).targets[0].files
    assert h[0].content == "fullchain" and all(x.owner == "webtob:webtob" for x in h)


@pytest.mark.parametrize("mutate,msg", [
    (lambda t: t.pop("reload_cmd"), "reload_cmd"),
    (lambda t: t.pop("cert_path"), "cert_path"),
    (lambda t: t.pop("key_path"), "key_path"),
    (lambda t: t.update(owner="root; rm -rf /"), "owner"),
    (lambda t: t.update(owner="Web Tob"), "owner"),
    (lambda t: t.update(cert_content="key"), "cert_content"),
    (lambda t: t.update(password_env="X", key_format="des"), "key_format"),
    (lambda t: t.update(cert_path="relative.crt"), "절대 경로"),
])
def test_webtob_config_errors(tmp_path, mutate, msg):
    t = webtob(tmp_path)
    mutate(t)
    with pytest.raises(ConfigError, match=msg):
        parse_config(cfg_of(t))


def test_jeus_config(tmp_path):
    t = parse_config(cfg_of(jeus(tmp_path))).targets[0]
    assert (t.files[0].content, t.files[0].mode, t.files[0].alias) == ("pkcs12", "0600", "server")
    assert parse_config(cfg_of(jeus(tmp_path, format="jks", alias="jeus"))).targets[0].files[0].content == "jks"
    for mutate, msg in ((lambda t: t.pop("password_env"), "password_env"), (lambda t: t.update(format="pem"), "jks 또는 pkcs12"),
                        (lambda t: t.pop("keystore_path"), "keystore_path"), (lambda t: t.pop("reload_cmd"), "reload_cmd")):
        t = jeus(tmp_path)
        mutate(t)
        with pytest.raises(ConfigError, match=msg):
            parse_config(cfg_of(t))


def test_generic_accepts_encrypted_key_kind_with_password_requirement():
    base = {"name": "g", "type": "generic", "reload_cmd": "true", "files": [{"path": "/s/k.pem", "content": "key_encrypted"}]}
    with pytest.raises(ConfigError, match="password"):
        parse_config(cfg_of(base))
    base["files"][0]["password_env"] = "P"
    assert parse_config(cfg_of(base)).targets[0].files[0].content == "key_encrypted"


# ------------------------------------------------------------------ 배포(로컬 전송)
class Env:
    def __init__(self, tmp, target, environ):
        self.tmp = tmp
        (tmp / "ssl").mkdir(exist_ok=True)
        self.cert, self.key = make_pki(tmp, "a", san=("web.hnu.kr",))[:2]
        self.target, self.environ = target, environ

    def deployer(self, rec=None):
        cfg = parse_config({"certificate": {"cert_file": str(self.cert), "key_file": str(self.key)}, "state_dir": str(self.tmp / "state"),
                            "options": {"verify_attempts": 1, "verify_interval": 0}, "targets": [self.target]})
        return Deployer(cfg, load_bundle(str(self.cert), str(self.key)), State(cfg.state_dir).load(), notifier=rec or NullNotifier(),
                        sleep=lambda s: None, environ=self.environ)


def test_webtob_deploy_plain_key(tmp_path):
    e = Env(tmp_path, webtob(tmp_path, owner=ME), {})
    (r,) = e.deployer().deploy()
    assert r.status == "deployed", r.message
    s = tmp_path / "ssl"
    b = load_bundle(str(e.cert), str(e.key))
    assert (s / "server.crt").read_bytes() == b.cert_pem() and (s / "chain.crt").read_bytes() == b.chain_pem()
    assert stat.S_IMODE((s / "server.key").stat().st_mode) == 0o600 and stat.S_IMODE((s / "server.crt").stat().st_mode) == 0o644
    assert (s / "server.key").stat().st_uid == os.getuid()


@pytest.mark.parametrize("fmt,header", [("traditional", b"BEGIN RSA PRIVATE KEY"), ("pkcs8", b"BEGIN ENCRYPTED PRIVATE KEY")])
def test_webtob_deploy_encrypted_key(tmp_path, fmt, header):
    e = Env(tmp_path, webtob(tmp_path, password_env="WTB_PW", key_format=fmt), {"WTB_PW": "pass-Phrase-1"})
    (r,) = e.deployer().deploy()
    assert r.status == "deployed", r.message
    data = (tmp_path / "ssl/server.key").read_bytes()
    assert header in data and b"ENCRYPTED" in data
    key = serialization.load_pem_private_key(data, b"pass-Phrase-1")
    assert key.public_key().public_numbers() == load_bundle(str(e.cert), str(e.key)).key.public_key().public_numbers()
    with pytest.raises(Exception):
        serialization.load_pem_private_key(data, b"wrong")


def test_missing_passphrase_is_reported_before_deploy(tmp_path):
    e = Env(tmp_path, webtob(tmp_path, password_env="WTB_PW"), {})
    assert any("WTB_PW" in p for p in e.deployer().validate_targets())
    (r,) = e.deployer().deploy()
    assert r.status == "failed" and not (tmp_path / "ssl/server.key").exists() and not (tmp_path / "ssl/server.crt").exists()   # 인증서도 설치되지 않음


def test_jeus_pkcs12_deploy(tmp_path):
    e = Env(tmp_path, jeus(tmp_path, owner=ME), {"KS_PW": "ks-Pass-1"})
    (r,) = e.deployer().deploy()
    assert r.status == "deployed", r.message
    key, cert, _ = pkcs12.load_key_and_certificates((tmp_path / "ssl/jeus.p12").read_bytes(), b"ks-Pass-1")
    assert cert.serial_number == load_bundle(str(e.cert), str(e.key)).serial
    assert stat.S_IMODE((tmp_path / "ssl/jeus.p12").stat().st_mode) == 0o600


def test_reload_failure_restores_previous_files(tmp_path):
    e = Env(tmp_path, webtob(tmp_path), {})
    s = tmp_path / "ssl"
    for n in ("server.crt", "server.key", "chain.crt"):
        (s / n).write_text("OLD-" + n)
    e.target["reload_cmd"] = "false"
    (r,) = e.deployer().deploy()
    assert r.status == "rolled_back"
    assert (s / "server.crt").read_text() == "OLD-server.crt" and (s / "server.key").read_text() == "OLD-server.key"


def test_invalid_owner_fails_and_rolls_back(tmp_path):
    e = Env(tmp_path, webtob(tmp_path, owner="no_such_user_xyz"), {})
    s = tmp_path / "ssl"
    (s / "server.crt").write_text("OLD")
    (r,) = e.deployer().deploy()
    assert r.status in ("failed", "rolled_back") and "파일 교체 실패" in r.message
    assert (s / "server.crt").read_text() == "OLD"


def test_plan_shows_owner_and_cli(tmp_path):
    e = Env(tmp_path, webtob(tmp_path, owner="webtob:webtob"), {})
    assert any("소유자 webtob:webtob" in line for line in e.deployer().plan())
    c, k = make_pki(tmp_path, "b", san=("web.hnu.kr",))[:2]
    p = tmp_path / "c.yml"
    p.write_text(yaml.safe_dump({"state_dir": str(tmp_path / "s"), "certificate": {"cert_file": str(c), "key_file": str(k)}, "targets": [webtob(tmp_path)]}))
    r = CliRunner().invoke(main, ["-c", str(p), "plan"])
    assert r.exit_code == 0 and "webtob" in r.output


def test_example_config_parses():
    from pathlib import Path
    d = yaml.safe_load((Path(__file__).resolve().parent.parent / "certdeploy/certdeploy.webtob-jeus.example.yml").read_text())
    cfg = parse_config(d)
    assert {t.type for t in cfg.targets} == {"webtob", "jeus"}
