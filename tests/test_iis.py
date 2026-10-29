"""Windows IIS 배포(SSH+PowerShell): 설정 검증·스크립트 생성(비밀 비노출·주입 방지)·배포/멱등/실패 복구/수동 롤백/preflight/CLI"""
import re

import pytest
import yaml
from click.testing import CliRunner

from certdeploy import iisdeploy
from certdeploy.bundle import load_bundle
from certdeploy.cli import main
from certdeploy.config import ConfigError, parse_config
from certdeploy.engine import Deployer
from certdeploy.notify import NullNotifier
from certdeploy.preflight import run_preflight
from certdeploy.state import State
from iis_fake import FakeWindows
from pki_helpers import make_pki

OLD = "A" * 40
KEY1 = "Default Web Site|443|"
KEY2 = "Portal|443|portal.hnu.kr"


class Rec(NullNotifier):
    def __init__(self):
        self.fired, self.resolved = [], []

    def fire(self, target, summary, description, severity="critical"):
        self.fired.append((target, description))

    def resolve(self, target):
        self.resolved.append(target)


def tcfg(**iis_over):
    iis = {"bindings": [{"site": "Default Web Site", "port": 443}, {"site": "Portal", "port": 443, "host_header": "portal.hnu.kr"}]}
    iis.update(iis_over)
    return {"name": "intra", "type": "iis", "transport": {"kind": "ssh", "host": "intra.hnu.kr", "user": "certdeploy"}, "iis": iis,
            "verify": {"host": "intra.hnu.kr", "port": 443}}


# ------------------------------------------------------------------ 설정 검증
def parse(t):
    return parse_config({"certificate": {"cert_file": "/a.crt", "key_file": "/a.key"}, "targets": [t]})


def test_valid_config_defaults():
    t = parse(tcfg()).targets[0]
    assert t.type == "iis" and t.iis["store"] == "My" and t.iis["powershell"] == "powershell" and t.iis["legacy_pkcs12"] is True
    assert t.iis["bindings"][1] == {"site": "Portal", "port": 443, "host_header": "portal.hnu.kr", "ip": "*"}


@pytest.mark.parametrize("mutate,msg", [
    (lambda t: t.pop("iis"), "iis 설정"),
    (lambda t: t["iis"].update(bindings=[]), "bindings"),
    (lambda t: t["iis"]["bindings"][0].update(site="a'; Remove-Item C:\\ #"), "site"),
    (lambda t: t["iis"]["bindings"][0].update(site="x\ny"), "site"),
    (lambda t: t["iis"]["bindings"][0].update(port=70000), "port"),
    (lambda t: t["iis"]["bindings"][0].update(port="443"), "port"),
    (lambda t: t["iis"]["bindings"][0].update(host_header="a b;c"), "host_header"),
    (lambda t: t["iis"]["bindings"][0].update(ip="1.2.3"), "ip"),
    (lambda t: t["iis"].update(store="My;calc"), "store"),
    (lambda t: t["iis"].update(powershell="cmd"), "powershell"),
    (lambda t: t["iis"].update(bogus=1), "알 수 없는 키"),
    (lambda t: t.update(transport={"kind": "local"}), "ssh transport"),
    (lambda t: t.pop("transport"), "ssh transport"),
])
def test_config_rejects(mutate, msg):
    t = tcfg()
    mutate(t)
    with pytest.raises(ConfigError, match=msg):
        parse(t)


# ------------------------------------------------------------------ 스크립트 생성
@pytest.fixture
def bundle(tmp_path):
    c, k, _, _ = make_pki(tmp_path, name="a", san=("intra.hnu.kr", "portal.hnu.kr"), days_to=90)
    return load_bundle(str(c), str(k))


def test_script_contains_expected_steps_and_no_command_line_secrets(bundle):
    iis = parse(tcfg()).targets[0].iis
    pw = iisdeploy.new_password()
    pfx = bundle.pkcs12(pw, "server", legacy=True)
    s = iisdeploy.build_deploy_script(iis, pfx, pw, iisdeploy.thumbprint(bundle))
    assert "Import-Module WebAdministration" in s and "AddSslCertificate" in s and "MachineKeySet" in s
    assert "ErrorActionPreference = 'Stop'" in s and "바인딩을 찾을 수 없거나" in s       # 없는 바인딩은 만들지 않고 실패
    cmd = iisdeploy.command(iis)
    assert pw not in cmd and "FromBase64" not in cmd and cmd.endswith("-Command -")        # 비밀은 stdin 으로만


def test_thumbprint_matches_sha1_of_certificate(bundle):
    from cryptography.hazmat.primitives import hashes
    assert iisdeploy.thumbprint(bundle) == bundle.leaf.fingerprint(hashes.SHA1()).hex().upper()  # nosec - 시험


def test_quote_escapes_single_quotes():
    assert iisdeploy._q("a'b") == "'a''b'"


def test_rollback_script_requires_valid_thumbprints():
    iis = parse(tcfg()).targets[0].iis
    with pytest.raises(iisdeploy.IisError):
        iisdeploy.build_rollback_script(iis, {KEY1: "xyz'; bad"})


def test_parse_output():
    out = "BIND|Default Web Site|443||aa11|BB22\nBIND|Portal|443|portal.hnu.kr||BB22\nOK\n"
    prev, done, ok, err = iisdeploy.parse_output(out)
    assert ok and err is None and prev[KEY1] == "AA11" and prev[KEY2] == "" and done == [KEY1, KEY2]
    assert iisdeploy.parse_output("BIND|x|443||AA|BB\nERR|실패 사유")[2:] == (False, "실패 사유")


# ------------------------------------------------------------------ 배포 흐름
class Env:
    def __init__(self, tmp, bundle, win, served=None):
        self.tmp, self.win = tmp, win
        self.cert, self.key = make_pki(tmp, "a", san=("intra.hnu.kr", "portal.hnu.kr"))[:2]
        self.served = served

    def deployer(self, rec=None, serial_after=True):
        cfg = parse_config({"certificate": {"cert_file": str(self.cert), "key_file": str(self.key)}, "state_dir": str(self.tmp / "state"),
                            "options": {"verify_attempts": 2, "verify_interval": 1}, "targets": [tcfg()]})
        b = load_bundle(str(self.cert), str(self.key))
        win = self.win

        def verifier(host, port, sni=None):
            cur = set(win.bindings.values())
            if iisdeploy.thumbprint(b) in cur and serial_after:
                return b.serial
            return 1                                                     # 이전 인증서(다른 일련번호)가 서빙됨
        return Deployer(cfg, b, State(cfg.state_dir).load(), transport_factory=lambda tr: win, verifier=verifier,
                        notifier=rec or Rec(), sleep=lambda s: None)


@pytest.fixture
def win():
    return FakeWindows({KEY1: OLD, KEY2: OLD}, {OLD})


@pytest.fixture
def env(tmp_path, win, bundle):
    return Env(tmp_path, bundle, win)


def test_deploy_binds_new_cert_and_records_previous(env, win):
    rec = Rec()
    (r,) = env.deployer(rec).deploy()
    assert r.status == "deployed", r.message
    thumb = iisdeploy.thumbprint(load_bundle(str(env.cert), str(env.key)))
    assert set(win.bindings.values()) == {thumb} and thumb in win.store and win.closed
    st = State(str(env.tmp / "state")).load().target("intra")
    assert st["iis_prev"] == {KEY1: OLD, KEY2: OLD} and st["status"] == "ok"
    assert rec.resolved == ["intra"]


def test_second_deploy_is_idempotent_skip(env, win):
    env.deployer().deploy()
    n = len(win.calls)
    (r,) = env.deployer().deploy()
    assert r.status == "skipped" and len(win.calls) == n          # 이미 새 인증서를 서빙 중이면 원격 명령을 보내지 않음


def test_bind_failure_midway_rolls_back_changed_bindings(env, win):
    win.fail_next_bind_after = 1                                   # 첫 바인딩만 바뀐 뒤 실패
    rec = Rec()
    (r,) = env.deployer(rec).deploy()
    assert r.status == "rolled_back" and "이전 인증서로 복구" in r.message
    assert win.bindings == {KEY1: OLD, KEY2: OLD}                  # 바뀐 바인딩이 이전 지문으로 복구됨
    assert rec.fired and State(str(env.tmp / "state")).load().target("intra")["status"] == "rolled_back"


def test_import_failure_has_nothing_to_roll_back(env, win):
    win.fail_on = "import"
    (r,) = env.deployer().deploy()
    assert r.status == "failed" and "Import 실패" in r.message and win.bindings == {KEY1: OLD, KEY2: OLD}


def test_verify_failure_after_bind_rolls_back(env, win):
    (r,) = env.deployer(serial_after=False).deploy()
    assert r.status == "rolled_back" and win.bindings == {KEY1: OLD, KEY2: OLD}


def test_rollback_failure_is_reported_as_manual_action(env, win):
    win.fail_next_bind_after = 1
    win.fail_on = None

    orig = win.run

    def run(cmd, stdin=None, timeout=60):
        if stdin and b"AddSslCertificate($old" in stdin:
            win.fail_on = "rollback"
        return orig(cmd, stdin, timeout)
    win.run = run
    (r,) = env.deployer().deploy()
    assert r.status == "failed" and "수동 조치 필요" in r.message


def test_missing_binding_fails_without_changes(tmp_path, bundle):
    win = FakeWindows({KEY1: OLD}, {OLD})                           # Portal 바인딩이 서버에 없음
    e = Env(tmp_path, bundle, win)
    (r,) = e.deployer().deploy()
    assert r.status in ("failed", "rolled_back") and "바인딩을 찾을 수 없" in r.message
    assert win.bindings == {KEY1: OLD}


def test_manual_rollback_command(env, win):
    env.deployer().deploy()
    d = env.deployer()
    r = d.rollback("intra")
    assert r.status == "rolled_back" and win.bindings == {KEY1: OLD, KEY2: OLD}
    assert d.rollback("intra").status == "failed"                   # 기록을 비웠으므로 두 번째는 되돌릴 것이 없음


def test_rollback_without_record_fails(env):
    assert env.deployer().rollback("intra").status == "failed"


def test_plan_and_validate_cover_san(env):
    lines = env.deployer().plan()
    assert any("IIS(SSH+PowerShell)" in line for line in lines) and any("Portal" in line for line in lines)
    assert env.deployer().validate_targets() == []


# ------------------------------------------------------------------ preflight / CLI / 문서
def test_preflight_reports_bindings_and_missing(env, win):
    checks = run_preflight(env.deployer())
    assert all(c.ok for c in checks) and any("현재 지문" in c.detail for c in checks)
    win.bindings.pop(KEY2)
    bad = [c for c in run_preflight(env.deployer()) if not c.ok]
    assert bad and "바인딩을 찾을 수 없" in bad[0].detail


def test_cli_validate_accepts_iis_config(tmp_path):
    c, k, _, _ = make_pki(tmp_path, name="a", san=("intra.hnu.kr", "portal.hnu.kr"))
    cfg = {"state_dir": str(tmp_path / "s"), "certificate": {"cert_file": str(c), "key_file": str(k)}, "targets": [tcfg()]}
    p = tmp_path / "c.yml"
    p.write_text(yaml.safe_dump(cfg, allow_unicode=True))
    r = CliRunner().invoke(main, ["-c", str(p), "plan"])
    assert r.exit_code == 0 and "IIS(SSH+PowerShell)" in r.output
    r2 = CliRunner().invoke(main, ["-c", str(p), "schema"])
    assert r2.exit_code == 0 and '"iis"' in r2.output


def test_fake_checks_pfx_really_opens(env, win):
    env.deployer().deploy()
    deploy_script = [s for s in win.scripts if "FromBase64String" in s][0]
    assert re.search(r"FromBase64String\('[A-Za-z0-9+/=]+'\)", deploy_script)


def test_example_config_parses():
    from pathlib import Path
    d = yaml.safe_load((Path(__file__).resolve().parent.parent / "certdeploy/certdeploy.iis.example.yml").read_text())
    t = parse_config(d).targets[0]
    assert t.type == "iis" and len(t.iis["bindings"]) == 2 and t.canary
