"""선택 기능: 개인키 암호화 옵션(암호 사용/미사용 모두), 수동 교체 대상(type: manual), 알림 시험(notify-test)."""
import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization

from certdeploy import manual as mn
from certdeploy.bundle import load_bundle
from certdeploy.cli import main
from certdeploy.config import ConfigError, parse_config
from certdeploy.engine import Deployer
from certdeploy.notify import NullNotifier
from certdeploy.runlog import build_report, metrics_text, report_markdown
from certdeploy.state import State
from certdeploy.transport import LocalTransport
from pki_helpers import make_pki, sign_csr
from test_certdeploy_acme import base_cfg, cd as acme_cd, env as acme_env  # noqa: F401  (가짜 CA/DNS 환경 재사용)

@pytest.fixture(autouse=True)
def _fresh_tracer():
    from certpilot_core import trace
    trace.TRACER.configure(path="", echo=None)          # CLI 가 설정 파일별로 트레이스 경로를 다시 잡도록
    trace.run_id_var.set(None)
    yield


PW = "key-pass-123456"
DOMAINS = ["*.hnu.kr", "hnu.kr"]


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def pem(c):
    return c.public_bytes(serialization.Encoding.PEM)


# ------------------------------------------------------------------ 개인키 암호화 옵션
@pytest.fixture
def kenv(tmp_path):
    ca = {}
    make_pki(tmp_path, "seed", shared_ca=ca)
    web = tmp_path / "web"
    web.mkdir()

    def write(encryption, with_env=True):
        cert = {"cert_file": str(tmp_path / "managed" / "w.crt"), "key_file": str(tmp_path / "managed" / "w.key")}
        if encryption == "passphrase" or with_env:
            cert["key_password_env"] = "KEYPW"
        if encryption:
            cert["key_encryption"] = encryption
        cfg = {"state_dir": str(tmp_path / "state"), "certificate": cert,
               "targets": [{"name": "w1", "type": "generic", "check_cmd": "true", "reload_cmd": "true",
                            "files": [{"path": str(web / "s.crt"), "content": "fullchain"}, {"path": str(web / "s.key"), "content": "key"}]}]}
        p = tmp_path / "cd.yml"
        p.write_text(yaml.safe_dump(cfg))
        return str(p)

    def issue_files():
        key_pem, csr_pem = mn.generate_csr(DOMAINS)
        (tmp_path / "k.key").write_bytes(key_pem)
        (tmp_path / "s.cer").write_bytes(pem(sign_csr(csr_pem, ca)) + pem(ca["inter"]))

    return type("K", (), {"tmp": tmp_path, "ca": ca, "web": web, "write": staticmethod(write), "issue": staticmethod(issue_files)})


def run(cfg, *args, env=None):
    return CliRunner().invoke(main, ["-c", cfg, *args], env=env, catch_exceptions=False)


def test_encryption_off_keeps_plain_key_and_is_the_default(kenv):
    cfg = kenv.write(None, with_env=False)
    kenv.issue()
    assert run(cfg, "import", "--file", str(kenv.tmp / "s.cer"), "--key-file", str(kenv.tmp / "k.key")).exit_code == 0
    key = kenv.tmp / "managed" / "w.key"
    assert key.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----") and mode(key) == 0o600
    v = run(cfg, "validate")
    assert v.exit_code == 0 and "평문(권한 600으로 보호)" in v.output and "key_encryption=none" in v.output


def test_encryption_on_stores_encrypted_key_and_deploys_plain_to_targets(kenv):
    cfg = kenv.write("passphrase")
    kenv.issue()
    r = run(cfg, "import", "--file", str(kenv.tmp / "s.cer"), "--key-file", str(kenv.tmp / "k.key"), "--deploy", env={"KEYPW": PW})
    assert r.exit_code == 0, r.output
    stored = (kenv.tmp / "managed" / "w.key").read_bytes()
    assert stored.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") and mode(kenv.tmp / "managed" / "w.key") == 0o600
    deployed = (kenv.web / "s.key").read_bytes()                              # 대상 서버 파일은 평문이어야 웹서버가 읽는다
    assert deployed.startswith(b"-----BEGIN PRIVATE KEY-----") and mode(kenv.web / "s.key") == 0o600
    assert serialization.load_pem_private_key(stored, PW.encode()).private_numbers() == serialization.load_pem_private_key(deployed, None).private_numbers()
    v = run(cfg, "validate", env={"KEYPW": PW})
    assert v.exit_code == 0 and "암호화됨(KEYPW)" in v.output


def test_encryption_on_requires_password_env_everywhere(kenv):
    cfg = kenv.write("passphrase")
    kenv.issue()
    r = run(cfg, "import", "--file", str(kenv.tmp / "s.cer"), "--key-file", str(kenv.tmp / "k.key"))
    assert r.exit_code != 0 and "개인키 암호화가 켜져 있습니다" in r.output and "KEYPW" in r.output
    run(cfg, "import", "--file", str(kenv.tmp / "s.cer"), "--key-file", str(kenv.tmp / "k.key"), env={"KEYPW": PW})
    bad = run(cfg, "validate", env={"KEYPW": "wrong-password-xx"})
    assert bad.exit_code == 2 and "암호 불일치" in bad.output
    nopw = run(cfg, "deploy")
    assert nopw.exit_code != 0 and "KEYPW" in nopw.output


def test_csr_pending_key_is_encrypted_and_import_uses_it(kenv):
    cfg = kenv.write("passphrase")
    assert run(cfg, "csr", "--domains", ",".join(DOMAINS), env={"KEYPW": PW}).exit_code == 0
    pending = kenv.tmp / "state" / "pending" / "default" / "key.pem"
    assert pending.read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    csr = (kenv.tmp / "state" / "pending" / "default" / "default.csr").read_bytes()
    (kenv.tmp / "s.cer").write_bytes(pem(sign_csr(csr, kenv.ca)) + pem(kenv.ca["inter"]))
    r = run(cfg, "import", "--file", str(kenv.tmp / "s.cer"), env={"KEYPW": PW})
    assert r.exit_code == 0 and not pending.exists()
    assert (kenv.tmp / "managed" / "w.key").read_bytes().startswith(b"-----BEGIN ENCRYPTED")


def test_key_encrypt_and_decrypt_roundtrip_with_backup(kenv):
    cfg = kenv.write(None, with_env=True)                          # 처음엔 평문 + 암호 환경변수 이름만 준비
    kenv.issue()
    run(cfg, "import", "--file", str(kenv.tmp / "s.cer"), "--key-file", str(kenv.tmp / "k.key"))
    key = kenv.tmp / "managed" / "w.key"
    plain = key.read_bytes()
    assert run(cfg, "key-encrypt").exit_code != 0                  # 암호 환경변수 없이는 거부
    r = run(cfg, "key-encrypt", env={"KEYPW": PW})
    assert r.exit_code == 0 and "key_encryption: passphrase" in r.output and key.read_bytes().startswith(b"-----BEGIN ENCRYPTED")
    baks = [p for p in os.listdir(kenv.tmp / "managed") if ".key.bak-" in p]
    assert baks and mode(kenv.tmp / "managed" / baks[0]) == 0o600 and (kenv.tmp / "managed" / baks[0]).read_bytes() == plain
    assert "이미 암호화" in run(cfg, "key-encrypt", env={"KEYPW": PW}).output
    # 설정과 실제 파일 상태가 다르면 validate 가 알려 준다
    v = run(cfg, "validate", env={"KEYPW": PW})
    assert v.exit_code == 1 and "key-encrypt" not in v.output.split("문제:")[0] and "key-decrypt" in v.output
    d = run(cfg, "key-decrypt", env={"KEYPW": PW})
    assert d.exit_code == 0 and key.read_bytes() == plain
    assert run(cfg, "key-decrypt", env={"KEYPW": "wrong-password-xx"}).exit_code == 0     # 이미 평문이면 변경 없음(오류 아님)


def test_key_decrypt_with_wrong_password_fails_without_touching_file(kenv):
    cfg = kenv.write("passphrase")
    kenv.issue()
    run(cfg, "import", "--file", str(kenv.tmp / "s.cer"), "--key-file", str(kenv.tmp / "k.key"), env={"KEYPW": PW})
    key = kenv.tmp / "managed" / "w.key"
    before = key.read_bytes()
    r = run(cfg, "key-decrypt", env={"KEYPW": "wrong-password-xx"})
    assert r.exit_code == 2 and "암호 불일치" in r.output and key.read_bytes() == before


def test_acme_issue_with_encryption_encrypts_pending_and_final_keys(acme_env):
    e = acme_env
    cfgp, marks, web = base_cfg(e.tmp, e, "manual")
    raw = yaml.safe_load(open(cfgp))
    raw["certificate"] = {"key_encryption": "passphrase", "key_password_env": "KEYPW", "cert_file": str(e.tmp / "m" / "a.crt"), "key_file": str(e.tmp / "m" / "a.key")}
    open(cfgp, "w").write(yaml.safe_dump(raw))
    envv = {"KEYPW": PW}
    assert acme_cd(cfgp, "issue", env=envv).exit_code == 4
    pk = e.tmp / "state" / "acme" / "pending" / "default.key"
    assert pk.read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    pend = json.load(open(e.tmp / "state" / "acme" / "pending" / "default.json"))
    for c in pend["challenges"]:
        e.zone.add("_acme-challenge.hnu.kr", c["txt_value"])
    r = acme_cd(cfgp, "issue", env=envv)
    assert r.exit_code == 0, r.output
    assert (e.tmp / "m" / "a.key").read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert (web / "s.key").read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----") and marks.exists()


@pytest.mark.parametrize("cert,extra,msg", [
    ({"key_encryption": "passphrase"}, {}, "key_password_env"),
    ({"key_encryption": "aes"}, {}, "none 또는 passphrase"),
    ({"key_encryption": "passphrase", "key_password_env": "X"}, {"lego": {"domains": ["a.kr"], "email": "a@b.c", "dns_provider": "x"}}, "lego 엔진"),
])
def test_key_encryption_config_validation(cert, extra, msg):
    base = {"certificate": {"cert_file": "/a.crt", "key_file": "/a.key", **cert},
            "targets": [{"name": "w", "type": "generic", "reload_cmd": "none", "files": [{"path": "/x", "content": "cert"}]}], **extra}
    with pytest.raises(ConfigError, match=msg):
        parse_config(base)


# ------------------------------------------------------------------ 수동 교체 대상 (type: manual)
class Rec(NullNotifier):
    def __init__(self):
        self.fired, self.resolved, self.summaries = [], [], []

    def fire(self, target, summary, description, severity="critical"):
        self.fired.append((target, summary, description, severity))

    def resolve(self, target):
        self.resolved.append(target)

    def summary(self, title, text, ok):
        self.summaries.append((title, ok))


class MEnv:
    def __init__(self, tmp, **manual):
        self.tmp = tmp
        self.cert, self.key = make_pki(tmp, "m")[:2]
        self.served = {"serial": None}
        self.now = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
        self.manual = {"formats": ["pem", "pfx"], "pfx_password_env": "PFXPW", "instructions": "관리 화면 → 인증서 → 가져오기 → 적용", **manual}

    def deployer(self, rec=None, with_verify=True, environ=None):
        tgt = {"name": "waf", "type": "manual", "manual": self.manual}
        if with_verify:
            tgt["verify"] = {"host": "www.univ.example", "port": 443}
        cfg = parse_config({"certificate": {"cert_file": str(self.cert), "key_file": str(self.key)}, "state_dir": str(self.tmp / "state"), "targets": [tgt]})

        def verifier(host, port, sni=None):
            if self.served["serial"] is None:
                from certdeploy.verify import VerifyError
                raise VerifyError("접속 실패")
            return self.served["serial"]
        return Deployer(cfg, load_bundle(str(self.cert), str(self.key)), State(cfg.state_dir).load(), transport_factory=lambda t: LocalTransport(),
                        verifier=verifier, notifier=rec or Rec(), sleep=lambda s: None, clock=lambda: self.now,
                        environ=environ if environ is not None else {"PFXPW": "pfx-pass-12345"})


@pytest.fixture
def menv(tmp_path):
    return MEnv(tmp_path)


def test_manual_target_prepares_handoff_files_and_notifies(menv):
    rec = Rec()
    d = menv.deployer(rec)
    (r,) = d.deploy()
    assert r.status == "manual_pending" and "수동 교체 대기" in r.message and r.since
    h = menv.tmp / "state" / "handoff" / "waf"
    assert sorted(os.listdir(h)) == ["INSTRUCTIONS.txt", "cert.pem", "chain.pem", "fullchain.pem", "privkey.pem", "server.pfx"]
    assert mode(h) == 0o700 and mode(h / "privkey.pem") == 0o600 and mode(h / "server.pfx") == 0o600 and mode(h / "fullchain.pem") == 0o644
    assert (h / "privkey.pem").read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    ins = (h / "INSTRUCTIONS.txt").read_text()
    assert "관리 화면 → 인증서 → 가져오기 → 적용" in ins and f"{d.bundle.serial:x}" in ins
    target, summary, desc, sev = rec.fired[0]
    assert target == "waf" and "수동 교체 필요" in summary and sev == "warning" and str(h) in desc and "pfx-pass-12345" not in desc
    assert d.state.target("waf")["status"] == "manual_pending"


def test_manual_target_escalates_after_remind_days_and_keeps_original_since(menv):
    rec = Rec()
    (first,) = menv.deployer(rec).deploy()
    menv.now += timedelta(days=4)
    (again,) = menv.deployer(rec).deploy()
    assert again.since == first.since                              # 안내 시작 시각 유지
    assert [f[3] for f in rec.fired] == ["warning", "critical"]    # remind_days(3) 지나면 긴급


def test_manual_target_completes_when_new_cert_is_served_and_removes_key_copy(menv):
    rec = Rec()
    d = menv.deployer(rec)
    d.deploy()
    h = menv.tmp / "state" / "handoff" / "waf"
    menv.served["serial"] = d.bundle.serial                          # 담당자가 장비에서 교체함
    d2 = menv.deployer(rec)
    (r,) = d2.deploy()
    assert r.status == "skipped" and "수동 교체 확인됨" in r.message
    assert not h.exists() and rec.resolved == ["waf"]
    assert d2.state.target("waf")["status"] == "ok" and d2.state.target("waf")["serial"] == f"{d.bundle.serial:x}"


def test_manual_target_without_verify_uses_confirm_command(menv):
    cfgd = menv.tmp / "cd.yml"
    cfgd.write_text(yaml.safe_dump({"certificate": {"cert_file": str(menv.cert), "key_file": str(menv.key)}, "state_dir": str(menv.tmp / "state"),
                                    "targets": [{"name": "waf", "type": "manual", "manual": {"formats": ["pem"]}}]}))
    r = run(str(cfgd), "deploy")
    assert r.exit_code == 0 and "수동 교체 대기" in r.output          # 대기는 실패가 아니다(종료 코드 0)
    assert os.path.exists(menv.tmp / "state" / "handoff" / "waf" / "privkey.pem")
    again = run(str(cfgd), "deploy")
    assert "수동 교체 대기" in again.output
    c = run(str(cfgd), "confirm", "--target", "waf")
    assert c.exit_code == 0 and not (menv.tmp / "state" / "handoff" / "waf").exists()
    assert "건너뜀" in run(str(cfgd), "deploy").output
    assert run(str(cfgd), "confirm", "--target", "nope").exit_code != 0


def test_manual_target_missing_pfx_password_creates_no_key_copy(menv):
    rec = Rec()
    d = menv.deployer(rec, environ={})
    assert any("PFXPW" in p for p in d.validate_targets())
    (r,) = d.deploy()
    assert r.status == "failed" and "PFXPW" in r.message
    assert not (menv.tmp / "state" / "handoff" / "waf").exists() or not os.listdir(menv.tmp / "state" / "handoff" / "waf")


def test_manual_target_dry_run_plan_preflight_and_rollback(menv):
    d = menv.deployer()
    (r,) = d.deploy(dry_run=True)
    assert r.status == "dry_run" and not (menv.tmp / "state" / "handoff").exists()
    plan = "\n".join(d.plan())
    assert "수동 교체" in plan and "waf" in plan
    from certdeploy.preflight import run_preflight
    checks = run_preflight(d)
    assert any(c.name == "교체용 파일 위치" and c.ok for c in checks) and any(c.name == "PFX 비밀번호" and c.ok for c in checks)
    assert d.rollback("waf").status == "failed"


def test_manual_pending_shows_in_report_and_metrics(menv):
    d = menv.deployer()
    results = d.deploy()
    rep = build_report("hnu", d.bundle, results, menv.now, menv.now)
    assert rep["ok"] is True                                         # 대기는 실패가 아님
    assert "수동 교체 대기" in report_markdown(rep)
    text = metrics_text(rep, {}, None, 0, menv.now)
    assert 'certdeploy_target_manual_pending{cert="hnu",target="waf"} 1' in text
    assert 'certdeploy_target_manual_pending_since_timestamp_seconds{cert="hnu",target="waf"}' in text
    assert 'certdeploy_target_ok{cert="hnu",target="waf"} 1' in text


@pytest.mark.parametrize("manual,msg", [({"formats": ["pdf"]}, "formats"), ({"formats": ["pfx"]}, "pfx_password_env"), ({"export_dir": "rel/dir"}, "export_dir")])
def test_manual_target_config_validation(manual, msg):
    with pytest.raises(ConfigError, match=msg):
        parse_config({"certificate": {"cert_file": "/a.crt", "key_file": "/a.key"}, "targets": [{"name": "w", "type": "manual", "manual": manual}]})


# ------------------------------------------------------------------ 알림 시험
def test_notify_test_requires_a_channel_and_reports_channels(tmp_path):
    cert, key = make_pki(tmp_path, "n")[:2]
    base = {"certificate": {"cert_file": str(cert), "key_file": str(key)}, "state_dir": str(tmp_path / "st"),
            "targets": [{"name": "w", "type": "generic", "reload_cmd": "none", "files": [{"path": str(tmp_path / "x.crt"), "content": "cert"}]}]}
    p = tmp_path / "cd.yml"
    p.write_text(yaml.safe_dump(base))
    assert run(str(p), "notify-test").exit_code != 0
    base["notify"] = {"smtp": {"host": "127.0.0.1", "port": 1, "starttls": False, "from": "a@b.c", "to": ["x@y.z", "q@y.z"]}}
    p.write_text(yaml.safe_dump(base))
    r = run(str(p), "notify-test")
    assert r.exit_code == 0 and "메일(x@y.z, q@y.z" in r.output
    errs = run(str(p), "trace", "--errors").output
    assert "notify/smtp" in errs                                       # 전송 실패는 숨지 않고 진단 이벤트로 남는다
