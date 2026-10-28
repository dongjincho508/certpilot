"""관리자 화면 설정(메일·인증서별 개인키 보호): 저장·적용·시험 메일·키 파일 변환, 웹 API 권한·비밀 비노출."""
import json
import os
import smtplib
import ssl
import stat

import pytest
import yaml
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization

import smtp_fake
from certdeploy import adminapi, manual as mn, settings as st
from certdeploy.cli import main
from certdeploy.config import load_config
from certdeploy.notify import MailTestError, build_notifier, send_test_mail
from certpilot_api.app import create_app
from pki_helpers import make_pki, sign_csr

PW = "Str0ng!Passw0rd"
PASS = "key-pass-123456"
DOMAINS = ["*.hnu.kr", "hnu.kr"]


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


@pytest.fixture
def adm(tmp_path):
    """두 인증서(hnu, hannam)를 가진 certdeploy 설정 + 이미 발급된 평문 키."""
    ca = {}
    make_pki(tmp_path, "seed", shared_ca=ca)
    certs = []
    for name in ("hnu", "hannam"):
        d = tmp_path / "state" / name / "managed"
        d.mkdir(parents=True)
        key_pem, csr = mn.generate_csr(DOMAINS if name == "hnu" else ["*.hannam.ac.kr", "hannam.ac.kr"])
        (d / "w.key").write_bytes(key_pem)
        os.chmod(d / "w.key", 0o600)
        (d / "w.crt").write_bytes(sign_csr(csr, ca).public_bytes(serialization.Encoding.PEM) + ca["inter"].public_bytes(serialization.Encoding.PEM))
        certs.append({"name": name, "certificate": {"cert_file": str(d / "w.crt"), "key_file": str(d / "w.key")},
                      "targets": [{"name": f"{name}-web", "type": "generic", "check_cmd": "true", "reload_cmd": "true",
                                   "files": [{"path": str(tmp_path / f"{name}-s.crt"), "content": "fullchain"}, {"path": str(tmp_path / f"{name}-s.key"), "content": "key"}]}]})
    cfg = {"state_dir": str(tmp_path / "state"), "certificates": certs}
    p = tmp_path / "cd.yml"
    p.write_text(yaml.safe_dump(cfg))
    return type("A", (), {"cfg": str(p), "tmp": tmp_path, "state": str(tmp_path / "state"), "ca": ca, "key": lambda self, n: tmp_path / "state" / n / "managed" / "w.key"})()


MAIL = {"enabled": True, "host": "smtp.hnu.kr", "port": 587, "starttls": True, "from": "cert-deploy@hnu.kr", "to": "a@hnu.kr, b@hnu.kr", "username": "cd", "password": "smtp-secret-1", "on_success": True}


# ------------------------------------------------------------------ 설정 저장·마스킹·적용
def test_settings_file_is_private_masked_and_applied_to_config(adm):
    r = adminapi.save(adm.cfg, {"mail": MAIL}, "admin")
    sp = os.path.join(adm.state, "settings.json")
    assert mode(sp) == 0o600 and r["changed"] == ["mail"]
    assert "smtp-secret-1" not in json.dumps(r) and r["settings"]["mail"]["password_set"] is True and "password" not in r["settings"]["mail"]
    assert json.load(open(sp))["mail"]["to"] == ["a@hnu.kr", "b@hnu.kr"] and json.load(open(sp))["updated_by"] == "admin"
    cfg = load_config(adm.cfg)
    s = cfg.notify.smtp
    assert (s.host, s.sender, s.to, s.username, s.password, s.on_success) == ("smtp.hnu.kr", "cert-deploy@hnu.kr", ["a@hnu.kr", "b@hnu.kr"], "cd", "smtp-secret-1", True)
    assert any("메일" in n for n in cfg.applied)
    v = CliRunner().invoke(main, ["-c", adm.cfg, "validate"])
    assert "관리자 화면(settings.json) 적용" in v.output or v.exit_code != 0           # 인증서 검증 전 단계에서 안내(아직 인증서 없는 설정이면 생략될 수 있음)


def test_password_blank_keeps_previous_but_username_change_requires_new_one(adm):
    adminapi.save(adm.cfg, {"mail": MAIL}, "admin")
    adminapi.save(adm.cfg, {"mail": {**MAIL, "password": "", "host": "smtp2.hnu.kr"}}, "admin")
    assert json.load(open(os.path.join(adm.state, "settings.json")))["mail"]["password"] == "smtp-secret-1"
    adminapi.save(adm.cfg, {"mail": {**MAIL, "password": "", "username": "other"}}, "admin")
    assert json.load(open(os.path.join(adm.state, "settings.json")))["mail"]["password"] is None


@pytest.mark.parametrize("over,msg", [({"host": ""}, "SMTP 서버"), ({"port": 70000}, "포트"), ({"from": "nope"}, "발신"), ({"to": ""}, "수신 주소가 하나"),
                                       ({"to": "a@b.c, bad"}, "형식"), ({"password": "x\ny"}, "줄바꿈")])
def test_mail_validation(adm, over, msg):
    with pytest.raises(adminapi.AdminError, match=msg):
        adminapi.save(adm.cfg, {"mail": {**MAIL, **over}}, "admin")
    assert not os.path.exists(os.path.join(adm.state, "settings.json"))


def test_mail_disabled_overrides_yaml_and_no_host_needed(adm):
    adminapi.save(adm.cfg, {"mail": {"enabled": False}}, "admin")
    assert load_config(adm.cfg).notify.smtp is None


def test_overview_reports_certs_mail_and_never_secrets(adm):
    adminapi.save(adm.cfg, {"mail": MAIL}, "admin")
    o = adminapi.overview(adm.cfg)
    assert [c["name"] for c in o["certificates"]] == ["hnu", "hannam"] and o["mail"]["source"] == "관리자 화면" and o["mail"]["password_set"]
    c = o["certificates"][0]
    assert c["key_file_encrypted"] is False and c["cert"]["days_left"] > 0 and c["key_encryption"] == "none"
    assert "smtp-secret-1" not in json.dumps(o)
    with pytest.raises(adminapi.AdminError, match="CERTDEPLOY_CONFIG"):
        adminapi.overview(None)
    with pytest.raises(adminapi.AdminError, match="읽을 수 없습니다"):
        adminapi.overview(str(adm.tmp / "missing.yml"))


# ------------------------------------------------------------------ 시험 메일
def test_mail_test_sends_real_smtp_message_and_classifies_failures(adm):
    srv = smtp_fake.SmtpServer()
    try:
        ok = adminapi.mail_test(adm.cfg, {**MAIL, "host": "127.0.0.1", "port": srv.port, "starttls": False, "username": "", "password": ""})
        assert ok["ok"] and "a@hnu.kr" in ok["message"] and len(srv.mails) == 1
        assert "certdeploy" in srv.mails[0]["data"]
    finally:
        srv.shutdown()
    auth = smtp_fake.SmtpServer(require_auth=("cd", "right-pass"))
    try:
        base = {**MAIL, "host": "127.0.0.1", "port": auth.port, "starttls": False, "username": "cd"}
        assert adminapi.mail_test(adm.cfg, {**base, "password": "wrong"})["message"].startswith("로그인 실패")
        assert adminapi.mail_test(adm.cfg, {**base, "password": "right-pass"})["ok"] and auth.logins == ["cd"]
    finally:
        auth.shutdown()
    rej = smtp_fake.SmtpServer(reject_rcpt=True)
    try:
        assert "수신 주소가 거부" in adminapi.mail_test(adm.cfg, {**MAIL, "host": "127.0.0.1", "port": rej.port, "starttls": False, "username": "", "password": ""})["message"]
    finally:
        rej.shutdown()
    refused = adminapi.mail_test(adm.cfg, {**MAIL, "host": "127.0.0.1", "port": 9, "starttls": False})
    assert refused["ok"] is False and "연결 거부" in refused["message"]
    assert adminapi.mail_test(adm.cfg, {**MAIL, "host": ""})["ok"] is False
    assert adminapi.mail_test(adm.cfg)["message"] == "저장된 메일 설정이 없습니다"
    assert "smtp-secret-1" not in json.dumps(refused)


def test_send_test_mail_error_classes():
    class Boom:
        def __init__(self, exc):
            self.exc = exc

        def __call__(self, *a, **k):
            raise self.exc
    from certdeploy.config import SmtpCfg
    cfg = SmtpCfg("h", "a@b.c", ["x@y.z"])
    for exc, text in ((ssl.SSLError("x"), "TLS 오류"), (smtplib.SMTPServerDisconnected("x"), "연결을 끊"), (TimeoutError(), "시간 초과"),
                      (smtplib.SMTPSenderRefused(550, b"no", "a@b.c"), "발신 주소"), (OSError("dns"), "접속 실패")):
        with pytest.raises(MailTestError, match=text):
            send_test_mail(cfg, smtp_factory=Boom(exc))


def test_settings_mail_password_is_used_by_the_real_notifier(adm):
    srv = smtp_fake.SmtpServer(require_auth=("cd", "smtp-secret-1"))
    try:
        adminapi.save(adm.cfg, {"mail": {**MAIL, "host": "127.0.0.1", "port": srv.port, "starttls": False}}, "admin")
        n = build_notifier(load_config(adm.cfg).notify)
        n.fire("hnu-web", "배포 실패", "시험", "critical")
        assert srv.logins == ["cd"] and srv.mails and "배포 실패" in srv.mails[0]["data"]
    finally:
        srv.shutdown()


# ------------------------------------------------------------------ 인증서별 개인키 보호
def test_enable_converts_key_and_removes_plain_backup_then_disable_restores(adm):
    plain = adm.key("hnu").read_bytes()
    r = adminapi.save(adm.cfg, {"certificates": {"hnu": {"key_encryption": "passphrase", "key_passphrase": PASS}}}, "admin")
    assert "암호로 보호했습니다" in r["messages"][0] and PASS not in json.dumps(r)
    enc = adm.key("hnu").read_bytes()
    assert enc.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") and mode(adm.key("hnu")) == 0o600
    assert not [f for f in os.listdir(adm.key("hnu").parent) if ".bak-" in f]               # 평문 사본이 남지 않는다
    assert adm.key("hannam").read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")       # 다른 인증서는 그대로(별 설정)
    o = adminapi.overview(adm.cfg)
    assert o["certificates"][0]["key_file_encrypted"] is True and o["certificates"][0]["key_encryption"] == "passphrase" and o["certificates"][0]["cert"]
    cfg = load_config(adm.cfg)
    assert [(c.name, c.key_encryption) for c in cfg.certs] == [("hnu", "passphrase"), ("hannam", "none")]
    # CLI 가 설정 화면의 암호로 그대로 동작(환경변수 불필요)
    v = CliRunner().invoke(main, ["-c", adm.cfg, "--cert", "hnu", "validate"], catch_exceptions=False)
    assert v.exit_code == 0 and "암호화됨" in v.output and "관리자 화면(settings.json) 적용" in v.output
    d = CliRunner().invoke(main, ["-c", adm.cfg, "--cert", "hnu", "deploy"], catch_exceptions=False)
    assert d.exit_code == 0 and (adm.tmp / "hnu-s.key").read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    # 암호 변경
    adminapi.save(adm.cfg, {"certificates": {"hnu": {"key_encryption": "passphrase", "key_passphrase": "another-pass-9999"}}}, "admin")
    assert CliRunner().invoke(main, ["-c", adm.cfg, "--cert", "hnu", "validate"], catch_exceptions=False).exit_code == 0
    # 사용 안 함으로 되돌리기
    adminapi.save(adm.cfg, {"certificates": {"hnu": {"key_encryption": "none"}}}, "admin")
    assert adm.key("hnu").read_bytes() == plain
    assert not [f for f in os.listdir(adm.key("hnu").parent) if ".bak-" in f]


def test_enable_requires_strong_passphrase_and_known_certificate(adm):
    for opts, msg in (({"key_encryption": "passphrase"}, "암호를 입력"), ({"key_encryption": "passphrase", "key_passphrase": "short"}, "12자"),
                      ({"key_encryption": "aes"}, "none 또는 passphrase")):
        with pytest.raises(adminapi.AdminError, match=msg):
            adminapi.save(adm.cfg, {"certificates": {"hnu": opts}}, "admin")
    with pytest.raises(adminapi.AdminError, match="알 수 없는 인증서"):
        adminapi.save(adm.cfg, {"certificates": {"nope": {"key_encryption": "none"}}}, "admin")
    assert adm.key("hnu").read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")           # 실패 시 파일 불변
    assert not os.path.exists(os.path.join(adm.state, "settings.json"))


def test_enable_before_key_exists_only_records_option_and_next_import_encrypts(adm, tmp_path):
    os.remove(adm.key("hannam"))
    r = adminapi.save(adm.cfg, {"certificates": {"hannam": {"key_encryption": "passphrase", "key_passphrase": PASS}}}, "admin")
    assert "다음 발급·가져오기부터" in r["messages"][0]
    key_pem, csr = mn.generate_csr(["*.hannam.ac.kr", "hannam.ac.kr"])
    (tmp_path / "k.key").write_bytes(key_pem)
    (tmp_path / "s.cer").write_bytes(sign_csr(csr, adm.ca).public_bytes(serialization.Encoding.PEM) + adm.ca["inter"].public_bytes(serialization.Encoding.PEM))
    res = CliRunner().invoke(main, ["-c", adm.cfg, "--cert", "hannam", "import", "--file", str(tmp_path / "s.cer"), "--key-file", str(tmp_path / "k.key")], catch_exceptions=False)
    assert res.exit_code == 0, res.output
    assert adm.key("hannam").read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")


def test_failed_conversion_saves_nothing(adm):
    adminapi.save(adm.cfg, {"certificates": {"hnu": {"key_encryption": "passphrase", "key_passphrase": PASS}}}, "admin")
    sp = os.path.join(adm.state, "settings.json")
    data = json.load(open(sp))
    data["certificates"]["hnu"]["key_passphrase"] = "tampered-passphrase-0"            # 파일의 암호가 실제 키와 불일치하는 상황
    json.dump(data, open(sp, "w"))
    before = adm.key("hnu").read_bytes()
    with pytest.raises(adminapi.AdminError):
        adminapi.save(adm.cfg, {"certificates": {"hnu": {"key_encryption": "none"}}}, "admin")
    assert adm.key("hnu").read_bytes() == before and json.load(open(sp))["certificates"]["hnu"]["key_encryption"] == "passphrase"


def test_corrupt_settings_file_is_reported_not_crashing(adm):
    open(os.path.join(adm.state, "settings.json"), "w").write("{not json")
    with pytest.raises(adminapi.AdminError, match="읽을 수 없습니다"):
        adminapi.overview(adm.cfg)
    from certdeploy.config import ConfigError
    with pytest.raises(ConfigError):
        load_config(adm.cfg)


# ------------------------------------------------------------------ 웹 API (권한·감사·비밀 비노출)
@pytest.fixture
def web(adm, tmp_path):
    app = create_app({"DATA_DIR": str(tmp_path / "webdata"), "ADMIN_USER": "root1", "ADMIN_PASSWORD": PW, "SECURE_COOKIE": False, "CERTDEPLOY_CONFIG": adm.cfg})
    c = app.test_client()
    assert c.post("/auth/login", json={"username": "root1", "password": PW}).status_code == 200
    return type("W", (), {"app": app, "c": c, "adm": adm})


def test_web_endpoints_admin_only(web):
    anon = web.app.test_client()
    for m, p in (("get", "/certdeploy/overview"), ("put", "/certdeploy/settings"), ("post", "/certdeploy/mail-test")):
        assert getattr(anon, m)(p).status_code == 401
    web.c.post("/users", json={"username": "op9", "password": PW + "9", "role": "operator"})
    o = web.app.test_client()
    o.post("/auth/login", json={"username": "op9", "password": PW + "9"})
    for m, p in (("get", "/certdeploy/overview"), ("put", "/certdeploy/settings"), ("post", "/certdeploy/mail-test")):
        assert getattr(o, m)(p, json={}).status_code == 403


def test_web_save_overview_audit_and_no_secret_leak(web):
    r = web.c.put("/certdeploy/settings", json={"mail": MAIL, "certificates": {"hnu": {"key_encryption": "passphrase", "key_passphrase": PASS}}})
    assert r.status_code == 200, r.get_data(as_text=True)
    ov = web.c.get("/certdeploy/overview")
    assert ov.status_code == 200 and ov.json["mail"]["host"] == "smtp.hnu.kr"
    everything = r.get_data(as_text=True) + ov.get_data(as_text=True) + json.dumps(web.c.get("/audit-logs").json)
    assert "smtp-secret-1" not in everything and PASS not in everything
    ev = [x for x in web.c.get("/audit-logs").json["logs"] if x["event_type"] == "certdeploy_settings_update"]
    assert ev and ev[0]["details"]["actor"] == "root1" and set(ev[0]["details"]["changed"]) == {"mail", "certificates.hnu"}
    assert web.c.get("/auth/me").json["username"] == "root1"
    bad = web.c.put("/certdeploy/settings", json={"mail": {**MAIL, "host": ""}})
    assert bad.status_code == 422 and "SMTP 서버" in bad.json["error"]["message"]
    assert web.c.put("/certdeploy/settings", data="x").status_code == 422


def test_web_mail_test_endpoint_and_audit(web):
    srv = smtp_fake.SmtpServer()
    try:
        r = web.c.post("/certdeploy/mail-test", json={**MAIL, "host": "127.0.0.1", "port": srv.port, "starttls": False, "username": "", "password": ""})
        assert r.status_code == 200 and r.json["ok"] and srv.mails
    finally:
        srv.shutdown()
    r2 = web.c.post("/certdeploy/mail-test", json={**MAIL, "host": "127.0.0.1", "port": 9, "starttls": False})
    assert r2.json["ok"] is False and "연결 거부" in r2.json["message"]
    assert [e for e in web.c.get("/audit-logs").json["logs"] if e["event_type"] == "certdeploy_mail_test"]


def test_web_without_certdeploy_config_returns_clear_409(tmp_path):
    app = create_app({"DATA_DIR": str(tmp_path / "d"), "ADMIN_USER": "root1", "ADMIN_PASSWORD": PW, "SECURE_COOKIE": False, "CERTDEPLOY_CONFIG": None})
    c = app.test_client()
    c.post("/auth/login", json={"username": "root1", "password": PW})
    r = c.get("/certdeploy/overview")
    assert r.status_code == 409 and "CERTDEPLOY_CONFIG" in r.json["error"]["message"]


def test_frontend_has_certdeploy_settings_view():
    base = os.path.join(os.path.dirname(__file__), "..", "frontend")
    html = open(os.path.join(base, "templates", "index.html"), encoding="utf-8").read()
    js = open(os.path.join(base, "js", "app.js"), encoding="utf-8").read()
    for token in ('data-view="cd"', 'id="view-cd"', 'id="cd-mail-form"', 'id="btn-mail-test"', 'id="cd-certs"'):
        assert token in html, token
    for token in ("/certdeploy/overview", "/certdeploy/settings", "/certdeploy/mail-test", "key_encryption", "개인키 보호"):
        assert token in js, token
