"""알림 확장: 웹훅 형식·심각도 필터·반복 억제, 티켓(ServiceNow·Jira·일반) 생성/중복방지/해소, 관리자 화면 설정·시험, 비밀 비노출"""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

from certdeploy import adminapi, settings as st
from certdeploy.config import ConfigError, ItsmCfg, NotifyCfg, WebhookCfg, parse_config
from certdeploy.notify import (ItsmNotifier, NotifyTestError, Throttle, WebhookNotifier, build_notifier, check_itsm,
                               send_test_webhook, sev_ok)

ROOT = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------ 가짜 서버
class Fake:
    """요청을 기록하고 경로별로 정해진 응답을 돌려준다. responses: {(METHOD, 경로접두): (상태, 본문)}"""

    def __init__(self):
        self.reqs, self.responses = [], {}
        outer = self

        class H(BaseHTTPRequestHandler):
            def _go(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode() if n else ""
                outer.reqs.append({"method": self.command, "path": self.path, "body": json.loads(body) if body else None,
                                   "auth": self.headers.get("Authorization")})
                for (m, prefix), (code, resp) in outer.responses.items():
                    if m == self.command and self.path.startswith(prefix):
                        break
                else:
                    code, resp = 200, {}
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(resp).encode())

            do_GET = do_POST = do_PATCH = do_PUT = _go

            def log_message(self, *a):
                pass
        self.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def fake():
    f = Fake()
    yield f
    f.close()


# ------------------------------------------------------------------ 웹훅
def test_severity_helper():
    assert sev_ok("critical", "warning") and sev_ok("warning", "warning") and not sev_ok("info", "warning")


@pytest.mark.parametrize("fmt,key", [("googlechat", "text"), ("discord", "content"), ("slack", "text"), ("generic", "title")])
def test_webhook_formats(fake, fmt, key):
    n = WebhookNotifier(WebhookCfg(None, None, fmt, False, fake.url + "/hook"))
    n.fire("t", "배포 실패", "원인", "critical")
    assert key in fake.reqs[0]["body"] and fake.reqs[0]["path"] == "/hook"


def test_webhook_url_from_settings_and_min_severity(fake):
    n = WebhookNotifier(WebhookCfg(None, None, "slack", False, fake.url + "/h", "warning"))
    n.fire("t", "정보성", "d", "info")
    assert fake.reqs == []
    n.fire("t", "경고", "d", "warning")
    assert len(fake.reqs) == 1


def test_webhook_test_message_and_errors(fake):
    send_test_webhook(WebhookCfg(None, None, "teams", False, fake.url + "/x"))
    assert fake.reqs[0]["body"]["type"] == "message"
    fake.responses[("POST", "/bad")] = (404, {})
    with pytest.raises(NotifyTestError, match="찾을 수 없음"):
        send_test_webhook(WebhookCfg(None, None, "slack", False, fake.url + "/bad?token=SECRET123"))
    with pytest.raises(NotifyTestError) as e:
        send_test_webhook(WebhookCfg(None, None, "slack", False, "http://127.0.0.1:9/x?token=SECRET123"))
    assert "SECRET123" not in str(e.value)
    with pytest.raises(NotifyTestError, match="설정되어 있지 않습니다"):
        send_test_webhook(WebhookCfg(None, None, "slack", False, None))


# ------------------------------------------------------------------ 반복 억제
def test_throttle_suppresses_repeats_until_resolved(tmp_path, fake):
    clock = {"t": 1000.0}
    th = Throttle(str(tmp_path), 24, clock=lambda: clock["t"])
    n = WebhookNotifier(WebhookCfg(None, None, "slack", False, fake.url + "/h"), throttle=th)
    n.fire("web1", "배포 실패", "d", "critical")
    clock["t"] += 3600
    n.fire("web1", "배포 실패", "d", "critical")                       # 1시간 뒤 → 억제
    assert len(fake.reqs) == 1
    n.fire("web2", "배포 실패", "d", "critical")                       # 다른 대상은 별개
    assert len(fake.reqs) == 2
    n.resolve("web1")
    n.fire("web1", "배포 실패", "d", "critical")                       # 해소 후 재발은 바로 알림
    assert len(fake.reqs) == 3
    clock["t"] += 25 * 3600
    n.fire("web2", "배포 실패", "d", "critical")                       # 24시간 지나면 다시
    assert len(fake.reqs) == 4
    assert oct((tmp_path / "notify-state.json").stat().st_mode & 0o777) == "0o600"


def test_throttle_off_by_default(tmp_path, fake):
    n = WebhookNotifier(WebhookCfg(None, None, "slack", False, fake.url + "/h"), throttle=Throttle(str(tmp_path), 0))
    n.fire("a", "s", "d")
    n.fire("a", "s", "d")
    assert len(fake.reqs) == 2


def test_build_notifier_wires_channels(tmp_path, fake):
    cfg = NotifyCfg(webhook=WebhookCfg(None, None, "slack", False, fake.url + "/h"), repeat_hours=24, state_dir=str(tmp_path),
                    itsm=ItsmCfg("generic", fake.url + "/ticket", "bearer", token="tok"))
    nt = build_notifier(cfg)
    nt.fire("t1", "실패", "d", "critical")
    paths = [r["path"] for r in fake.reqs]
    assert "/h" in paths and "/ticket" in paths


# ------------------------------------------------------------------ 티켓
def snow(fake, **kw):
    return ItsmCfg("servicenow", fake.url, "basic", "svc", "p@ss", None, None, None, kw.pop("min_severity", "warning"), assignment_group="전산실", category="인증서", **kw)


def test_servicenow_create_dedupe_and_close(tmp_path, fake):
    fake.responses[("POST", "/api/now/table/incident")] = (201, {"result": {"sys_id": "abc123", "number": "INC0010001"}})
    n = ItsmNotifier(snow(fake), state_dir=str(tmp_path))
    n.fire("web1", "배포 실패: web1", "원인 설명", "critical")
    n.fire("web1", "배포 실패: web1", "원인 설명", "critical")                  # 같은 대상 → 중복 생성 없음
    posts = [r for r in fake.reqs if r["method"] == "POST"]
    assert len(posts) == 1
    b = posts[0]["body"]
    assert b["short_description"] == "배포 실패: web1" and b["urgency"] == "1" and b["assignment_group"] == "전산실" and b["category"] == "인증서"
    assert posts[0]["auth"] == "Basic " + base64.b64encode(b"svc:p@ss").decode()
    assert json.loads((tmp_path / "tickets.json").read_text())["web1"]["ref"] == "INC0010001"
    n.resolve("web1")
    patch = [r for r in fake.reqs if r["method"] == "PATCH"][0]
    assert patch["path"].endswith("/incident/abc123") and patch["body"]["state"] == "6" and "close_notes" in patch["body"]
    assert json.loads((tmp_path / "tickets.json").read_text()) == {}
    n.resolve("web1")                                                       # 열린 티켓 없음 → 아무 일 없음
    assert len([r for r in fake.reqs if r["method"] == "PATCH"]) == 1


def test_severity_filter_for_tickets(tmp_path, fake):
    n = ItsmNotifier(snow(fake, min_severity="critical"), state_dir=str(tmp_path))
    n.fire("w", "경고", "d", "warning")
    assert fake.reqs == []


def test_jira_create_comment_transition(tmp_path, fake):
    fake.responses[("POST", "/rest/api/2/issue")] = (201, {"id": "10001", "key": "CERT-7"})
    c = ItsmCfg("jira", fake.url, "bearer", token="pat-1", project="CERT", issue_type="Bug", resolve_transition_id="31", priority_map={"critical": "Blocker"})
    n = ItsmNotifier(c, state_dir=str(tmp_path))
    n.fire("web1", "배포 실패", "d", "critical")
    create = fake.reqs[0]
    f = create["body"]["fields"]
    assert f["project"] == {"key": "CERT"} and f["issuetype"] == {"name": "Bug"} and f["priority"] == {"name": "Blocker"} and create["auth"] == "Bearer pat-1"
    n.resolve("web1")
    assert [r["path"] for r in fake.reqs[1:]] == ["/rest/api/2/issue/CERT-7/comment", "/rest/api/2/issue/CERT-7/transitions"]
    assert fake.reqs[2]["body"] == {"transition": {"id": "31"}}


def test_jira_without_transition_only_comments(tmp_path, fake):
    fake.responses[("POST", "/rest/api/2/issue")] = (201, {"key": "CERT-8"})
    n = ItsmNotifier(ItsmCfg("jira", fake.url, "bearer", token="t", project="CERT"), state_dir=str(tmp_path))
    n.fire("w", "x", "d", "critical")
    n.resolve("w")
    assert fake.reqs[-1]["path"].endswith("/comment") and not any("transitions" in r["path"] for r in fake.reqs)


def test_generic_itsm_events(tmp_path, fake):
    fake.responses[("POST", "/t")] = (200, {"id": "T-1"})
    n = ItsmNotifier(ItsmCfg("generic", fake.url + "/t", "bearer", token="x"), state_dir=str(tmp_path))
    n.fire("w", "제목", "본문", "critical")
    n.resolve("w")
    assert [r["body"]["event"] for r in fake.reqs] == ["fire", "resolve"] and fake.reqs[1]["body"]["id"] == "T-1"


def test_ticket_failures_never_raise_and_are_retried(tmp_path, fake):
    fake.responses[("POST", "/api/now/table/incident")] = (401, {})
    n = ItsmNotifier(snow(fake), state_dir=str(tmp_path))
    n.fire("w", "s", "d", "critical")                                       # 예외 없이 무시, 기록 없음
    assert not (tmp_path / "tickets.json").exists() or json.loads((tmp_path / "tickets.json").read_text()) == {}
    fake.responses[("POST", "/api/now/table/incident")] = (201, {"result": {"sys_id": "z", "number": "INC1"}})
    n.fire("w", "s", "d", "critical")
    fake.responses[("PATCH", "/api/now/table/incident")] = (500, {})
    n.resolve("w")                                                          # 닫기 실패 → 기록 유지(다음에 재시도)
    assert "w" in json.loads((tmp_path / "tickets.json").read_text())
    fake.responses[("PATCH", "/api/now/table/incident")] = (200, {})
    n.resolve("w")
    assert json.loads((tmp_path / "tickets.json").read_text()) == {}


def test_check_does_not_create_tickets_and_classifies_errors(tmp_path, fake):
    assert "접속·인증 확인" in check_itsm(snow(fake))
    assert [r["method"] for r in fake.reqs] == ["GET"]
    fake.reqs.clear()
    fake.responses[("GET", "/rest/api/2/myself")] = (200, {"displayName": "홍길동"})
    msg = check_itsm(ItsmCfg("jira", fake.url, "basic", "u", "p", project="CERT"))
    assert "홍길동" in msg and [r["path"] for r in fake.reqs] == ["/rest/api/2/myself", "/rest/api/2/project/CERT"]
    fake.responses[("GET", "/api/now")] = (401, {})
    with pytest.raises(NotifyTestError, match="인증 실패"):
        check_itsm(snow(fake))
    fake.responses[("GET", "/api/now")] = (403, {})
    with pytest.raises(NotifyTestError, match="권한 없음"):
        check_itsm(snow(fake))
    with pytest.raises(NotifyTestError, match="접속 실패") as e:
        check_itsm(ItsmCfg("servicenow", "http://127.0.0.1:9", "basic", "u", "SECRETPW"))
    assert "SECRETPW" not in str(e.value)
    with pytest.raises(NotifyTestError, match="설정되어 있지 않습니다"):
        check_itsm(ItsmCfg("servicenow", fake.url, "basic", None, None))


def test_secret_from_environment():
    c = ItsmCfg("generic", "http://x/t", "basic", "u", None, "ITSM_PW")
    assert ItsmNotifier(c, {"ITSM_PW": "pw1"})._headers()["Authorization"] == "Basic " + base64.b64encode(b"u:pw1").decode()


def test_non_http_scheme_refused():
    n = ItsmNotifier(ItsmCfg("generic", "file:///etc/passwd", "bearer", token="t"))
    with pytest.raises(OSError):
        n._call("POST", "file:///etc/passwd", {})


# ------------------------------------------------------------------ YAML 설정
def ycfg(notify):
    return {"certificate": {"cert_file": "/a.crt", "key_file": "/a.key"}, "notify": notify,
            "targets": [{"name": "w", "type": "apache", "cert_path": "/c", "key_path": "/k"}]}


def test_yaml_itsm_and_repeat_hours_parse():
    c = parse_config(ycfg({"repeat_hours": 24, "webhook": {"url_env": "H", "format": "googlechat", "min_severity": "warning"},
                           "itsm": {"format": "jira", "url": "https://jira.hnu.kr", "auth": "bearer", "token_env": "JT", "project": "CERT"}}))
    n = c.notify
    assert n.repeat_hours == 24 and n.webhook.format == "googlechat" and n.webhook.min_severity == "warning" and n.state_dir == c.state_dir
    assert n.itsm.format == "jira" and n.itsm.token_env == "JT" and n.itsm.min_severity == "warning"


@pytest.mark.parametrize("notify,msg", [
    ({"repeat_hours": -1}, "repeat_hours"),
    ({"itsm": {"format": "remedy", "url": "https://x"}}, "format"),
    ({"itsm": {"format": "jira", "url": "ftp://x", "auth": "bearer", "token_env": "T", "project": "C"}}, "http"),
    ({"itsm": {"format": "jira", "url": "https://x", "auth": "bearer", "token_env": "T"}}, "project"),
    ({"itsm": {"format": "generic", "url": "https://x", "auth": "basic", "username": "u"}}, "password_env"),
    ({"itsm": {"format": "generic", "url": "https://x", "auth": "bearer"}}, "token_env"),
    ({"itsm": {"format": "generic", "url": "https://x", "auth": "bearer", "token_env": "T", "bogus": 1}}, "알 수 없는 키"),
    ({"webhook": {"url_env": "H", "min_severity": "fatal"}}, "min_severity"),
    ({"itsm": {"format": "generic", "url": "https://x", "auth": "bearer", "token_env": "T", "ca_file": "rel.pem"}}, "ca_file"),
])
def test_yaml_notify_errors(notify, msg):
    with pytest.raises(ConfigError, match=msg):
        parse_config(ycfg(notify))


# ------------------------------------------------------------------ 설정 화면(settings / adminapi)
def test_normalize_webhook_keeps_previous_secret_and_validates():
    prev = {"enabled": True, "format": "teams", "url": "https://hook.example/abc", "min_severity": "info"}
    n = st.normalize_webhook({"enabled": True, "format": "teams", "url": ""}, prev)
    assert n["url"] == "https://hook.example/abc"
    for bad in ({"enabled": True, "format": "teams", "url": "javascript:alert(1)"}, {"enabled": True, "format": "x", "url": "https://a.b"},
                {"enabled": True, "format": "teams", "url": ""}):
        with pytest.raises(st.SettingsError):
            st.normalize_webhook(bad, None)
    assert st.normalize_webhook({"enabled": False}, None)["enabled"] is False


def test_normalize_itsm_rules():
    base = {"enabled": True, "format": "servicenow", "url": "https://x.service-now.com/", "auth": "basic", "username": "u", "password": "p"}
    n = st.normalize_itsm(base, None)
    assert n["url"] == "https://x.service-now.com" and n["min_severity"] == "warning"
    kept = st.normalize_itsm({**base, "password": ""}, n)                    # 같은 계정이면 비밀번호 유지
    assert kept["password"] == "p"
    changed = st.normalize_itsm({**base, "username": "u2", "password": "newpw"}, n)
    assert changed["password"] == "newpw"
    with pytest.raises(st.SettingsError, match="비밀번호"):
        st.normalize_itsm({**base, "username": "other", "password": ""}, n)  # 계정이 바뀌면 재입력
    with pytest.raises(st.SettingsError, match="프로젝트"):
        st.normalize_itsm({**base, "format": "jira"}, None)
    with pytest.raises(st.SettingsError, match="토큰"):
        st.normalize_itsm({"enabled": True, "format": "generic", "url": "https://x", "auth": "bearer"}, None)
    with pytest.raises(st.SettingsError, match="줄바꿈"):
        st.normalize_itsm({**base, "password": "a\nb"}, None)
    with pytest.raises(st.SettingsError):
        st.normalize_common({"repeat_hours": 9999})


@pytest.fixture
def cfgfile(tmp_path):
    cfg = {"state_dir": str(tmp_path / "state"), "certificate": {"cert_file": str(tmp_path / "a.crt"), "key_file": str(tmp_path / "a.key")},
           "targets": [{"name": "w", "type": "apache", "cert_path": "/c", "key_path": "/k"}]}
    p = tmp_path / "certdeploy.yml"
    p.write_text(yaml.safe_dump(cfg))
    return str(p)


def test_save_overview_masks_secrets_and_apply(cfgfile, tmp_path):
    payload = {"webhook": {"enabled": True, "format": "teams", "url": "https://hook.example/SECRETTOKEN", "min_severity": "warning"},
               "itsm": {"enabled": True, "format": "jira", "url": "https://jira.hnu.kr", "auth": "bearer", "token": "PATSECRET", "project": "CERT"},
               "notify_common": {"repeat_hours": 24}, "mail": {"enabled": True, "host": "smtp.hnu.kr", "from": "a@hnu.kr", "to": "b@hnu.kr", "min_severity": "critical"}}
    r = adminapi.save(cfgfile, payload, "admin1")
    assert set(r["changed"]) == {"webhook", "itsm", "notify_common", "mail"}
    blob = json.dumps(r) + json.dumps(adminapi.overview(cfgfile))
    assert "SECRETTOKEN" not in blob and "PATSECRET" not in blob
    ov = adminapi.overview(cfgfile)
    assert ov["webhook"]["url_set"] is True and ov["itsm"]["token_set"] is True and ov["notify_common"]["repeat_hours"] == 24 and ov["mail"]["min_severity"] == "critical"
    saved = tmp_path / "state/settings.json"
    assert oct(saved.stat().st_mode & 0o777) == "0o600"
    from certdeploy.config import load_config
    cfg = load_config(cfgfile)
    assert cfg.notify.webhook.url.endswith("SECRETTOKEN") and cfg.notify.itsm.token == "PATSECRET" and cfg.notify.repeat_hours == 24
    assert cfg.notify.smtp.min_severity == "critical" and any("웹훅" in a for a in cfg.applied)
    adminapi.save(cfgfile, {"webhook": {"enabled": False}}, "admin1")
    assert load_config(cfgfile).notify.webhook is None


def test_adminapi_channel_tests(cfgfile, fake):
    r = adminapi.webhook_test(cfgfile, {"enabled": True, "format": "slack", "url": fake.url + "/h"})
    assert r["ok"] and fake.reqs[0]["path"] == "/h"
    bad = adminapi.webhook_test(cfgfile, {"enabled": True, "format": "slack", "url": "not a url"})
    assert not bad["ok"] and "주소" in bad["message"]
    assert not adminapi.webhook_test(cfgfile)["ok"]                                       # 저장된 설정 없음
    r2 = adminapi.itsm_test(cfgfile, {"enabled": True, "format": "servicenow", "url": fake.url, "auth": "basic", "username": "u", "password": "p"})
    assert r2["ok"] and fake.reqs[-1]["method"] == "GET"
    fake.responses[("GET", "/api/now")] = (401, {})
    r3 = adminapi.itsm_test(cfgfile, {"enabled": True, "format": "servicenow", "url": fake.url, "auth": "basic", "username": "u", "password": "p"})
    assert not r3["ok"] and "인증 실패" in r3["message"]
    adminapi.save(cfgfile, {"webhook": {"enabled": True, "format": "slack", "url": fake.url + "/saved"}}, "a")
    assert adminapi.webhook_test(cfgfile)["ok"] and fake.reqs[-1]["path"] == "/saved"       # 저장된 값으로 시험


def test_web_endpoints_admin_only_and_audit_without_secrets(cfgfile, tmp_path, sandbox, fake):
    from certpilot_api.app import create_app
    from certpilot_core.remote import SandboxExecutor
    pw = "Str0ng!Passw0rd"
    app = create_app({"DATA_DIR": str(tmp_path / "data"), "ADMIN_USER": "root1", "ADMIN_PASSWORD": pw, "SECURE_COOKIE": False,
                      "CERTDEPLOY_CONFIG": cfgfile}, executor_factory=lambda t: SandboxExecutor(sandbox.path))
    c = app.test_client()
    assert c.post("/certdeploy/webhook-test", json={}).status_code == 401
    c.post("/auth/login", json={"username": "root1", "password": pw})
    body = {"enabled": True, "format": "slack", "url": fake.url + "/TOKENXYZ"}
    r = c.post("/certdeploy/webhook-test", json=body)
    assert r.status_code == 200 and r.json["ok"]
    it = c.post("/certdeploy/itsm-test", json={"enabled": True, "format": "servicenow", "url": fake.url, "auth": "basic", "username": "u", "password": "PWSECRET"})
    assert it.json["ok"]
    assert c.put("/certdeploy/settings", json={"itsm": {"enabled": True, "format": "generic", "url": fake.url + "/t", "auth": "bearer", "token": "TOK1"}}).status_code == 200
    logs = json.dumps(c.get("/audit-logs?limit=50").json, ensure_ascii=False)
    assert "certdeploy_webhook_test" in logs and "certdeploy_itsm_test" in logs and "TOKENXYZ" not in logs and "PWSECRET" not in logs and "TOK1" not in logs
    assert "TOK1" not in json.dumps(c.get("/certdeploy/overview").json)
    c.post("/users", json={"username": "op1", "password": "An0ther!Passw0rd", "role": "operator"})
    op = app.test_client()
    op.post("/auth/login", json={"username": "op1", "password": "An0ther!Passw0rd"})
    assert op.post("/certdeploy/webhook-test", json=body).status_code == 403 and op.post("/certdeploy/itsm-test", json={}).status_code == 403


def test_frontend_wiring_and_docs():
    html = (ROOT / "frontend/templates/index.html").read_text()
    js = (ROOT / "frontend/js/app.js").read_text()
    for i in ("cd-wh-form", "w-url", "w-format", "cd-it-form", "i-format", "i-url", "i-pass", "i-token", "n-repeat", "m-sev", "btn-it-test", "btn-wh-test"):
        assert f'id="{i}"' in html, i
    for e in ("/certdeploy/webhook-test", "/certdeploy/itsm-test", "wireChannels", "notify_common", "fillChannels"):
        assert e in js, e
    assert "ServiceNow" in (ROOT / "docs/ops/vm-install-and-test.md").read_text()
