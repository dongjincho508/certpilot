"""전 과정 디버깅 장치: 트레이스(마스킹·구간·파일), 관리자 진단 API, certdeploy trace/diagnose, 감시 점검."""
import json
import os
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import yaml
from click.testing import CliRunner

from certdeploy import manual as mn
from certdeploy.cli import main
from certpilot_api.app import create_app
from certpilot_core import diag, trace
from certpilot_core.remote import FailureCause, RemoteError, SandboxExecutor
from conftest import make_cert, pem as cpem
from pki_helpers import make_pki, sign_csr

PW = "Str0ng!Passw0rd"
PRIV = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----"


@pytest.fixture(autouse=True)
def fresh_tracer():
    trace.TRACER.clear()
    trace.TRACER.configure(path="", echo=None)
    trace.run_id_var.set(None)           # CLI 가 프로세스 수명 동안 설정하는 작업 ID 가 테스트 간에 새지 않게
    yield
    trace.TRACER.configure(path="", echo=None)


# ------------------------------------------------------------------ 트레이스 단위
def test_redaction_of_secrets():
    r = trace.redact({"password": "hunter2", "db_password_file": "/etc/pw", "cmd": f"echo {PRIV}",
                      "hdr": "Authorization: Bearer abcdef123456789", "nested": {"token": "t", "ok": 1}, "tokens_env": "X",
                      "blob": b"\x00\x01", "api_key": "k", "empty_password": ""})
    assert r["password"] == "[REDACTED]" and r["nested"]["token"] == "[REDACTED]" and r["api_key"] == "[REDACTED]"
    assert r["db_password_file"] == "/etc/pw" and r["tokens_env"] == "X"      # 경로·환경변수 '이름'은 진단에 필요
    assert "MIIEvQ" not in r["cmd"] and "[REDACTED PRIVATE KEY]" in r["cmd"]
    assert "abcdef123456789" not in r["hdr"] and r["blob"] == "<2 bytes>" and r["empty_password"] == ""
    assert len(trace.redact("x" * 5000)) < 700


def test_span_success_error_and_nesting_run_id():
    with trace.run("t") as rid:
        with trace.span("c", "ok", a=1) as ctx:
            ctx["extra"] = "v"
        with pytest.raises(ValueError):
            with trace.span("c", "bad", password="p"):
                raise ValueError("boom " + PRIV)
        with trace.run("inner") as rid2:
            assert rid2 == rid                              # 이미 작업 안이면 같은 ID 재사용
    evs = trace.TRACER.events(run_id=rid)
    steps = [(e["step"], e["level"]) for e in evs]
    assert steps == [("ok.start", "debug"), ("ok", "info"), ("bad.start", "debug"), ("bad", "error")]
    ok, bad = evs[1], evs[3]
    assert ok["extra"] == "v" and ok["a"] == 1 and "ms" in ok
    assert bad["error"] == "ValueError" and "MIIEvQ" not in json.dumps(bad) and bad["password"] == "[REDACTED]" and bad["where"]
    assert trace.TRACER.events(level="error") == [bad]


def test_file_sink_perms_rotation_and_reader(tmp_path):
    f = tmp_path / "d" / "trace.jsonl"
    trace.TRACER.configure(path=str(f), max_bytes=400)
    for i in range(20):
        trace.event("c", "s", n=i, secret="x")
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600 and os.path.exists(str(f) + ".1")
    got = trace.read_file(str(f))
    assert got and got[-1]["n"] == 19 and all(e["secret"] == "[REDACTED]" for e in got)
    assert "secret" not in open(f).read().replace('"secret": "[REDACTED]"', "")
    trace.TRACER.configure(max_bytes=5_000_000)


def test_echo_failure_does_not_break_work():
    trace.TRACER.configure(echo=lambda s: 1 / 0)
    trace.event("c", "s")                                    # 예외가 새어 나오지 않는다


def test_env_configuration(tmp_path):
    lines = []
    trace.configure_from_env({"X_TRACE_FILE": str(tmp_path / "t.jsonl"), "X_DEBUG": "1"}, prefix="X")
    trace.TRACER.configure(echo=lines.append)
    trace.event("c", "s")
    assert os.path.exists(tmp_path / "t.jsonl") and "c/s" in lines[0]


def test_cli_viewer(tmp_path, capsys):
    f = tmp_path / "t.jsonl"
    trace.TRACER.configure(path=str(f))
    with trace.run("r") as rid:
        trace.event("a", "one")
        trace.event("a", "two", "error", message="x")
    trace.event("b", "other")
    assert trace.main([str(f), "--errors"]) == 0
    out = capsys.readouterr().out
    assert "a/two" in out and "a/one" not in out
    trace.main([str(f), "--run", rid])
    assert "b/other" not in capsys.readouterr().out


# ------------------------------------------------------------------ 관리자 API
@pytest.fixture
def api(tmp_path, sandbox):
    app = create_app({"DATA_DIR": str(tmp_path / "data"), "ADMIN_USER": "root1", "ADMIN_PASSWORD": PW, "SECURE_COOKIE": False},
                     executor_factory=lambda t: SandboxExecutor(sandbox.path), sleep=lambda s: None)
    c = app.test_client()
    assert c.post("/auth/login", json={"username": "root1", "password": PW}).status_code == 200
    return type("A", (), {"app": app, "c": c, "box": sandbox})


def test_debug_endpoints_admin_only(api):
    anon = api.app.test_client()
    for p in ("/debug/events", "/debug/selfcheck", "/debug/bundle"):
        assert anon.get(p).status_code == 401
    api.c.post("/users", json={"username": "op9", "password": PW + "9", "role": "operator"})
    o = api.app.test_client()
    o.post("/auth/login", json={"username": "op9", "password": PW + "9"})
    for p in ("/debug/events", "/debug/selfcheck", "/debug/bundle"):
        assert o.get(p).status_code == 403


def test_probe_steps_visible_in_events(api):
    api.box.put("/etc/nginx/ssl/a.crt", cpem(make_cert("a.test")[1]))
    r = api.c.post("/servers/probe", json={"hostname": "web1.example", "account": "certscan"})
    assert r.status_code == 200 and r.headers["X-Request-Id"]
    evs = api.c.get("/debug/events?limit=100").json["events"]
    steps = [(e["component"], e["step"]) for e in evs]
    assert ("probe", "ssh_connected") in steps and ("probe", "check_connection") in steps and ("api", "request") in steps
    run_ids = {e["run_id"] for e in evs if e["component"] == "probe"}
    assert run_ids and all(x.startswith("req-") for x in run_ids)                   # 요청 단위로 묶임
    one = api.c.get(f"/debug/events?run_id={sorted(run_ids)[0]}").json["events"]
    assert {e["component"] for e in one} >= {"probe", "api"}


def test_failed_probe_records_cause_and_raw_error_only_in_admin_debug(api):
    api.app.extensions["certpilot"]["service"].scanner.executor_factory = (
        lambda t: (_ for _ in ()).throw(RemoteError(FailureCause.TIMEOUT, "raw detail ssh timeout")))
    r = api.c.post("/servers/probe", json={"hostname": "h.example", "account": "u"})
    assert "raw detail" not in r.get_data(as_text=True)                              # 일반 응답은 원문 비노출(기존 정책 유지)
    errs = api.c.get("/debug/events?level=warning").json["events"]
    assert any(e["step"] == "ssh_failed" and e["cause"] == "TIMEOUT" and "raw detail" in e["detail"] for e in errs)


def test_unhandled_exception_returns_request_id_and_traces(api):
    svc = api.app.extensions["certpilot"]["service"]
    svc.overview = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db exploded " + PRIV))
    r = api.c.get("/servers", headers={"X-Request-Id": "abc123"})
    assert r.status_code == 500 and r.json["error"]["code"] == "internal" and "abc123" in r.json["error"]["message"]
    assert "MIIEvQ" not in r.get_data(as_text=True)
    e = [x for x in api.c.get("/debug/events?level=error").json["events"] if x["step"] == "unhandled_exception"][0]
    assert e["run_id"] == "req-abc123" and e["error"] == "RuntimeError" and "MIIEvQ" not in json.dumps(e) and e["traceback"]
    assert api.c.get("/nope").status_code == 404                                    # HTTP 오류는 그대로


def test_selfcheck_and_bundle_have_no_secrets(api):
    sc = api.c.get("/debug/selfcheck").json
    assert sc["ok"] and {"db", "audit_chain", "admin_exists", "data_dir_writable"} <= {c["name"] for c in sc["checks"]}
    api.c.post("/servers", json={"name": "s1", "hostname": "h.example", "account": "u"})
    b = api.c.get("/debug/bundle")
    assert "attachment" in b.headers["Content-Disposition"]
    text = b.get_data(as_text=True)
    assert PW not in text and "password_hash" not in text and json.loads(text)["servers"][0]["name"] == "s1"
    assert any(e["event_type"] == "debug_bundle" for e in api.c.get("/audit-logs").json["logs"])


def test_frontend_has_debug_view():
    html = open(os.path.join(os.path.dirname(__file__), "..", "frontend", "templates", "index.html"), encoding="utf-8").read()
    js = open(os.path.join(os.path.dirname(__file__), "..", "frontend", "js", "app.js"), encoding="utf-8").read()
    assert 'data-view="debug"' in html and 'id="view-debug"' in html and "/debug/events" in js and "요청 ID" in js


# ------------------------------------------------------------------ certdeploy trace / diagnose
def make_cfg(tmp_path, reload_cmd="true", extra=None):
    cert_f, key_f = make_pki(tmp_path, "tls", ("univ.example", "*.univ.example"))[:2]
    web = tmp_path / "web"
    web.mkdir()
    cfg = {"state_dir": str(tmp_path / "state"), "audit_log": str(tmp_path / "audit"),
           "certificate": {"cert_file": str(cert_f), "key_file": str(key_f)},
           "targets": [{"name": "web1", "type": "generic", "check_cmd": "true", "reload_cmd": reload_cmd,
                        "files": [{"path": str(web / "s.crt"), "content": "fullchain"}, {"path": str(web / "s.key"), "content": "key"}]}]}
    cfg.update(extra or {})
    p = tmp_path / "cd.yml"
    p.write_text(yaml.safe_dump(cfg))
    return str(p)


def run(cfg, *args, env=None):
    return CliRunner().invoke(main, ["-c", cfg, *args], env=env, catch_exceptions=False)


def test_deploy_failure_is_diagnosable_via_trace(tmp_path):
    cfg = make_cfg(tmp_path, reload_cmd="echo 'nginx: bad directive on line 7' >&2; false")
    r = run(cfg, "deploy")
    assert r.exit_code == 1 and "롤백" in r.output
    t = run(cfg, "trace", "--errors")
    assert "deploy/reload_cmd" in t.output and "bad directive on line 7" in t.output and "deploy/failure" in t.output
    full = run(cfg, "trace", "--debug", "-n", "200").output
    for step in ("served_serial", "connect", "install_file", "check_cmd", "reload_cmd", "failure", "target"):
        assert f"deploy/{step}" in full, step
    assert os.path.getsize(tmp_path / "state" / "trace.jsonl") > 0
    assert stat.S_IMODE(os.stat(tmp_path / "state" / "trace.jsonl").st_mode) == 0o600


def test_debug_flag_streams_steps_to_stderr(tmp_path):
    cfg = make_cfg(tmp_path)
    r = CliRunner().invoke(main, ["-c", cfg, "--debug", "deploy"], catch_exceptions=False)
    assert r.exit_code == 0 and "deploy/install_file" in r.stderr and "deploy/reload_cmd" in r.stderr
    assert "deploy/install_file" not in r.stdout


def test_diagnose_bundle_masks_secrets_and_lists_problems(tmp_path):
    cfg = make_cfg(tmp_path, extra={"notify": {"smtp": {"host": "smtp.example", "from": "a@b.c", "to": ["x@y.z"],
                                                          "password_env": "SMTP_PW"}, "webhook": {"url_env": "HOOK"}}})
    run(cfg, "deploy")
    out = tmp_path / "diag.json"
    r = run(cfg, "diagnose", "--out", str(out))
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    text = out.read_text()
    assert "PRIVATE KEY" not in text
    b = json.loads(text)
    assert b["certificates"][0]["certificate"]["ok"] and b["events"] and any(c["name"].endswith("last_run") for c in b["checks"])
    os.chmod(b["certificates"][0]["key_file"], 0o644)
    bad = run(cfg, "diagnose")
    assert bad.exit_code == 1 and "key_permissions" in bad.output and "chmod 600" in bad.output
    assert run(str(tmp_path / "nope.yml"), "diagnose").exit_code == 1


class Mon(BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):
        path = self.path.split("?")[0]
        body = self.routes.get(path)
        if body is None:
            self.send_response(404); self.end_headers(); return
        self.send_response(200); self.end_headers(); self.wfile.write(body if isinstance(body, bytes) else json.dumps(body).encode())

    def log_message(self, *a):
        pass


@pytest.fixture
def mon():
    srv = HTTPServer(("127.0.0.1", 0), Mon)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_check_monitoring_reports_down_targets_and_missing_metrics(mon):
    srv, url = mon
    Mon.routes = {
        "/api/v1/targets": {"data": {"activeTargets": [
            {"labels": {"job": "ssl-endpoints", "instance": "a:443"}, "health": "up"},
            {"labels": {"job": "ssl-endpoints", "instance": "b:443"}, "health": "down", "lastError": "connection refused"}]}},
        "/api/v1/rules": {"data": {"groups": [{"rules": [{"health": "ok"}, {"health": "err"}]}]}},
        "/api/v1/alerts": {"data": {"alerts": [{"state": "firing", "labels": {"alertname": "CertExpiringSoon"}}]}},
        "/api/v1/query": {"data": {"result": []}}, "/api/v2/status": {}, "/metrics": b"# nothing\n"}
    checks = {c["name"]: c for c in diag.check_monitoring(url, url, url)}
    assert not checks["prometheus.targets"]["ok"] and "b:443: connection refused" in checks["prometheus.targets"]["detail"]
    assert not checks["prometheus.rules"]["ok"] and checks["prometheus.alerts"]["ok"] and "CertExpiringSoon" in checks["prometheus.alerts"]["detail"]
    assert not checks["prometheus.certdeploy_metrics"]["ok"] and "pushgateway" in checks["prometheus.certdeploy_metrics"]["hint"]
    assert checks["alertmanager.reachable"]["ok"] and not checks["pushgateway.certdeploy_metrics"]["ok"]
    Mon.routes["/api/v1/query"] = {"data": {"result": [{"metric": {}, "value": [0, "1"]}]}}
    Mon.routes["/metrics"] = b'certdeploy_last_run_timestamp_seconds{cert="x"} 1\n'
    checks = {c["name"]: c for c in diag.check_monitoring(url, None, url)}
    assert checks["prometheus.certdeploy_metrics"]["ok"] and checks["pushgateway.certdeploy_metrics"]["ok"]


def test_check_monitoring_unreachable():
    c = diag.check_monitoring("http://127.0.0.1:9")[0]
    assert not c["ok"] and c["name"] == "prometheus.reachable" and c["hint"]


def test_diagnose_reports_invalid_config_without_crashing(tmp_path):
    p = tmp_path / "bad.yml"
    p.write_text(yaml.safe_dump({"targets": []}))
    r = run(str(p), "diagnose")
    assert r.exit_code == 1 and "[문제] config" in r.output and "targets" in r.output


def test_frontend_registration_has_os_selector():
    base = os.path.join(os.path.dirname(__file__), "..", "frontend")
    html = open(os.path.join(base, "templates", "index.html"), encoding="utf-8").read()
    js = open(os.path.join(base, "js", "app.js"), encoding="utf-8").read()
    assert 'id="f-os"' in html and "/os-profiles" in js and "os_type: $('f-os').value" in js and "mismatch" in js
