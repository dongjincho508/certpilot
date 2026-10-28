"""certdeploy 추가 기능: 다중 인증서·defaults·알림 채널·보고/메트릭/감사·사전 점검·백업·발급 백오프·scaffold."""
import io
import json
import os
import shutil
import smtplib
import subprocess
import tarfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import yaml
from click.testing import CliRunner

from certdeploy import backup as bk
from certdeploy import runlog
from certdeploy.bundle import key_permission_problems, load_bundle
from certdeploy.cli import main
from certdeploy.config import ConfigError, NotifyCfg, SmtpCfg, WebhookCfg, parse_config
from certdeploy.engine import Deployer, TargetResult
from certdeploy.issuer import BackoffActive, IssueBackoff, IssueError, LegoIssuer, build_command
from certdeploy.notify import (AlertmanagerNotifier, CompositeNotifier, NullNotifier, SmtpNotifier, WebhookNotifier,
                               build_notifier)
from certdeploy.preflight import run_preflight
from certdeploy.state import State
from certdeploy.transport import LocalTransport
from lego_fake import install_fake_lego
from pki_helpers import make_pki

TARGET = {"name": "w", "type": "apache", "cert_path": "/c", "key_path": "/k"}
CERT = {"certificate": {"cert_file": "/a.crt", "key_file": "/a.key"}}


# ================================================================== 설정: defaults · 다중 인증서 · 새 옵션
def test_defaults_are_merged_into_targets_with_nested_override():
    cfg = parse_config({**CERT, "defaults": {
        "transport": {"kind": "ssh", "user": "deploy", "key_file": "/k", "known_hosts": "/kh"},
        "verify": {"port": 8443, "strict": True}, "soak_seconds": 0},
        "targets": [{**TARGET, "name": "a", "transport": {"host": "a.univ.example"}, "verify": {"host": "a.univ.example"}},
                    {**TARGET, "name": "b", "transport": {"host": "b.univ.example", "user": "other"},
                     "verify": {"host": "b.univ.example", "port": 443}}]})
    a, b = cfg.targets
    assert a.transport == {"kind": "ssh", "user": "deploy", "key_file": "/k", "known_hosts": "/kh", "host": "a.univ.example"}
    assert b.transport["user"] == "other" and b.transport["host"] == "b.univ.example"        # 대상 값이 우선
    assert (a.verify.port, a.verify.strict) == (8443, True) and b.verify.port == 443 and b.verify.strict is True


def test_multiple_certificates_have_separate_state_and_selection():
    cfg = parse_config({"state_dir": "/var/lib/cd", "certificates": [
        {"name": "wildcard", **CERT, "targets": [TARGET]},
        {"name": "portal", "certificate": {"cert_file": "/p.crt", "key_file": "/p.key"},
         "targets": [{**TARGET, "name": "p1"}]}]})
    assert [c.name for c in cfg.certs] == ["wildcard", "portal"]
    assert [c.state_dir for c in cfg.certs] == ["/var/lib/cd/wildcard", "/var/lib/cd/portal"]
    assert [c.name for c in cfg.select("portal")] == ["portal"] and len(cfg.select(None)) == 2
    with pytest.raises(ConfigError, match="알 수 없는 인증서"):
        cfg.select("nope")
    with pytest.raises(AttributeError):
        cfg.targets          # 인증서가 둘 이상이면 모호하므로 위임하지 않는다
    # 단일 구성은 기존 방식 그대로
    single = parse_config({**CERT, "targets": [TARGET]})
    assert single.certs[0].name == "default" and single.certs[0].state_dir == "/var/lib/certdeploy" and single.targets


@pytest.mark.parametrize("data,msg", [
    ({"certificates": [{"name": "a", **CERT, "targets": [TARGET]}], "targets": [TARGET]}, "함께 쓸 수 없습니다"),
    ({"certificates": [{"name": "a", **CERT, "targets": [TARGET]}, {"name": "a", **CERT, "targets": [TARGET]}]}, "중복"),
    ({"certificates": [{"name": "bad name", **CERT, "targets": [TARGET]}]}, "name"),
    ({"certificates": [{"name": "a", **CERT}]}, "targets 가 비어"),
    ({**CERT, "targets": [TARGET], "notify": {"smtp": {"host": "h"}}}, "notify.smtp"),
    ({**CERT, "targets": [TARGET], "notify": {"webhook": {"format": "slack"}}}, "url_env 또는 url_file"),
    ({**CERT, "targets": [TARGET], "notify": {"webhook": {"url_env": "X", "format": "kakao"}}}, "format"),
    ({**CERT, "targets": [TARGET], "audit_log": "relative"}, "audit_log"),
    ({**CERT, "targets": [{**TARGET, "health": {"url": "ftp://x"}}]}, "health.url"),
    ({**CERT, "targets": [{**TARGET, "soak_seconds": 30}]}, "soak_seconds"),
    ({**CERT, "targets": [{**TARGET, "type": "tomcat", "keystore_path": "/k", "reload_cmd": "true"}]}, "password"),
    ({**CERT, "options": {"verify_attempts": "abc"}}, "options.verify_attempts"),
])
def test_new_config_validation(data, msg):
    data.setdefault("targets", data.get("targets", [TARGET])) if "certificates" not in data else None
    with pytest.raises(ConfigError, match=msg):
        parse_config(data)


def test_notify_section_parsed_without_secrets_in_file():
    cfg = parse_config({**CERT, "targets": [TARGET], "notify": {
        "alertmanager_url": "http://am:9093", "pushgateway_url": "http://pg:9091", "metrics_file": "/var/lib/m/certdeploy.prom",
        "smtp": {"host": "smtp.univ.example", "from": "cd@univ.example", "to": "a@univ.example, b@univ.example",
                 "password_env": "SMTP_PW", "username": "cd"},
        "webhook": {"url_env": "HOOK_URL", "format": "teams", "on_success": True}}})
    n = cfg.notify
    assert n.smtp.to == ["a@univ.example", "b@univ.example"] and n.smtp.password_env == "SMTP_PW" and n.smtp.starttls
    assert n.webhook.format == "teams" and n.webhook.on_success and n.metrics_file.endswith(".prom")


# ================================================================== 발급: 백오프 · 옵션
LEGO = {"email": "ops@univ.example", "dns_provider": "infoblox", "domains": ["univ.example", "*.univ.example"], "path": "/l"}


def test_lego_extra_options_and_http_mode():
    c = build_command({**LEGO, "key_type": "ec256", "dns_propagation_wait": "90s"}, "run")
    assert c[c.index("--key-type") + 1] == "ec256" and c[c.index("--dns.propagation-wait") + 1] == "90s"
    http = build_command({"email": "a@b.c", "domains": ["www.univ.example"], "http_webroot": "/var/www/html", "path": "/l"}, "run")
    assert "--http" in http and http[http.index("--http.webroot") + 1] == "/var/www/html" and "--dns" not in http
    with pytest.raises(IssueError, match="와일드카드"):
        build_command({**LEGO, "http_webroot": "/w"}, "run")
    with pytest.raises(IssueError, match="key_type"):
        build_command({**LEGO, "key_type": "dsa1024"}, "run")
    with pytest.raises(IssueError, match="dns_provider 또는 lego.http_webroot"):
        build_command({"email": "a@b.c", "domains": ["x.y"]}, "run")


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


def test_backoff_blocks_after_failure_and_resets_on_success(tmp_path):
    clock = Clock()
    calls = []

    class R:
        def __init__(self, rc):
            self.returncode, self.stdout, self.stderr = rc, "", "429 rate limited"
    results = [R(1), R(0)]

    def runner(cmd, env, timeout):
        calls.append(cmd)
        return results.pop(0)
    iss = LegoIssuer({**LEGO, "path": str(tmp_path / "lego")}, runner=runner)
    bo = IssueBackoff(str(tmp_path / "st"), clock)
    with pytest.raises(IssueError, match="429"):
        iss.ensure(backoff=bo, backoff_minutes=60)
    assert bo.failures == 1
    clock.now += timedelta(minutes=30)
    with pytest.raises(BackoffActive) as e:
        iss.ensure(backoff=IssueBackoff(str(tmp_path / "st"), clock), backoff_minutes=60)     # 디스크에서 상태를 다시 읽음
    assert len(calls) == 1 and e.value.failures == 1 and "13:00" in str(e.value)               # lego 를 호출하지 않음
    assert iss.ensure(backoff=IssueBackoff(str(tmp_path / "st"), clock), backoff_minutes=60, ignore_backoff=True) == "run"
    clock.now += timedelta(minutes=1)
    assert IssueBackoff(str(tmp_path / "st"), clock).failures == 0                              # 성공하면 초기화
    assert oct(os.stat(tmp_path / "st" / "lego.json").st_mode & 0o777) == "0o600"


def test_backoff_expires_after_window(tmp_path):
    clock = Clock()
    bo = IssueBackoff(str(tmp_path), clock)
    bo.record_failure()
    clock.now += timedelta(minutes=61)
    bo.check(60)          # 대기 시간이 지나면 예외 없음


# ================================================================== 키 파일 권한
def test_key_permission_problems(tmp_path):
    k = tmp_path / "a.key"
    k.write_text("x")
    os.chmod(k, 0o644)
    assert any("권한이 너무 넓습니다" in p for p in key_permission_problems(str(k)))
    os.chmod(k, 0o600)
    assert key_permission_problems(str(k)) == []
    os.chmod(tmp_path, 0o777)
    assert any("쓰기 가능" in p for p in key_permission_problems(str(k)))
    os.chmod(tmp_path, 0o755)
    assert key_permission_problems(str(tmp_path / "missing")) == []


# ================================================================== 알림 채널
class FakeSmtp:
    sent, logins, tls = [], [], []
    fail = False

    def __init__(self, host, port, timeout=None):
        if FakeSmtp.fail:
            raise smtplib.SMTPConnectError(421, "down")
        self.host, self.port = host, port

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        FakeSmtp.tls.append(True)

    def login(self, u, p):
        FakeSmtp.logins.append((u, p))

    def send_message(self, m):
        FakeSmtp.sent.append(m)


@pytest.fixture(autouse=True)
def reset_smtp():
    FakeSmtp.sent, FakeSmtp.logins, FakeSmtp.tls, FakeSmtp.fail = [], [], [], False


def smtp_cfg(**kw):
    return SmtpCfg("smtp.univ.example", "cd@univ.example", ["ops@univ.example", "dba@univ.example"], username="cd",
                   password_env="PW", **kw)


def test_smtp_failure_always_sent_success_only_when_enabled():
    n = SmtpNotifier(smtp_cfg(on_success=False), environ={"PW": "s3cret"}, smtp_factory=FakeSmtp)
    n.fire("web1", "인증서 배포 실패: web1", "점검 실패", "critical")
    assert len(FakeSmtp.sent) == 1 and "CRITICAL" in FakeSmtp.sent[0]["Subject"] and "web1" in FakeSmtp.sent[0]["Subject"]
    assert FakeSmtp.sent[0]["To"] == "ops@univ.example, dba@univ.example"
    assert FakeSmtp.tls == [True] and FakeSmtp.logins == [("cd", "s3cret")]
    n.summary("배포 완료", "본문", ok=True)
    assert len(FakeSmtp.sent) == 1                              # on_success=False → 성공 요약은 보내지 않음
    n.summary("배포 문제", "본문", ok=False)
    assert len(FakeSmtp.sent) == 2 and FakeSmtp.sent[1]["Subject"].startswith("[certdeploy] 실패")
    SmtpNotifier(smtp_cfg(on_success=True), environ={"PW": "x"}, smtp_factory=FakeSmtp).summary("배포 완료", "본문", True)
    assert len(FakeSmtp.sent) == 3


def test_smtp_password_from_file_and_unreachable_server_never_raises(tmp_path):
    pwf = tmp_path / "pw"
    pwf.write_text("filepw\n")
    c = SmtpCfg("h", "a@b.c", ["x@y.z"], username="u", password_file=str(pwf))
    SmtpNotifier(c, environ={}, smtp_factory=FakeSmtp).fire("t", "s", "d")
    assert FakeSmtp.logins == [("u", "filepw")]
    FakeSmtp.fail = True
    SmtpNotifier(c, environ={}, smtp_factory=FakeSmtp).fire("t", "s", "d")      # 예외 없음


class Hook(BaseHTTPRequestHandler):
    bodies = []

    def do_POST(self):
        Hook.bodies.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def hook():
    Hook.bodies = []
    srv = HTTPServer(("127.0.0.1", 0), Hook)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/hook/TOKEN"
    srv.shutdown()


@pytest.mark.parametrize("fmt,check", [
    ("generic", lambda b: b["ok"] is False and b["title"] == "T" and b["source"] == "certdeploy"),
    ("slack", lambda b: set(b) == {"text"} and "🚨 T" in b["text"] and "본문" in b["text"]),
    ("teams", lambda b: b["type"] == "message" and b["attachments"][0]["content"]["type"] == "AdaptiveCard"),
])
def test_webhook_formats_and_url_from_env(hook, fmt, check):
    n = WebhookNotifier(WebhookCfg(url_env="HOOK", format=fmt), environ={"HOOK": hook})
    n.summary("T", "본문", ok=False)
    path, body = Hook.bodies[-1]
    assert path == "/hook/TOKEN" and check(body)


def test_webhook_success_gating_url_file_and_missing_url(hook, tmp_path):
    f = tmp_path / "url"
    f.write_text(hook + "\n")
    n = WebhookNotifier(WebhookCfg(url_file=str(f), format="slack", on_success=False), environ={})
    n.summary("OK", "x", ok=True)
    assert Hook.bodies == []
    n.fire("t", "S", "D")
    assert len(Hook.bodies) == 1
    WebhookNotifier(WebhookCfg(url_env="NOPE"), environ={}).summary("x", "y", False)     # URL 없음 → 조용히 건너뜀
    WebhookNotifier(WebhookCfg(url_env="U"), environ={"U": "http://127.0.0.1:9/x"}, timeout=1).fire("t", "s", "d")


def test_composite_and_builder(hook):
    calls = []

    class N(NullNotifier):
        def fire(self, *a, **k):
            calls.append(("fire", a[0]))

        def resolve(self, t):
            calls.append(("resolve", t))

        def summary(self, *a, **k):
            calls.append(("summary", a[0]))
    c = CompositeNotifier([N(), N()])
    c.fire("t", "s", "d")
    c.resolve("t")
    c.summary("T", "x", True)
    assert len(calls) == 6
    assert isinstance(build_notifier(NotifyCfg()), NullNotifier)
    full = build_notifier(NotifyCfg("http://am:9093", SmtpCfg("h", "a@b.c", ["x@y.z"]), WebhookCfg(url_env="U")))
    assert [type(x) for x in full.notifiers] == [AlertmanagerNotifier, SmtpNotifier, WebhookNotifier]


# ================================================================== 보고서 · 메트릭 · 감사 로그
def make_bundle(tmp_path, name="b", **kw):
    cert, key, *_ = make_pki(tmp_path, name=name, **kw)
    return load_bundle(str(cert), str(key))


def certset(tmp_path, notify=None, audit=True):
    cfg = parse_config({**CERT, "state_dir": str(tmp_path / "st"), "targets": [TARGET],
                        "audit_log": str(tmp_path / "audit") if audit else None,
                        "notify": notify or {}})
    return cfg.certs[0]


def test_report_and_markdown(tmp_path):
    b = make_bundle(tmp_path)
    t0 = datetime.now(timezone.utc)
    rep = runlog.build_report("default", b, [TargetResult("a", "deployed", "배포·확인 완료"), TargetResult("b", "failed", "점검 실패 | 롤백")], t0, t0)
    assert rep["ok"] is False and rep["certificate"]["serial"] == f"{b.serial:x}"
    md = runlog.report_markdown(rep)
    assert "문제 있음" in md and "| a | 배포 완료 |" in md and "점검 실패 / 롤백" in md      # 표를 깨는 | 는 이스케이프
    assert runlog.build_report("d", b, [TargetResult("a", "skipped")], t0, t0)["ok"] is True


def test_metrics_text_is_valid_prometheus_format(tmp_path):
    b = make_bundle(tmp_path)
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    rep = runlog.build_report("wild\"card", b, [TargetResult("web-1", "deployed"), TargetResult("web-2", "rolled_back")], now, now)
    text = runlog.metrics_text(rep, {}, prev_success_ts=1000.0, issue_failures=2, now=now)
    assert 'certdeploy_target_ok{cert="wild\\"card",target="web-1"} 1' in text
    assert 'certdeploy_target_ok{cert="wild\\"card",target="web-2"} 0' in text
    assert 'certdeploy_target_status{cert="wild\\"card",target="web-2",status="rolled_back"} 1' in text
    assert 'certdeploy_last_success_timestamp_seconds{cert="wild\\"card"} 1000' in text      # 실패한 실행은 이전 성공 시각 유지
    assert 'certdeploy_issue_failures{cert="wild\\"card"} 2' in text
    pt = shutil.which("promtool") or os.environ.get("PROMTOOL")
    if pt:
        r = subprocess.run([pt, "check", "metrics"], input=text, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
    ok = runlog.metrics_text(runlog.build_report("c", b, [TargetResult("a", "skipped")], now, now), {}, None, 0, now)
    assert f'certdeploy_last_success_timestamp_seconds{{cert="c"}} {int(now.timestamp())}' in ok


class Pg(BaseHTTPRequestHandler):
    reqs = []

    def do_POST(self):
        Pg.reqs.append((self.path, self.headers.get("Authorization"), self.rfile.read(int(self.headers["Content-Length"])).decode()))
        self.send_response(202)
        self.end_headers()

    def log_message(self, *a):
        pass


def test_push_metrics_and_textfile(tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), Pg)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    Pg.reqs = []
    url = f"http://127.0.0.1:{srv.server_port}"
    assert runlog.push_metrics(url, "wild card", "m 1\n", "u", "p")
    path, auth, body = Pg.reqs[0]
    assert path == "/metrics/job/certdeploy/cert/wild%20card" and auth.startswith("Basic ") and body == "m 1\n"
    srv.shutdown()
    assert runlog.push_metrics("http://127.0.0.1:9", "c", "m 1\n", timeout=1) is False       # 실패해도 예외 없음
    f = tmp_path / "tf" / "certdeploy.prom"
    runlog.write_metrics_file(str(f), "x 1\n")
    assert f.read_text() == "x 1\n" and oct(os.stat(f).st_mode & 0o777) == "0o644" and not [p for p in os.listdir(f.parent) if p.startswith(".tmp")]


def test_finish_run_writes_report_audit_metrics_and_summaries(tmp_path):
    b = make_bundle(tmp_path)
    mf = tmp_path / "m.prom"
    cs = certset(tmp_path, notify={"metrics_file": str(mf)})
    sums = []

    class N(NullNotifier):
        def summary(self, title, text, ok):
            sums.append((title, ok))
    t0 = datetime.now(timezone.utc)
    rep = runlog.finish_run(cs, b, [TargetResult("w", "deployed", "ok")], t0, N())
    assert rep["ok"] and runlog.load_report(cs.state_dir)["results"][0]["target"] == "w"
    assert 'certdeploy_run_ok{cert="default"} 1' in mf.read_text()
    from certpilot_core.audit_storage import AuditLogReader
    r = AuditLogReader(cs.audit_dir).verify_integrity()
    assert r["integrity_valid"] and r["total_logs"] == 2            # 대상 1 + 실행 요약 1
    assert sums == [("인증서 배포 완료 — default", True)]
    first_ok = runlog.load_report(cs.state_dir)["last_success_ts"]
    # 변경이 없던(건너뜀) 실행은 요약 알림을 보내지 않는다
    runlog.finish_run(cs, b, [TargetResult("w", "skipped")], t0, N())
    assert len(sums) == 1
    # 실패 실행: last_success_ts 는 이전 값 유지, 요약은 실패로 전달
    rep2 = runlog.finish_run(cs, b, [TargetResult("w", "failed", "x")], t0, N())
    assert rep2["last_success_ts"] != 0 and sums[-1][1] is False
    assert runlog.load_report(cs.state_dir)["last_success_ts"] >= first_ok
    # dry-run 은 아무것도 기록하지 않는다
    cs2 = certset(tmp_path / "other")
    runlog.finish_run(cs2, b, [TargetResult("w", "dry_run")], t0, N())
    assert not os.path.exists(cs2.state_dir)


def test_audit_log_tamper_detected_by_cli(tmp_path):
    b = make_bundle(tmp_path)
    cs = certset(tmp_path)
    runlog.finish_run(cs, b, [TargetResult("w", "deployed", "ok")], datetime.now(timezone.utc), NullNotifier())
    cfgfile = tmp_path / "c.yml"
    cfgfile.write_text(yaml.safe_dump({**CERT, "state_dir": cs.state_dir, "targets": [TARGET], "audit_log": cs.audit_dir}))
    r = CliRunner().invoke(main, ["-c", str(cfgfile), "verify-audit"])
    assert r.exit_code == 0 and '"integrity_valid": true' in r.output
    log = next(p for p in os.listdir(cs.audit_dir) if p.endswith(".log"))
    path = os.path.join(cs.audit_dir, log)
    text = open(path).read().replace("deploy_deployed", "deploy_hacked")
    open(path, "w").write(text)
    assert CliRunner().invoke(main, ["-c", str(cfgfile), "verify-audit"]).exit_code == 1


# ================================================================== 사전 점검
def pf_env(tmp_path, **target_over):
    cert, key, *_ = make_pki(tmp_path)
    web = tmp_path / "web"
    web.mkdir(exist_ok=True)
    t = {"name": "t1", "type": "generic", "files": [{"path": str(web / "a.crt"), "content": "fullchain"},
                                                     {"path": str(web / "a.key"), "content": "key"}],
         "check_cmd": "true", "reload_cmd": "true", **target_over}
    cfg = parse_config({"certificate": {"cert_file": str(cert), "key_file": str(key)}, "state_dir": str(tmp_path / "st"), "targets": [t]})
    d = Deployer(cfg, load_bundle(str(cert), str(key)), State(cfg.state_dir), transport_factory=lambda tr: LocalTransport(),
                 verifier=lambda *a, **k: 1, environ={})
    return d


def test_preflight_all_green(tmp_path):
    d = pf_env(tmp_path, verify={"host": "www.univ.example"})
    checks = run_preflight(d)
    assert all(c.ok for c in checks), [c for c in checks if not c.ok]
    names = " ".join(c.name for c in checks)
    assert "접속" in names and "디렉터리 쓰기" in names and "여유 공간" in names and "점검 명령(true)" in names and "현재 TLS" in names
    assert os.listdir(tmp_path / "web") == []                    # 아무것도 쓰지 않음


def test_preflight_detects_missing_dir_command_and_unreachable_tls(tmp_path):
    from certdeploy.verify import VerifyError
    d = pf_env(tmp_path, files=[{"path": "/no-such-dir-xyz/a.crt", "content": "cert"}],
               check_cmd="definitely-not-a-command --x", reload_cmd="a && b", verify={"host": "www.univ.example"})

    def down(*a, **k):
        raise VerifyError("연결 거부")
    d.verifier = down
    bad = {c.name: c.detail for c in run_preflight(d) if not c.ok}
    assert any("디렉터리 쓰기" in n for n in bad) and any("점검 명령(definitely-not-a-command)" in n for n in bad)
    assert "현재 TLS" in bad
    ok = {c.name for c in run_preflight(d) if c.ok}
    assert "재로드 명령" in ok                                    # 복합 명령은 점검을 생략(통과 처리)


def test_preflight_reports_missing_keystore_password_and_hook_binaries(tmp_path):
    d = pf_env(tmp_path, type="tomcat", format="pkcs12", files=None, keystore_path=str(tmp_path / "web" / "k.p12"),
               password_env="NOPE", pre_cmd="no-such-binary-xyz arg", reload_cmd="true")
    bad = [c for c in run_preflight(d) if not c.ok]
    assert any("비밀번호" in c.detail for c in bad) and any("pre_cmd" in c.name for c in bad)


def test_preflight_cli_exit_codes(tmp_path):
    cert, key, *_ = make_pki(tmp_path)
    cfgfile = tmp_path / "c.yml"
    web = tmp_path / "web"
    web.mkdir()
    cfg = {"certificate": {"cert_file": str(cert), "key_file": str(key)}, "state_dir": str(tmp_path / "st"),
           "targets": [{"name": "t1", "type": "generic", "check_cmd": "true", "reload_cmd": "true",
                        "files": [{"path": str(web / "a.crt"), "content": "cert"}]}]}
    cfgfile.write_text(yaml.safe_dump(cfg))
    r = CliRunner().invoke(main, ["-c", str(cfgfile), "preflight"])
    assert r.exit_code == 0 and "✔ [t1] 접속" in r.output and "실패 0건" in r.output
    cfg["targets"][0]["files"][0]["path"] = "/missing-dir-abc/a.crt"
    cfgfile.write_text(yaml.safe_dump(cfg))
    r2 = CliRunner().invoke(main, ["-c", str(cfgfile), "preflight"])
    assert r2.exit_code == 1 and "✘ [t1] 디렉터리 쓰기" in r2.output


# ================================================================== 백업 · 복원
def test_backup_roundtrip_wrong_password_and_tamper(tmp_path):
    src = tmp_path / "lego"
    (src / "certificates").mkdir(parents=True)
    key = src / "certificates" / "a.key"
    key.write_text("PRIVATE")
    os.chmod(key, 0o600)
    blob = bk.create_backup({"lego/default": str(src), "state/none": str(tmp_path / "missing")}, "correct horse battery")
    assert blob.startswith(b"CDBK1") and b"PRIVATE" not in blob                      # 평문이 보이지 않음
    dest = tmp_path / "restored"
    assert bk.restore_backup(blob, "correct horse battery", str(dest)) == ["lego"]
    assert (dest / "lego/default/certificates/a.key").read_text() == "PRIVATE"
    assert oct(os.stat(dest / "lego/default/certificates/a.key").st_mode & 0o777) == "0o600"
    with pytest.raises(bk.BackupError, match="복호화 실패"):
        bk.restore_backup(blob, "wrong password!!", str(tmp_path / "x"))
    tampered = blob[:-5] + bytes([blob[-5] ^ 1]) + blob[-4:]
    with pytest.raises(bk.BackupError, match="변조"):
        bk.restore_backup(tampered, "correct horse battery", str(tmp_path / "y"))
    with pytest.raises(bk.BackupError, match="12자"):
        bk.create_backup({"a": str(src)}, "short")
    with pytest.raises(bk.BackupError, match="백업 파일이 아닙니다"):
        bk.restore_backup(b"hello", "correct horse battery", str(tmp_path / "z"))


def _evil_backup(entry_name, kind="file", linkname=None, pw="correct horse battery"):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        ti = tarfile.TarInfo(entry_name)
        if kind == "symlink":
            ti.type, ti.linkname = tarfile.SYMTYPE, linkname
            tar.addfile(ti)
        else:
            data = b"x"
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    salt, nonce = os.urandom(16), os.urandom(12)
    return bk.MAGIC + salt + nonce + AESGCM(bk._key(pw, salt)).encrypt(nonce, buf.getvalue(), bk.MAGIC)


@pytest.mark.parametrize("blob_args", [("../escape.txt",), ("/abs/escape.txt",), ("ok/link", "symlink", "/etc/passwd")])
def test_restore_refuses_path_traversal_and_links(tmp_path, blob_args):
    with pytest.raises(bk.BackupError):
        bk.restore_backup(_evil_backup(*blob_args), "correct horse battery", str(tmp_path / "dest"))
    assert not (tmp_path / "escape.txt").exists()


def test_backup_restore_cli(tmp_path):
    lego = tmp_path / "lego"
    lego.mkdir()
    (lego / "acct.key").write_text("ACCOUNTKEY")
    cert, key, *_ = make_pki(tmp_path)
    cfgfile = tmp_path / "cd.yml"
    cfgfile.write_text(yaml.safe_dump({"state_dir": str(tmp_path / "st"), "lego": {**LEGO, "path": str(lego)},
                                       "certificate": {"cert_file": str(cert), "key_file": str(key)}, "targets": [TARGET]}))
    (tmp_path / "st").mkdir()
    (tmp_path / "st" / "state.json").write_text("{}")
    out = tmp_path / "backup.cdbk"
    env = {"BK_PW": "correct horse battery"}
    r = CliRunner().invoke(main, ["-c", str(cfgfile), "backup", "--out", str(out), "--passphrase-env", "BK_PW"], env=env)
    assert r.exit_code == 0 and oct(os.stat(out).st_mode & 0o777) == "0o600" and b"ACCOUNTKEY" not in out.read_bytes()
    r2 = CliRunner().invoke(main, ["-c", str(cfgfile), "restore", "--in", str(out), "--dest", str(tmp_path / "rest"),
                                   "--passphrase-env", "BK_PW"], env=env)
    assert r2.exit_code == 0 and (tmp_path / "rest/lego/default/acct.key").read_text() == "ACCOUNTKEY"
    assert (tmp_path / "rest/state/default/state.json").exists() and (tmp_path / "rest/config/cd.yml").exists()
    assert CliRunner().invoke(main, ["-c", str(cfgfile), "backup", "--out", str(out), "--passphrase-env", "NOPE"]).exit_code != 0
    bad = CliRunner().invoke(main, ["-c", str(cfgfile), "restore", "--in", str(out), "--dest", str(tmp_path / "r2"),
                                    "--passphrase-env", "BK_PW"], env={"BK_PW": "a different passphrase"})
    assert bad.exit_code != 0 and "복호화 실패" in bad.output


# ================================================================== scaffold
def test_scaffold_generates_valid_targets(tmp_path):
    csvf = tmp_path / "s.csv"
    csvf.write_text("name,host,type,port,canary,order,cert_path,key_path\n"
                    "web1,www1.univ.example,apache,443,yes,1,,\n"
                    "tc1,sugang.univ.example,tomcat,8443,,2,,\n"
                    "nx,proxy.univ.example,nginx,,,3,/etc/nginx/c.pem,/etc/nginx/k.pem\n", encoding="utf-8")
    r = CliRunner().invoke(main, ["-c", "unused.yml", "scaffold", str(csvf), "--user", "certdeploy"])
    assert r.exit_code == 0, r.output
    snippet = yaml.safe_load(r.output)
    ts = {t["name"]: t for t in snippet["targets"]}
    assert ts["web1"]["canary"] is True and ts["web1"]["transport"]["user"] == "certdeploy" and ts["web1"]["verify"]["port"] == 443
    assert ts["nx"]["cert_path"] == "/etc/nginx/c.pem" and ts["tc1"]["reload_cmd"].startswith("TODO")
    # 생성한 조각 + 필요한 항목을 채우면 설정으로 유효하다(tomcat 은 키스토어 정보 보완 필요)
    ts["tc1"].update(keystore_path="/opt/tomcat/k.p12", password_env="TC_PW", reload_cmd="true")
    cfg = parse_config({**CERT, "targets": list(ts.values())})
    assert [t.name for t in cfg.targets] == ["web1", "tc1", "nx"]


def test_scaffold_reports_row_errors(tmp_path):
    csvf = tmp_path / "bad.csv"
    csvf.write_text("name,host,type\nbad name!,h.example,apache\nok,h.example,iis\n", encoding="utf-8")
    r = CliRunner().invoke(main, ["-c", "unused.yml", "scaffold", str(csvf)])
    assert r.exit_code == 1 and "2행" in r.output and "3행" in r.output


# ================================================================== 다중 인증서 · 백오프 CLI 전 과정
@pytest.fixture
def multi(tmp_path):
    lego = install_fake_lego(tmp_path)
    web = tmp_path / "web"
    web.mkdir()

    def cert_spec(name, domains):
        return {"name": name, "lego": {"binary": lego, "email": "ops@univ.example", "dns_provider": "infoblox",
                                       "domains": domains, "path": str(tmp_path / f"lego-{name}"), "renew_days": 30},
                "targets": [{"name": f"{name}-web", "type": "generic", "check_cmd": "true", "reload_cmd": f"echo r >> {tmp_path}/{name}.log",
                             "files": [{"path": str(web / f"{name}.crt"), "content": "fullchain"},
                                       {"path": str(web / f"{name}.key"), "content": "key"}]}]}
    cfg = {"state_dir": str(tmp_path / "state"), "audit_log": str(tmp_path / "audit"),
           "notify": {"metrics_file": str(tmp_path / "m.prom")},
           "certificates": [cert_spec("wildcard", ["univ.example", "*.univ.example"]), cert_spec("portal", ["portal.univ.example"])]}
    path = tmp_path / "cd.yml"
    path.write_text(yaml.safe_dump(cfg, allow_unicode=True))
    return type("M", (), {"cfg": str(path), "tmp": tmp_path, "web": web, "raw": cfg})


def run(m, *args, env=None):
    return CliRunner().invoke(main, ["-c", m.cfg, *args], env=env, catch_exceptions=False)


def test_multi_certificate_issue_deploy_report_and_status(multi):
    r = run(multi, "issue")
    assert r.exit_code == 0 and "== wildcard ==" in r.output and "== portal ==" in r.output, r.output
    assert (multi.web / "wildcard.crt").exists() and (multi.web / "portal.crt").exists()
    assert os.path.isdir(multi.tmp / "state" / "wildcard") and os.path.isdir(multi.tmp / "state" / "portal")   # 상태 분리
    only = run(multi, "--cert", "portal", "deploy", "--force")
    assert "== wildcard ==" not in only.output and (multi.tmp / "portal.log").read_text().count("r") == 2       # 해당 인증서만
    j = json.loads(run(multi, "status", "--format", "json").output)
    assert {(x["cert"], x["target"]) for x in j} == {("wildcard", "wildcard-web"), ("portal", "portal-web")}
    assert all(x["recorded_status"] == "ok" and x["live"] == "unknown" for x in j)
    rep = run(multi, "--cert", "wildcard", "report", "--format", "json")
    assert json.loads(rep.output)["cert"] == "wildcard"
    assert "# 인증서 배포 보고 — portal" in run(multi, "--cert", "portal", "report").output
    metrics = (multi.tmp / "m.prom").read_text()
    assert 'cert="portal"' in metrics                              # 마지막으로 기록한 인증서의 지표(파일은 덮어씀)
    assert run(multi, "verify-audit").exit_code == 0
    amb = CliRunner().invoke(main, ["-c", multi.cfg, "--cert", "nope", "status"])
    assert amb.exit_code != 0 and "알 수 없는 인증서" in amb.output


def test_cli_rollback_requires_unambiguous_target(multi):
    run(multi, "issue")
    raw = yaml.safe_load(open(multi.cfg))
    raw["certificates"][1]["targets"][0]["name"] = "wildcard-web"       # 이름 충돌
    open(multi.cfg, "w").write(yaml.safe_dump(raw, allow_unicode=True))
    r = CliRunner().invoke(main, ["-c", multi.cfg, "rollback", "--target", "wildcard-web"])
    assert r.exit_code != 0 and "--cert" in r.output


def test_issue_failure_backoff_and_severity_via_cli(multi, tmp_path):
    am = []

    class Am(BaseHTTPRequestHandler):
        def do_POST(self):
            am.append(json.loads(self.rfile.read(int(self.headers["Content-Length"])))[0])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), Am)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    raw = yaml.safe_load(open(multi.cfg))
    raw["notify"]["alertmanager_url"] = f"http://127.0.0.1:{srv.server_port}"
    raw["certificates"] = raw["certificates"][:1]
    open(multi.cfg, "w").write(yaml.safe_dump(raw, allow_unicode=True))
    counter = tmp_path / "count"
    env = {"FAKE_LEGO_FAIL": "1", "FAKE_LEGO_COUNT": str(counter)}
    r1 = run(multi, "renew", env=env)
    assert r1.exit_code == 1 and "발급 실패" in r1.output
    fired = [a for a in am if a["labels"]["alertname"] == "CertDeployFailed"]
    assert fired[0]["labels"]["severity"] == "critical" and "사용 가능한 인증서 없음" in fired[0]["annotations"]["description"]
    r2 = run(multi, "renew", env=env)                                  # 대기 시간 안 → lego 호출 없이 건너뜀
    assert "발급 건너뜀" in r2.output and counter.read_text().count("call") == 1
    r3 = run(multi, "renew", "--ignore-backoff", env={"FAKE_LEGO_COUNT": str(counter)})   # 이번엔 성공
    assert r3.exit_code == 0 and counter.read_text().count("call") == 2
    lego_alerts = [a for a in am if a["labels"]["target"] == "lego:wildcard"]
    resolved = lego_alerts[-1]
    assert resolved["annotations"]["summary"] == "" and resolved["endsAt"] > resolved["startsAt"]      # 성공 후 해소 전송
    assert datetime.fromisoformat(resolved["endsAt"]) <= datetime.now(timezone.utc) + timedelta(seconds=2)
    srv.shutdown()


def test_validate_flags_loose_key_permissions(multi):
    run(multi, "issue")
    key = multi.tmp / "lego-portal" / "certificates" / "portal.univ.example.key"
    os.chmod(key, 0o644)
    r = CliRunner().invoke(main, ["-c", multi.cfg, "--cert", "portal", "validate"])
    assert r.exit_code == 1 and "권한이 너무 넓습니다" in r.output
    os.chmod(key, 0o600)
    assert CliRunner().invoke(main, ["-c", multi.cfg, "--cert", "portal", "validate"]).exit_code == 0


# ================================================================== 자체 점검에서 찾은 문제의 회귀 테스트
def test_hooks_do_not_receive_secret_environment_variables(tmp_path):
    """훅은 최소 환경만 받는다 — 키스토어 비밀번호 등 certdeploy 의 비밀 환경변수가 새지 않는다."""
    d = pf_env(tmp_path, pre_cmd="p", post_cmd="q", hook_env=["LB_API_TOKEN"])
    d.environ = {"PATH": "/usr/bin", "TOMCAT_KS_PASS": "supersecret", "SMTP_PASSWORD": "x", "LB_API_TOKEN": "lbtok"}
    env = d._hook_env(d.cfg.targets[0], "pre")
    assert "TOMCAT_KS_PASS" not in env and "SMTP_PASSWORD" not in env
    assert env["LB_API_TOKEN"] == "lbtok" and env["PATH"] == "/usr/bin"               # 명시적으로 허용한 변수만
    assert env["CERTDEPLOY_TARGET"] == "t1" and env["CERTDEPLOY_STATUS"] == "pre"
    assert "supersecret" not in repr(env)


def test_real_hook_subprocess_cannot_see_secrets(tmp_path):
    """실제 sh 로 훅을 실행해 환경변수 목록에 비밀이 없는지 확인한다."""
    d = pf_env(tmp_path, pre_cmd=f"env > {tmp_path}/hook_env.txt", reload_cmd="true")
    d.environ = {"PATH": os.environ["PATH"], "TOMCAT_KS_PASS": "supersecret"}
    d.verifier = lambda *a, **k: 0
    assert d.deploy(force=True)[0].status == "deployed"
    seen = (tmp_path / "hook_env.txt").read_text()
    assert "supersecret" not in seen and "CERTDEPLOY_TARGET=t1" in seen


def test_config_copy_does_not_recurse():
    import copy
    cfg = parse_config({**CERT, "targets": [TARGET]})
    assert copy.deepcopy(cfg).certs[0].name == "default"


def test_scaffold_reports_non_numeric_port(tmp_path):
    csvf = tmp_path / "bad.csv"
    csvf.write_text("name,host,port\nw,h.example,abc\n", encoding="utf-8")
    r = CliRunner().invoke(main, ["-c", "unused.yml", "scaffold", str(csvf)])
    assert r.exit_code == 1 and "숫자" in r.output and "Traceback" not in r.output
