import json
import os
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import yaml
from click.testing import CliRunner

from certdeploy.cli import main
from certdeploy.config import ConfigError, load_config, parse_config
from certdeploy.issuer import (IssueError, LegoIssuer, build_command, lego_basename, lego_output_paths,
                               parse_env_file)
from certdeploy.notify import AlertmanagerNotifier
from lego_fake import install_fake_lego
from pki_helpers import make_pki

TESTS_DIR = os.path.dirname(__file__)


# ------------------------------------------------------------------ 설정 검증
def good(**over):
    cfg = {"certificate": {"cert_file": "/a.crt", "key_file": "/a.key"},
           "targets": [{"name": "w", "type": "apache", "cert_path": "/c", "key_path": "/k"}]}
    cfg.update(over)
    return cfg


def test_config_defaults_and_lego_derived_paths():
    cfg = parse_config({"lego": {"domains": ["*.univ.example", "univ.example"], "path": "/var/lib/lego",
                                 "email": "a@b.c", "dns_provider": "infoblox"},
                        "targets": good()["targets"]})
    assert cfg.cert_file == "/var/lib/lego/certificates/_.univ.example.crt"
    assert cfg.key_file.endswith("_.univ.example.key") and cfg.state_dir == "/var/lib/certdeploy"
    assert cfg.targets[0].reload_cmd and "httpd" in cfg.targets[0].reload_cmd


@pytest.mark.parametrize("mutate,msg", [
    (lambda c: c["targets"][0].update(name="bad name!"), "name"),
    (lambda c: c["targets"][0].update(type="bogus"), "알 수 없는 type"),
    (lambda c: c["targets"][0].pop("key_path"), "key_path"),
    (lambda c: c["targets"][0].update(cert_path="relative/path"), "절대 경로"),
    (lambda c: c["targets"][0].update(transport={"kind": "ssh", "host": "h"}), "host, user"),
    (lambda c: c["targets"][0].update(transport={"kind": "ftp"}), "local 또는 ssh"),
    (lambda c: c.update(targets=[]), "targets"),
    (lambda c: c.update(options={"nope": 1}), "알 수 없는 옵션"),
    (lambda c: c["targets"].append(dict(c["targets"][0])), "중복"),
    (lambda c: c["targets"][0].update(type="nodejs"), "reload_cmd"),
    (lambda c: c["targets"][0].update(verify={"port": 443}), "verify.host"),
])
def test_config_errors(mutate, msg):
    c = good()
    mutate(c)
    with pytest.raises(ConfigError, match=msg):
        parse_config(c)


def test_tomcat_and_generic_specs():
    t = {"name": "tc", "type": "tomcat", "keystore_path": "/k.p12", "password_env": "P", "reload_cmd": "true"}
    cfg = parse_config(good(targets=[t]))
    assert cfg.targets[0].files[0].content == "pkcs12" and cfg.targets[0].files[0].mode == "0600"
    with pytest.raises(ConfigError, match="password_env"):
        parse_config(good(targets=[{"name": "tc", "type": "tomcat", "keystore_path": "/k", "reload_cmd": "true"}]))
    g = {"name": "jeus", "type": "generic", "reload_cmd": "none", "files": [
        {"path": "/s/k.jks", "content": "jks", "password_env": "P"}, {"path": "/s/c.pem", "content": "cert"}]}
    c2 = parse_config(good(targets=[g]))
    assert c2.targets[0].reload_cmd is None and [f.mode for f in c2.targets[0].files] == ["0600", "0644"]
    with pytest.raises(ConfigError, match="files"):
        parse_config(good(targets=[{"name": "x", "type": "generic", "reload_cmd": "none"}]))


def test_load_config_file_errors(tmp_path):
    with pytest.raises(ConfigError, match="읽을 수 없습니다"):
        load_config(str(tmp_path / "none.yml"))
    bad = tmp_path / "bad.yml"
    bad.write_text("a: [unclosed")
    with pytest.raises(ConfigError, match="YAML"):
        load_config(str(bad))


# ------------------------------------------------------------------ lego 명령 구성
LEGO = {"email": "ops@univ.example", "dns_provider": "infoblox", "domains": ["*.univ.example", "univ.example"],
        "path": "/var/lib/lego", "server": "https://acme.example/dir", "renew_days": 21, "dns_resolvers": ["10.0.0.53:53"]}


def test_lego_command_construction():
    run = build_command(LEGO, "run")
    assert run[0] == "lego" and run[-1] == "run" and "--accept-tos" in run
    assert run[run.index("--dns") + 1] == "infoblox" and run[run.index("--server") + 1] == "https://acme.example/dir"
    assert [run[i + 1] for i, a in enumerate(run) if a == "--domains"] == ["*.univ.example", "univ.example"]
    assert run[run.index("--dns.resolvers") + 1] == "10.0.0.53:53"
    renew = build_command(LEGO, "renew")
    assert renew[-3:] == ["renew", "--days", "21"]
    assert "acme-staging" in build_command(LEGO, "run", staging=True)[build_command(LEGO, "run", staging=True).index("--server") + 1]
    with pytest.raises(IssueError):
        build_command({"email": "x"}, "run")
    assert lego_basename(["*.a.b"]) == "_.a.b"
    assert lego_output_paths(LEGO)[0] == "/var/lib/lego/certificates/_.univ.example.crt"


def test_env_file_parsing(tmp_path):
    f = tmp_path / "lego.env"
    f.write_text("# 주석\nINFOBLOX_HOST=ib.univ.example\nINFOBLOX_PASSWORD=\"p@ss word\"\n\nTOKEN='x=y'\nbad line\n")
    assert parse_env_file(str(f)) == {"INFOBLOX_HOST": "ib.univ.example", "INFOBLOX_PASSWORD": "p@ss word", "TOKEN": "x=y"}


def test_issuer_chooses_run_or_renew_and_passes_env(tmp_path):
    calls = []

    def runner(cmd, env, timeout):
        calls.append((cmd, env.get("INFOBLOX_USER")))
        class R:
            returncode, stdout, stderr = 0, "", ""
        return R()
    env_file = tmp_path / "lego.env"
    env_file.write_text("INFOBLOX_USER=svc\n")
    cfg = {**LEGO, "path": str(tmp_path / "lego"), "env_file": str(env_file)}
    iss = LegoIssuer(cfg, runner=runner)
    assert iss.ensure() == "run"                       # 인증서가 아직 없음
    cert, _ = lego_output_paths(cfg)
    os.makedirs(os.path.dirname(cert))
    open(cert, "w").write("x")
    assert iss.ensure() == "renew"
    assert [c[0][-1] if c[0][-1] == "run" else c[0][-3] for c in calls] == ["run", "renew"]
    assert all(user == "svc" for _, user in calls)


def test_issuer_failures_are_clear(tmp_path):
    cfg = {**LEGO, "path": str(tmp_path / "l")}

    class Fail:
        returncode, stdout, stderr = 1, "", "error: DNS-01 failed\nacme: error 429 rate limited"
    with pytest.raises(IssueError, match="429"):
        LegoIssuer(cfg, runner=lambda *a: Fail()).ensure()
    with pytest.raises(IssueError, match="찾을 수 없습니다"):
        LegoIssuer({**cfg, "binary": "/no/such/lego"}).ensure()
    with pytest.raises(IssueError, match="env_file"):
        LegoIssuer({**cfg, "env_file": str(tmp_path / "missing.env")}, runner=lambda *a: Fail()).ensure()


# ------------------------------------------------------------------ 알림
class Sink(BaseHTTPRequestHandler):
    bodies = []

    def do_POST(self):
        Sink.bodies.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


@pytest.fixture
def sink():
    Sink.bodies = []
    srv = HTTPServer(("127.0.0.1", 0), Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_alertmanager_notifier_payloads(sink):
    n = AlertmanagerNotifier(sink)
    n.fire("web1", "배포 실패", "점검 실패")
    n.resolve("web1")
    (p1, fire), (p2, res) = Sink.bodies
    assert p1 == p2 == "/api/v2/alerts"
    a, r = fire[0], res[0]
    assert a["labels"] == {"alertname": "CertDeployFailed", "severity": "critical", "target": "web1", "service": "certdeploy"}
    assert a["annotations"]["description"] == "점검 실패" and a["endsAt"] > a["startsAt"]
    assert r["labels"] == a["labels"] and r["endsAt"] > r["startsAt"] and r["endsAt"] < a["endsAt"]      # 해소는 과거 종료 시각


def test_notifier_unreachable_never_raises():
    AlertmanagerNotifier("http://127.0.0.1:9", timeout=1).fire("t", "s", "d")


# ------------------------------------------------------------------ CLI 전 과정 (가짜 lego + 로컬 배포)
@pytest.fixture
def stack(tmp_path):
    lego = install_fake_lego(tmp_path)
    web = tmp_path / "web"
    web.mkdir()
    marks = tmp_path / "reloads.log"
    cfg = {"state_dir": str(tmp_path / "state"),
           "lego": {"binary": lego, "email": "ops@univ.example", "dns_provider": "infoblox",
                    "domains": ["univ.example", "*.univ.example"], "path": str(tmp_path / "lego"), "renew_days": 30},
           "targets": [{"name": "web1", "type": "generic", "check_cmd": "true", "reload_cmd": f"echo r >> {marks}",
                        "files": [{"path": str(web / "site.crt"), "content": "fullchain"},
                                  {"path": str(web / "site.key"), "content": "key"}]}]}
    path = tmp_path / "certdeploy.yml"
    path.write_text(yaml.safe_dump(cfg, allow_unicode=True))
    return type("S", (), {"cfg": str(path), "web": web, "marks": marks, "tmp": tmp_path, "raw": cfg})


def invoke(stack, *args, env=None):
    return CliRunner().invoke(main, ["-c", stack.cfg, *args], env=env, catch_exceptions=False)


def test_issue_then_renew_cycle(stack):
    r = invoke(stack, "issue")
    assert r.exit_code == 0 and "lego run 완료" in r.output and "배포 완료" in r.output, r.output
    first = (stack.web / "site.crt").read_bytes()
    assert stat.S_IMODE(os.stat(stack.web / "site.key").st_mode) == 0o600
    assert stack.marks.read_text().split() == ["r"]
    # 아직 갱신 시점이 아님 → lego 는 아무것도 안 하고, 배포도 건너뜀(서비스 재로드 없음)
    r2 = invoke(stack, "renew")
    assert r2.exit_code == 0 and "건너뜀" in r2.output and stack.marks.read_text().split() == ["r"], r2.output
    assert (stack.web / "site.crt").read_bytes() == first
    # 인증서를 만료 임박(10일 남음)으로 바꿔 놓으면 lego 가 새 인증서를 쓰고 자동 배포된다
    cert_path = stack.tmp / "lego" / "certificates" / "univ.example.crt"
    make_pki(cert_path.parent, name="univ.example", san=("univ.example", "*.univ.example"), days_from=-80, days_to=10)
    r3 = invoke(stack, "renew")
    assert r3.exit_code == 0 and "lego renew 완료" in r3.output and "배포 완료" in r3.output, r3.output
    assert (stack.web / "site.crt").read_bytes() != first and stack.marks.read_text().split() == ["r", "r"]


def test_issue_failure_exit_code_and_alert(stack, sink):
    raw = dict(stack.raw, notify={"alertmanager_url": sink})
    open(stack.cfg, "w").write(yaml.safe_dump(raw, allow_unicode=True))
    r = invoke(stack, "issue", env={"FAKE_LEGO_FAIL": "1"})
    assert r.exit_code == 1 and "발급 실패" in r.output + (r.stderr if hasattr(r, "stderr") and r.stderr_bytes else "")
    assert any(b[0]["labels"]["target"] == "lego" for _, b in Sink.bodies)


def test_validate_plan_deploy_dry_run_status_rollback(stack):
    invoke(stack, "issue", "--no-deploy")
    v = invoke(stack, "validate")
    assert v.exit_code == 0 and "인증서 OK" in v.output and "univ.example" in v.output
    p = invoke(stack, "plan")
    assert p.exit_code == 0 and "[web1]" in p.output and "BEGIN" not in p.output
    dr = invoke(stack, "deploy", "--dry-run")
    assert dr.exit_code == 0 and "계획만" in dr.output and not (stack.web / "site.crt").exists()
    (stack.web / "site.crt").write_text("OLD")
    d = invoke(stack, "deploy")
    assert d.exit_code == 0 and "배포 완료" in d.output
    st = invoke(stack, "status")
    assert "기록: ok" in st.output
    rb = invoke(stack, "rollback", "--target", "web1")
    assert rb.exit_code == 0 and (stack.web / "site.crt").read_text() == "OLD"
    assert invoke(stack, "rollback", "--target", "web1").exit_code == 1


def test_cli_config_and_certificate_errors_exit_codes(stack, tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("targets: []\n")
    r = CliRunner().invoke(main, ["-c", str(bad), "validate"])
    assert r.exit_code != 0 and "설정 오류" in r.output
    r2 = invoke(stack, "deploy")        # 인증서 파일이 아직 없음
    assert r2.exit_code == 2 and "인증서 오류" in r2.output


def test_cli_failed_deploy_returns_1_and_reports(stack):
    invoke(stack, "issue", "--no-deploy")
    raw = yaml.safe_load(open(stack.cfg))
    raw["targets"][0]["check_cmd"] = "echo broken >&2; false"
    open(stack.cfg, "w").write(yaml.safe_dump(raw, allow_unicode=True))
    r = invoke(stack, "deploy")
    assert r.exit_code == 1 and "롤백됨" in r.output and "broken" in r.output


def test_shipped_example_config_and_systemd_units_are_valid():
    root = os.path.join(TESTS_DIR, "..", "certdeploy")
    cfg = load_config(os.path.join(root, "certdeploy.example.yml"))
    assert {t.name for t in cfg.targets} >= {"web-canary", "sugang-tomcat"} and cfg.lego["dns_provider"] == "infoblox"
    assert [t.name for t in cfg.targets if t.canary] == ["web-canary"]
    unit = open(os.path.join(root, "systemd", "certdeploy-renew.service"), encoding="utf-8").read()
    assert "certdeploy -c /etc/certdeploy/certdeploy.yml renew" in unit and "NoNewPrivileges=true" in unit
    assert "OnCalendar" in open(os.path.join(root, "systemd", "certdeploy-renew.timer"), encoding="utf-8").read()
