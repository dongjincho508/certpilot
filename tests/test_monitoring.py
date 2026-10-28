"""감시 스택(monitoring/) 설정·스크립트 검증.

- 항상 실행: YAML/JSON 구조, 서로 참조하는 경로·이름의 일관성, 대시보드 PromQL 문법, 도구 스크립트
- 도구가 있을 때만 실행: promtool(설정·규칙·단위 테스트), amtool(Alertmanager 설정)
  PATH 또는 환경변수 PROMTOOL / AMTOOL 로 위치 지정. CI 에서는 릴리스 바이너리를 내려받아 실행한다.
"""
import csv
import importlib.util
import json
import os
import re
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import yaml

MON = Path(__file__).resolve().parent.parent / "monitoring"


def load(path):
    return yaml.safe_load((MON / path).read_text(encoding="utf-8"))


def script(name):
    spec = importlib.util.spec_from_file_location(name, MON / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------ 구조·일관성
def test_all_yaml_files_parse():
    for f in MON.rglob("*.yml*"):
        assert yaml.safe_load(f.read_text(encoding="utf-8")) is not None, f


def test_compose_is_pinned_and_not_exposed():
    c = load("docker-compose.yml")
    for name, svc in c["services"].items():
        assert ":latest" not in svc["image"] and ":" in svc["image"], f"{name}: 이미지 버전 고정 필요"
    for name in ("prometheus", "alertmanager"):
        for port in c["services"][name]["ports"]:
            assert str(port).startswith("127.0.0.1:"), f"{name} 는 외부에 노출하지 않는다"
    assert "?" in c["services"]["grafana"]["environment"]["GF_SECURITY_ADMIN_PASSWORD"]  # 비밀번호 미설정 시 기동 거부
    assert "retention.time=400d" in " ".join(c["services"]["prometheus"]["command"])
    assert c["services"]["grafana"]["environment"]["GF_AUTH_ANONYMOUS_ENABLED"] == "false"


def test_prometheus_config_matches_compose_mounts_and_rules():
    prom, compose = load("prometheus/prometheus.yml"), load("docker-compose.yml")
    mounts = " ".join(compose["services"]["prometheus"]["volumes"])
    assert "/etc/prometheus/rules" in mounts and "/etc/prometheus/targets" in mounts
    assert prom["rule_files"] == ["/etc/prometheus/rules/*.yml"]
    jobs = {j["job_name"] for j in prom["scrape_configs"]}
    assert {"ssl-endpoints", "ssl-exporter-self"} <= jobs
    ssl = next(j for j in prom["scrape_configs"] if j["job_name"] == "ssl-endpoints")
    assert ssl["metrics_path"] == "/probe" and ssl["file_sd_configs"][0]["files"] == ["/etc/prometheus/targets/*.yml"]
    rules = load("prometheus/rules/cert-expiry.yml")
    text = json.dumps(rules)
    for job in ("ssl-endpoints", "ssl-exporter-self"):
        assert job in text  # 규칙이 참조하는 job 이 실제 존재해야 한다
    am = prom["alerting"]["alertmanagers"][0]["static_configs"][0]["targets"]
    assert am == ["alertmanager:9093"]


def test_exporter_modules_cover_configured_labels():
    exp = load("ssl_exporter/ssl_exporter.yml")
    assert exp["default_module"] in exp["modules"]
    assert all(m["tls_config"]["insecure_skip_verify"] is True for m in exp["modules"].values())  # 사설 CA 도 만료 조회
    example = load("prometheus/targets/servers.yml.example")
    for group in example:
        mod = group["labels"].get("module")
        assert mod is None or mod in exp["modules"]


def test_alert_rules_have_severity_and_korean_annotations():
    rules = [r for g in load("prometheus/rules/cert-expiry.yml")["groups"] for r in g["rules"]]
    names = [r["alert"] for r in rules]
    assert len(names) == len(set(names))
    for r in rules:
        assert r["labels"]["severity"] in {"critical", "warning", "info"}, r["alert"]
        assert {"summary", "description"} <= set(r["annotations"]), r["alert"]
    assert {"CertExpired", "CertExpiresIn1Day", "CertExpiresIn3Days", "CertExpiresIn7Days", "CertExpiresIn14Days",
            "CertExpiresIn30Days", "CertRenewalLagging", "CertProbeFailed", "CertExporterDown"} <= set(names)


def test_alertmanager_routes_reference_existing_receivers_and_secrets_are_files():
    am = load("alertmanager/alertmanager.yml")
    receivers = {r["name"] for r in am["receivers"]}
    assert am["route"]["receiver"] in receivers
    assert {r["receiver"] for r in am["route"]["routes"]} <= receivers
    raw = (MON / "alertmanager/alertmanager.yml").read_text(encoding="utf-8")
    text = "\n".join(l for l in raw.splitlines() if not l.lstrip().startswith("#"))  # 주석의 예시는 제외
    assert "smtp_auth_password:" not in text and "url:" not in text.replace("url_file:", "")  # 비밀은 파일로
    for f in re.findall(r"/etc/alertmanager/secrets/(\w+)", text):
        assert (MON / "alertmanager/secrets.example" / f).exists(), f


# ------------------------------------------------------------------ 대시보드
VARS = {"$group": ".*", "$service": ".*", "$os": ".*", "$serial_no": ".*"}


def dashboard_exprs():
    d = json.loads((MON / "grafana/dashboards/cert-overview.json").read_text(encoding="utf-8"))
    for p in d["panels"]:
        for t in p["targets"]:
            yield p["title"], t["expr"]


def sub(expr):
    for k, v in VARS.items():
        expr = expr.replace(k, v)
    return expr


def test_dashboard_structure():
    d = json.loads((MON / "grafana/dashboards/cert-overview.json").read_text(encoding="utf-8"))
    ids = [p["id"] for p in d["panels"]]
    assert len(ids) == len(set(ids)) and d["uid"] == "cert-overview"
    assert all(p["datasource"]["uid"] == "prometheus" for p in d["panels"])
    declared = {v["name"] for v in d["templating"]["list"]}
    used = set(re.findall(r"\$(\w+)", json.dumps([e for _, e in dashboard_exprs()])))
    assert used <= declared, used - declared
    ds = load("grafana/provisioning/datasources/prometheus.yml")["datasources"][0]
    assert ds["uid"] == "prometheus"


def test_dashboard_promql_parses():
    promql = pytest.importorskip("promql_parser")
    for title, expr in dashboard_exprs():
        promql.parse(sub(expr))  # 문법 오류면 예외


def test_alert_rule_promql_parses():
    promql = pytest.importorskip("promql_parser")
    for g in load("prometheus/rules/cert-expiry.yml")["groups"]:
        for r in g["rules"]:
            promql.parse(" ".join(str(r["expr"]).split()))


# ------------------------------------------------------------------ promtool / amtool
def tool(name):
    return os.environ.get(name.upper()) or shutil.which(name)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kw)


@pytest.fixture
def staged(tmp_path):
    """설정 안의 /etc/... 절대 경로를 임시 디렉터리로 치환해 도구로 검사할 수 있게 배치한다."""
    base = tmp_path / "etc"
    for sub_ in ("prometheus", "alertmanager"):
        shutil.copytree(MON / sub_, base / sub_, ignore=shutil.ignore_patterns("tests"))
    shutil.copytree(MON / "alertmanager/secrets.example", base / "alertmanager/secrets")
    (base / "ssl_exporter").mkdir()
    for f in [base / "prometheus/prometheus.yml", base / "alertmanager/alertmanager.yml"]:
        f.write_text(f.read_text(encoding="utf-8").replace("/etc/", str(base) + "/"), encoding="utf-8")
    return base


def test_promtool_check_config_and_rules(staged):
    pt = tool("promtool")
    if not pt:
        pytest.skip("promtool 없음")
    r = run([pt, "check", "config", str(staged / "prometheus/prometheus.yml")])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SUCCESS" in r.stdout


def test_promtool_rule_unit_tests():
    pt = tool("promtool")
    if not pt:
        pytest.skip("promtool 없음")
    r = run([pt, "test", "rules", str(MON / "prometheus/tests/cert-expiry.test.yml")])
    assert r.returncode == 0, r.stdout + r.stderr


def test_amtool_check_config(staged):
    am = tool("amtool")
    if not am:
        pytest.skip("amtool 없음")
    r = run([am, "check-config", str(staged / "alertmanager/alertmanager.yml")])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "3 receivers" in r.stdout and "1 templates" in r.stdout


# ------------------------------------------------------------------ csv_to_targets
def test_csv_to_targets_groups_by_labels_and_defaults():
    m = script("csv_to_targets")
    rows = csv.DictReader(
        "host,port,group,service,os,owner\n"
        "a.univ.ac.kr,443,홈,apache,Linux,전산실\n"
        "b.univ.ac.kr,,홈,apache,linux,전산실\n"
        "c.univ.ac.kr,8443,학사,tomcat,linux,학사팀\n".splitlines())
    out = m.convert(rows)
    assert out[0] == {"targets": ["a.univ.ac.kr:443", "b.univ.ac.kr:443"],
                      "labels": {"group": "홈", "service": "apache", "os": "linux", "owner": "전산실"}}
    assert out[1]["targets"] == ["c.univ.ac.kr:8443"]


@pytest.mark.parametrize("csv_text,msg", [
    ("host,port\nbad host,443\n", "호스트 형식"),
    ("host,port\na.example,abc\n", "숫자가 아닙니다"),
    ("host,port\na.example,70000\n", "범위"),
    ("host,port\na.example,443\na.example,443\n", "중복"),
    ("host,os\na.example,solaris\n", "os 는"),
])
def test_csv_to_targets_rejects_bad_rows(csv_text, msg):
    m = script("csv_to_targets")
    with pytest.raises(m.RowError, match=msg):
        m.convert(csv.DictReader(csv_text.splitlines()))


def test_csv_to_targets_cli_output_is_valid_file_sd(tmp_path):
    m = script("csv_to_targets")
    src = tmp_path / "s.csv"
    src.write_text("﻿host,port,group,service,os\nwww.univ.ac.kr,443,홈,apache,linux\n", encoding="utf-8")
    out = tmp_path / "t.yml"
    assert m.main([str(src), "-o", str(out)]) == 0
    data = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert data == [{"targets": ["www.univ.ac.kr:443"], "labels": {"group": "홈", "service": "apache", "os": "linux"}}]
    bad = tmp_path / "bad.csv"
    bad.write_text("host\nbad host\n", encoding="utf-8")
    assert m.main([str(bad)]) == 1


# ------------------------------------------------------------------ cert_inventory (가짜 Prometheus)
class FakeProm(BaseHTTPRequestHandler):
    certs = []     # (instance, group, serial, days)
    failed = []

    def do_GET(self):
        expr = parse_qs(urlparse(self.path).query)["query"][0]
        if "ssl_probe_success" in expr:
            result = [{"metric": {"instance": i}, "value": [0, "0"]} for i in self.failed]
        else:
            result = [{"metric": {"instance": i, "group": g, "service": "apache", "os": "linux", "owner": "전산실",
                                  "cn": "*.univ.example", "issuer_cn": "RapidSSL", "serial_no": s},
                       "value": [0, str(d)]} for i, g, s, d in self.certs]
        body = json.dumps({"status": "success", "data": {"resultType": "vector", "result": result}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def prom():
    srv = HTTPServer(("127.0.0.1", 0), FakeProm)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    FakeProm.certs, FakeProm.failed = [], []
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_inventory_list_and_serials(prom, capsys):
    inv = script("cert_inventory")
    FakeProm.certs = [("a:443", "홈", "111", 5.5), ("b:443", "홈", "111", 6.0), ("c:443", "학사", "222", 90.0)]
    assert inv.main(["--url", prom, "list"]) == 0
    out = capsys.readouterr().out
    assert out.index("a:443") < out.index("c:443")          # 만료 임박 순
    assert inv.main(["--url", prom, "serials"]) == 0
    out = capsys.readouterr().out
    assert re.search(r"111\s+\*\.univ\.example\s+RapidSSL\s+2\s+5일", out)  # 같은 인증서 2대


def test_inventory_snapshot_and_replacement_check(prom, tmp_path, capsys):
    inv = script("cert_inventory")
    FakeProm.certs = [("a:443", "홈", "111", 5.0), ("b:443", "홈", "111", 5.0), ("c:443", "학사", "111", 5.0),
                      ("d:443", "학사", "222", 90.0)]
    snap = tmp_path / "before.csv"
    assert inv.main(["--url", prom, "snapshot", "--serial", "111", "-o", str(snap)]) == 0
    assert len(list(csv.DictReader(snap.open(encoding="utf-8")))) == 3
    # 교체 진행: a 는 새 인증서, b 는 그대로, c 는 조회 실패
    FakeProm.certs = [("a:443", "홈", "333", 199.0), ("b:443", "홈", "111", 5.0), ("d:443", "학사", "222", 90.0)]
    FakeProm.failed = ["c:443"]
    out_csv = tmp_path / "result.csv"
    capsys.readouterr()
    assert inv.main(["--url", prom, "check", "--snapshot", str(snap), "-o", str(out_csv)]) == 1
    text = capsys.readouterr().out
    assert "교체 완료 1 / 미교체 1 / 조회 실패 1" in text
    status = {r["instance"]: r["status"] for r in csv.DictReader(out_csv.open(encoding="utf-8"))}
    assert status == {"a:443": "교체 완료", "b:443": "미교체", "c:443": "조회 실패"}
    # 전부 교체되면 종료 코드 0
    FakeProm.certs = [("a:443", "홈", "333", 199.0), ("b:443", "홈", "333", 199.0), ("c:443", "학사", "333", 199.0)]
    FakeProm.failed = []
    assert inv.main(["--url", prom, "check", "--snapshot", str(snap)]) == 0


def test_inventory_snapshot_unknown_serial_and_unreachable(prom, tmp_path, capsys):
    inv = script("cert_inventory")
    assert inv.main(["--url", prom, "snapshot", "--serial", "999", "-o", str(tmp_path / "x.csv")]) == 2
    assert inv.main(["--url", "http://127.0.0.1:9", "list"]) == 3


def test_bind_mounts_have_selinux_label_for_rocky():
    """Rocky/RHEL(SELinux enforcing)에서 컨테이너가 바인드 마운트 파일을 읽으려면 z 라벨이 필요하다."""
    c = load("docker-compose.yml")
    for name, svc in c["services"].items():
        for v in svc.get("volumes", []):
            if str(v).startswith("./"):
                assert str(v).endswith(":ro,z"), f"{name}: {v}"
