"""전 과정 시나리오: 서버 등록(연결 테스트·조회) → CSR → 수동 발급 → 가져오기 → 자동 배포 → 지표/알림 → 실패 주입 → 진단 → 복구.

사람이 보며 디버깅할 때:  PIPELINE_VERBOSE=1 python -m pytest tests/test_pipeline_e2e.py -s -q
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import yaml
from click.testing import CliRunner
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from certdeploy import manual as mn
from certdeploy.cli import main
from certpilot_api.app import create_app
from certpilot_core import diag, trace
from certpilot_core.remote import SandboxExecutor
from conftest import make_cert, pem as cpem
from pki_helpers import make_pki, sign_csr

PW = "Str0ng!Passw0rd"


class Gateway(BaseHTTPRequestHandler):
    """Pushgateway/Alertmanager 역할: 받은 것을 기록하고 지표는 GET /metrics 로 돌려준다."""
    posts, metrics = [], ""

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        Gateway.posts.append((self.path, body))
        if self.path.startswith("/metrics/"):
            Gateway.metrics = body
        self.send_response(200); self.end_headers(); self.wfile.write(b"{}")

    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(Gateway.metrics.encode())

    def log_message(self, *a):
        pass


@pytest.fixture
def gateway():
    Gateway.posts, Gateway.metrics = [], ""
    srv = HTTPServer(("127.0.0.1", 0), Gateway)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_full_pipeline_with_failure_injection_and_diagnosis(tmp_path, sandbox, gateway, capsys):
    trace.TRACER.clear()
    # ---------------------------------------------------------------- 1) 관리자 화면: 연결 테스트 → 등록 → 조회
    sandbox.put("/etc/nginx/ssl/site.crt", cpem(make_cert("old.univ.example", -30, 5)[1]))
    app = create_app({"DATA_DIR": str(tmp_path / "data"), "ADMIN_USER": "root1", "ADMIN_PASSWORD": PW, "SECURE_COOKIE": False},
                     executor_factory=lambda t: SandboxExecutor(sandbox.path), sleep=lambda s: None)
    api = app.test_client()
    assert api.post("/auth/login", json={"username": "root1", "password": PW}).status_code == 200
    probe = api.post("/servers/probe", json={"hostname": "web1.univ.example", "account": "certscan"}).json
    assert probe["connected"] and probe["standard_paths"]
    sid = api.post("/servers", json={"name": "web1", "hostname": "web1.univ.example", "account": "certscan"}).json["server"]["id"]
    scan = api.post(f"/servers/{sid}/scan").json
    assert scan["certificates"]

    # ---------------------------------------------------------------- 2) 수동 발급: CSR → (CA 서명) → 가져오기 → 자동 배포
    web = [tmp_path / "web1", tmp_path / "web2"]
    marks = tmp_path / "reload.log"
    fail_flag = tmp_path / "fail-web2"
    targets = []
    for i, w in enumerate(web, 1):
        w.mkdir()
        reload = f"echo r{i} >> {marks}" if i == 1 else f"if [ -e {fail_flag} ]; then echo 'apache: Syntax error on line 12' >&2; false; else echo r{i} >> {marks}; fi"
        targets.append({"name": f"web{i}", "type": "generic", "canary": i == 1, "order": i, "check_cmd": "true", "reload_cmd": reload,
                        "files": [{"path": str(w / "s.crt"), "content": "fullchain"}, {"path": str(w / "s.key"), "content": "key"}]})
    cfgp = tmp_path / "cd.yml"
    cfgp.write_text(yaml.safe_dump({
        "state_dir": str(tmp_path / "state"), "audit_log": str(tmp_path / "audit"),
        "certificate": {"cert_file": str(tmp_path / "managed" / "w.crt"), "key_file": str(tmp_path / "managed" / "w.key")},
        "notify": {"pushgateway_url": gateway, "alertmanager_url": gateway}, "targets": targets}))
    cfg = str(cfgp)

    def cd(*args):
        return CliRunner().invoke(main, ["-c", cfg, *args], catch_exceptions=False)

    ca = {}
    make_pki(tmp_path / "ca_seed" if (tmp_path / "ca_seed").mkdir() is None else tmp_path, "seed", shared_ca=ca)
    assert cd("csr", "--domains", "*.univ.example,univ.example").exit_code == 0
    leaf = sign_csr((tmp_path / "state" / "pending" / "default" / "default.csr").read_bytes(), ca)
    (tmp_path / "server.cer").write_bytes(cpem(leaf))
    (tmp_path / "ca.p7b").write_bytes(pkcs7.serialize_certificates([ca["inter"], ca["root"]], Encoding.PEM))
    r = cd("import", "--file", str(tmp_path / "server.cer"), "--file", str(tmp_path / "ca.p7b"), "--deploy")
    assert r.exit_code == 0 and "배포 완료" in r.output, r.output
    assert marks.read_text().split() == ["r1", "r2"]

    # ---------------------------------------------------------------- 3) 감시: 지표가 푸시 게이트웨이에 도달, 감사 체인 정상
    mon = {c["name"]: c for c in diag.check_monitoring(pushgateway=gateway)}
    assert mon["pushgateway.certdeploy_metrics"]["ok"]
    assert 'certdeploy_run_ok{cert="default"} 1' in Gateway.metrics
    assert cd("verify-audit").exit_code == 0

    # ---------------------------------------------------------------- 4) 실패 주입: 갱신 시 web2 의 설정 오류 → 롤백
    key_pem, csr_pem = mn.generate_csr(["*.univ.example", "univ.example"])
    (tmp_path / "new.key").write_bytes(key_pem)
    (tmp_path / "new.cer").write_bytes(cpem(sign_csr(csr_pem, ca)))
    fail_flag.write_text("x")
    r = cd("import", "--file", str(tmp_path / "new.cer"), "--file", str(tmp_path / "ca.p7b"), "--key-file", str(tmp_path / "new.key"), "--deploy")
    assert r.exit_code == 1 and "롤백됨" in r.output
    assert 'certdeploy_run_ok{cert="default"} 0' in Gateway.metrics
    assert any(p.startswith("/api/v2/alerts") for p, _ in Gateway.posts)

    # ---------------------------------------------------------------- 5) 진단: 어느 단계에서 왜 실패했는지 한 번에 보인다
    errs = cd("trace", "--errors").output
    assert "deploy/reload_cmd" in errs and 'target="web2"' in errs and "Syntax error on line 12" in errs
    assert "deploy/failure" in errs and "[import-" in errs                       # 작업 ID 로 묶여 있음
    d = cd("diagnose")
    assert d.exit_code == 1 and "[문제] default.last_run" in d.output and "web2=rolled_back" in d.output
    st = json.loads(cd("status", "--format", "json").output)
    assert any("rolled_back" in json.dumps(x) for x in (st if isinstance(st, list) else st.get("targets", st)))

    # ---------------------------------------------------------------- 6) 수정 후 재배포 → 복구
    fail_flag.unlink()
    r = cd("deploy")
    assert r.exit_code == 0, r.output
    assert 'certdeploy_run_ok{cert="default"} 1' in Gateway.metrics
    assert cd("diagnose").exit_code == 0

    # ---------------------------------------------------------------- 관리자 화면 이벤트에도 같은 진단 정보가 남아 있다
    evs = api.get("/debug/events?limit=500").json["events"]
    components = {e["component"] for e in evs}
    assert {"api", "probe", "scan", "deploy", "import", "metrics", "report"} <= components
    # 비밀 누출 없음: 어떤 이벤트에도 개인키 PEM 이 없다
    assert "PRIVATE KEY" not in json.dumps(evs) and "PRIVATE KEY" not in open(tmp_path / "state" / "trace.jsonl").read()
    if os.environ.get("PIPELINE_VERBOSE"):
        with capsys.disabled():
            print("\n".join(trace.format_event(e) for e in evs if e["level"] != "debug"))
