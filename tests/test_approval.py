"""배포 승인 단계: 정책 검증·게이트(대기/승인/반려/만료/대체)·CLI 흐름·긴급 우회·지표·감사·알림 규칙"""
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from certdeploy import approval
from certdeploy.bundle import load_bundle
from certdeploy.cli import main
from certdeploy.config import ConfigError, parse_config
from pki_helpers import make_pki

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------------ 정책 검증
def pol(**kw):
    problems = []
    p = approval.parse_policy({"required": True, **kw}, "[x]", problems)
    return p, problems


def test_policy_defaults_and_disabled():
    p, pr = pol()
    assert pr == [] and p == {"required": True, "approvers": 1, "ttl_hours": 72, "self_approval": False}
    assert approval.parse_policy(None, "[x]", []) is None
    assert approval.parse_policy({"required": False}, "[x]", []) is None


@pytest.mark.parametrize("kw", [{"approvers": 0}, {"approvers": 4}, {"ttl_hours": 0}, {"ttl_hours": 721}, {"approvers": "2"},
                                {"self_approval": "yes"}, {"bogus": 1}])
def test_policy_rejects_bad_values(kw):
    assert pol(**kw)[1]


def test_config_global_and_per_cert_override(tmp_path):
    base = {"state_dir": "/s", "approval": {"required": True, "approvers": 2}, "certificates": [
        {"name": "hnu", "certificate": {"cert_file": "/a.crt", "key_file": "/a.key"}, "targets": [{"name": "w", "type": "apache", "cert_path": "/c", "key_path": "/k"}]},
        {"name": "hannam", "approval": {"required": False}, "certificate": {"cert_file": "/b.crt", "key_file": "/b.key"},
         "targets": [{"name": "w", "type": "apache", "cert_path": "/c", "key_path": "/k"}]}]}
    cfg = parse_config(base)
    assert cfg.certs[0].approval["approvers"] == 2 and cfg.certs[1].approval is None
    base["approval"] = {"required": True, "approvers": 9}
    with pytest.raises(ConfigError, match="approvers"):
        parse_config(base)


# ------------------------------------------------------------------ 게이트
@pytest.fixture
def bundle(tmp_path):
    c, k, _, _ = make_pki(tmp_path, name="a", san=("web.hnu.kr",), days_to=90)
    return load_bundle(str(c), str(k))


@pytest.fixture
def bundle2(tmp_path):
    c, k, _, _ = make_pki(tmp_path, name="b", san=("web.hnu.kr",), days_to=90)
    return load_bundle(str(c), str(k))


def gate(tmp_path, bundle, policy=None, **kw):
    return approval.gate("hnu", str(tmp_path / "st"), policy or {"required": True, "approvers": 1, "ttl_hours": 72, "self_approval": False},
                         bundle, ["w1"], kw.pop("action", "renew"), now=kw.pop("now", NOW), **kw)


def test_not_required_passes(tmp_path, bundle):
    assert approval.gate("hnu", str(tmp_path), None, bundle, [], "renew").status == "not_required"


def test_pending_then_approved_then_applied(tmp_path, bundle):
    g = gate(tmp_path, bundle)
    assert g.status == "pending" and g.created and g.request["needed"] == 1
    again = gate(tmp_path, bundle)
    assert again.status == "pending" and not again.created and again.request["id"] == g.request["id"]
    r = approval.approve(str(tmp_path / "st"), g.request["id"], "alice", "ok", now=NOW)
    assert r["status"] == "approved"
    assert gate(tmp_path, bundle).status == "approved"
    approval.mark_applied(str(tmp_path / "st"), g.request["id"], NOW)
    ok = gate(tmp_path, bundle)                                  # 적용 후 재실행(멱등)은 다시 요청하지 않는다
    assert ok.status == "approved" and not ok.created
    assert approval.list_requests(str(tmp_path / "st")) == []


def test_two_person_rule(tmp_path, bundle):
    g = gate(tmp_path, bundle, {"required": True, "approvers": 2, "ttl_hours": 72, "self_approval": False}, action="deploy", requested_by="bob")
    st, rid = str(tmp_path / "st"), g.request["id"]
    with pytest.raises(approval.ApprovalError, match="직접 승인"):
        approval.approve(st, rid, "bob", now=NOW)
    assert approval.approve(st, rid, "alice", now=NOW)["status"] == "pending"
    with pytest.raises(approval.ApprovalError, match="이미 승인"):
        approval.approve(st, rid, "alice", now=NOW)
    assert approval.approve(st, rid, "carol", now=NOW)["status"] == "approved"


def test_self_approval_allowed_when_configured(tmp_path, bundle):
    g = gate(tmp_path, bundle, {"required": True, "approvers": 1, "ttl_hours": 72, "self_approval": True}, action="deploy", requested_by="bob")
    assert approval.approve(str(tmp_path / "st"), g.request["id"], "bob", now=NOW)["status"] == "approved"


def test_system_requester_can_be_approved_by_anyone(tmp_path, bundle):
    g = gate(tmp_path, bundle)
    assert approval.approve(str(tmp_path / "st"), g.request["id"], approval.SYSTEM, now=NOW)["status"] == "approved"


def test_reject_blocks_until_reopened(tmp_path, bundle):
    g = gate(tmp_path, bundle)
    st = str(tmp_path / "st")
    approval.reject(st, g.request["id"], "alice", "키 교체 확인 필요", now=NOW)
    r = gate(tmp_path, bundle)
    assert r.status == "rejected" and not r.created and r.request["rejection"]["reason"].startswith("키")
    again = gate(tmp_path, bundle, reopen=True)
    assert again.status == "pending" and again.created and again.request["id"] != g.request["id"]


def test_expiry_creates_new_request(tmp_path, bundle):
    g = gate(tmp_path, bundle)
    st = str(tmp_path / "st")
    approval.approve(st, g.request["id"], "alice", now=NOW)
    late = gate(tmp_path, bundle, now=NOW + timedelta(hours=73))
    assert late.status == "pending" and late.created
    with pytest.raises(approval.ApprovalError, match="상태"):
        approval.approve(st, g.request["id"], "bob", now=NOW + timedelta(hours=73))


def test_new_certificate_needs_new_approval_and_supersedes(tmp_path, bundle, bundle2):
    g1 = gate(tmp_path, bundle)
    approval.approve(str(tmp_path / "st"), g1.request["id"], "alice", now=NOW)
    g2 = gate(tmp_path, bundle2)                                  # 다른 인증서 → 이전 승인은 효력 없음
    assert g2.status == "pending" and g2.request["fingerprint"] != g1.request["fingerprint"]
    old = [r for r in approval.list_requests(str(tmp_path / "st"), include_closed=True) if r["id"] == g1.request["id"]][0]
    assert old["status"] == "superseded"


@pytest.mark.parametrize("bad", ["", "a b", "x" * 65, "a;b"])
def test_invalid_approver_name(tmp_path, bundle, bad):
    g = gate(tmp_path, bundle)
    with pytest.raises(approval.ApprovalError, match="이름"):
        approval.approve(str(tmp_path / "st"), g.request["id"], bad, now=NOW)


def test_unknown_request(tmp_path):
    with pytest.raises(approval.ApprovalError, match="찾을 수"):
        approval.approve(str(tmp_path), "nope", "alice")


def test_metrics_text(tmp_path, bundle):
    gate(tmp_path, bundle)
    m = approval.metrics_text("hnu", str(tmp_path / "st"), now=NOW)
    assert 'certdeploy_approval_pending{cert="hnu"} 1' in m and f"since_timestamp_seconds{{cert=\"hnu\"}} {int(NOW.timestamp())}" in m


# ------------------------------------------------------------------ CLI 흐름 (실제 배포 포함)
@pytest.fixture
def stack(tmp_path):
    c, k, _, _ = make_pki(tmp_path, name="site", san=("web.hnu.kr",), days_to=90)
    web = tmp_path / "web"
    web.mkdir()
    cfg = {"state_dir": str(tmp_path / "state"), "audit_log": str(tmp_path / "audit"),
           "approval": {"required": True, "approvers": 2},
           "certificate": {"cert_file": str(c), "key_file": str(k)},
           "targets": [{"name": "web1", "type": "generic", "check_cmd": "true", "reload_cmd": "true",
                        "files": [{"path": str(web / "site.crt"), "content": "fullchain"}, {"path": str(web / "site.key"), "content": "key"}]}]}
    path = tmp_path / "certdeploy.yml"
    path.write_text(yaml.safe_dump(cfg, allow_unicode=True))
    return type("S", (), {"cfg": str(path), "web": web, "tmp": tmp_path, "raw": cfg})


def run(stack, *args):
    return CliRunner().invoke(main, ["-c", stack.cfg, *args])


def req_id(stack):
    out = run(stack, "approvals").output
    return out.split()[0]


def test_deploy_blocked_until_two_approvals(stack):
    r = run(stack, "deploy")
    assert r.exit_code == 5 and "배포 보류" in r.output and "승인 대기 0/2" in r.output
    assert not (stack.web / "site.crt").exists()                      # 아무것도 배포되지 않음
    rid = req_id(stack)
    assert run(stack, "approve", rid, "--by", "alice").exit_code == 0
    assert run(stack, "deploy").exit_code == 5                        # 1/2
    assert not (stack.web / "site.crt").exists()
    assert "다른 승인자" not in run(stack, "approve", rid, "--by", "bob").output.replace("승인 완료", "")
    d = run(stack, "deploy")
    assert d.exit_code == 0 and (stack.web / "site.crt").exists()
    assert "배포 완료" in run(stack, "approvals", "--all").output
    assert run(stack, "approvals").output.strip() == "대기 중인 승인 요청이 없습니다"
    assert run(stack, "deploy").exit_code == 0                         # 재실행은 승인 없이 멱등 통과(이미 배포됨)


def test_dry_run_never_blocked_and_makes_no_request(stack):
    r = run(stack, "deploy", "--dry-run")
    assert r.exit_code == 0
    assert run(stack, "approvals").output.strip() == "대기 중인 승인 요청이 없습니다"


def test_renew_path_uses_gate_via_deploy_function(stack):
    from certdeploy.cli import _run_deploy
    from certdeploy.config import load_config
    from certdeploy.cli import _bundle
    cfg = load_config(stack.cfg)
    cs = cfg.certs[0]
    assert _run_deploy(cfg, cs, _bundle(cs), False, False, (), False, action="renew") == 5
    req = json.load(open(os.path.join(cs.state_dir, "approvals.json")))["requests"][0]
    assert req["requested_by"] == approval.SYSTEM and req["action"] == "renew"


def test_reject_and_reopen(stack):
    run(stack, "deploy")
    rid = req_id(stack)
    assert run(stack, "reject", rid, "--by", "alice", "--reason", "다음 주에").exit_code == 0
    r = run(stack, "deploy")
    assert r.exit_code == 5 and "반려됨" in r.output
    assert run(stack, "approval-request").exit_code == 0
    assert "승인 대기" in run(stack, "approvals").output


def test_emergency_bypass_requires_reason_and_is_recorded(stack):
    r = run(stack, "deploy", "--emergency", "만료 임박 장애 대응")
    assert r.exit_code == 0 and (stack.web / "site.crt").exists() and "긴급" in r.output
    st = json.load(open(os.path.join(stack.raw["state_dir"], "approvals.json")))["requests"]
    assert st[-1]["status"] == "bypassed" and st[-1]["bypass_reason"] == "만료 임박 장애 대응"
    assert any("approval_bypass" in open(p).read() for p in Path(stack.tmp / "audit").rglob("*") if p.is_file())


def test_audit_and_unknown_request(stack):
    run(stack, "deploy")
    rid = req_id(stack)
    run(stack, "approve", rid, "--by", "alice", "--comment", "확인")
    text = "".join(open(p).read() for p in Path(stack.tmp / "audit").rglob("*") if p.is_file())
    assert "approval_requested" in text and "approval_approved" in text
    bad = run(stack, "approve", "nope", "--by", "alice")
    assert bad.exit_code != 0 and "찾을 수" in bad.output
    again = run(stack, "approve", rid, "--by", "alice")
    assert again.exit_code != 0 and "이미 승인" in again.output


def test_no_policy_means_no_gate(stack):
    stack.raw.pop("approval")
    Path(stack.cfg).write_text(yaml.safe_dump(stack.raw, allow_unicode=True))
    assert run(stack, "deploy").exit_code == 0 and (stack.web / "site.crt").exists()


# ------------------------------------------------------------------ 배포 파일
def test_alert_rules_and_systemd():
    r = yaml.safe_load((ROOT / "monitoring/prometheus/rules/certdeploy.yml").read_text())
    names = {x["alert"] for g in r["groups"] for x in g["rules"]}
    assert {"CertDeployApprovalPending", "CertDeployApprovalPendingLong"} <= names
    assert "SuccessExitStatus=4 5" in (ROOT / "certdeploy/systemd/certdeploy-renew.service").read_text()


# ------------------------------------------------------------------ 관리자 화면 API
def test_admin_api_list_and_decide(stack):
    from certdeploy import adminapi
    run(stack, "deploy")
    ov = adminapi.approvals(stack.cfg)
    c = ov["certificates"][0]
    assert c["policy"]["approvers"] == 2 and c["requests"][0]["status"] == "pending"
    rid = c["requests"][0]["id"]
    assert adminapi.decide(stack.cfg, rid, "approve", "admin1")["request"]["status"] == "pending"
    with pytest.raises(adminapi.AdminError, match="이미 승인"):
        adminapi.decide(stack.cfg, rid, "approve", "admin1")
    assert adminapi.decide(stack.cfg, rid, "approve", "admin2")["request"]["status"] == "approved"
    assert run(stack, "deploy").exit_code == 0                          # 화면에서 승인한 요청으로 CLI 배포
    with pytest.raises(adminapi.AdminError) as e:
        adminapi.decide(stack.cfg, "nope", "approve", "admin1")
    assert e.value.status == 404
    with pytest.raises(adminapi.AdminError, match="decision"):
        adminapi.decide(stack.cfg, rid, "delete", "admin1")


def test_admin_web_endpoints(stack, tmp_path, sandbox):
    from certpilot_api.app import create_app
    from certpilot_core.remote import SandboxExecutor
    run(stack, "deploy")
    pw = "Str0ng!Passw0rd"
    app = create_app({"DATA_DIR": str(tmp_path / "data"), "ADMIN_USER": "root1", "ADMIN_PASSWORD": pw, "SECURE_COOKIE": False,
                      "CERTDEPLOY_CONFIG": stack.cfg}, executor_factory=lambda t: SandboxExecutor(sandbox.path))
    c = app.test_client()
    assert c.get("/certdeploy/approvals").status_code == 401
    c.post("/auth/login", json={"username": "root1", "password": pw})
    rid = c.get("/certdeploy/approvals").json["certificates"][0]["requests"][0]["id"]
    r = c.post(f"/certdeploy/approvals/{rid}/approve", json={})
    assert r.status_code == 200 and r.json["request"]["approvals"][0]["by"] == "root1"       # 승인자 = 로그인 계정
    assert c.post(f"/certdeploy/approvals/{rid}/approve", json={}).status_code == 422          # 같은 사람 중복 승인 불가
    logs = json.dumps(c.get("/audit-logs?limit=20").json, ensure_ascii=False)
    assert "approval_approved" in logs
    c.post("/users", json={"username": "op1", "password": "An0ther!Passw0rd", "role": "operator"})
    op = app.test_client()
    op.post("/auth/login", json={"username": "op1", "password": "An0ther!Passw0rd"})
    assert op.get("/certdeploy/approvals").status_code == 403
    assert op.post(f"/certdeploy/approvals/{rid}/approve", json={}).status_code == 403


def test_frontend_wiring():
    html = (ROOT / "frontend/templates/index.html").read_text()
    js = (ROOT / "frontend/js/app.js").read_text()
    assert 'id="cd-approvals"' in html and "/certdeploy/approvals" in js and "loadApprovals" in js
