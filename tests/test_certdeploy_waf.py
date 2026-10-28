"""웹방화벽·어플라이언스(HTTP API) 배포: 로그인→업로드→적용→확인, 실패 시 이전 배포본으로 롤백, 설정 검증, 비밀 비노출."""
import json
import os
import stat

import pytest
import yaml
from click.testing import CliRunner

import waf_fake
from certdeploy import apideploy
from certdeploy.bundle import load_bundle
from certdeploy.cli import main
from certdeploy.config import ConfigError, parse_config
from certdeploy.engine import Deployer
from certdeploy.notify import NullNotifier
from certdeploy.state import State
from certdeploy.verify import VerifyError
from pki_helpers import make_pki
from certpilot_core import trace


class Rec(NullNotifier):
    def __init__(self):
        self.fired, self.resolved = [], []

    def fire(self, target, summary, description, severity="critical"):
        self.fired.append((target, description))

    def resolve(self, target):
        self.resolved.append(target)


def api_cfg(port, **over):
    base = f"http://127.0.0.1:{port}"
    api = {"base_url": base, "vars": {"cert_name": "hnu-wildcard"},
           "steps": [
               {"name": "login", "method": "POST", "url": "/api/login", "json": {"user": "{env:WAF_USER}", "password": "{env:WAF_PASS}"},
                "expect_json": {"$.code": 0}, "extract": {"token": "$.data.token"}},
               {"name": "upload", "method": "POST", "url": "/api/ssl/cert", "headers": {"Authorization": "Bearer {token}"},
                "json": {"name": "{cert_name}", "cert": "{fullchain_pem}", "key": "{key_pem}"}, "expect_json": {"$.code": 0}},
               {"name": "apply", "method": "POST", "url": "/api/ssl/apply", "headers": {"Authorization": "Bearer {token}"}, "json": {"name": "{cert_name}"}}],
           "rollback_steps": [
               {"name": "rollback-upload", "method": "POST", "url": "/api/ssl/cert", "headers": {"Authorization": "Bearer {token}"},
                "json": {"name": "{cert_name}", "cert": "{prev_fullchain_pem}", "key": "{prev_key_pem}"}, "expect_json": {"$.code": 0}},
               {"name": "rollback-apply", "method": "POST", "url": "/api/ssl/apply", "headers": {"Authorization": "Bearer {token}"}, "json": {"name": "{cert_name}"}}],
           "finally_steps": [{"name": "logout", "method": "POST", "url": "/api/logout", "headers": {"Authorization": "Bearer {token}"}}]}
    api.update(over)
    return api


class Env:
    def __init__(self, tmp, waf, **over):
        self.tmp, self.waf = tmp, waf
        self.cert, self.key = make_pki(tmp, "a")[:2]
        self.over = over

    def new_cert(self, name):
        self.cert, self.key = make_pki(self.tmp, name)[:2]

    def deployer(self, verifier=None, rec=None, environ=None):
        cfg = parse_config({"certificate": {"cert_file": str(self.cert), "key_file": str(self.key)}, "state_dir": str(self.tmp / "state"),
                            "options": {"verify_attempts": 2, "verify_interval": 1},
                            "targets": [{"name": "waf1", "type": "http_api", "api": api_cfg(self.waf.server_port, **self.over),
                                         "verify": {"host": "www.univ.example", "port": 443}}]})

        def served(host, port, sni=None):
            s = self.waf.waf["active_serial"]
            if not s:
                raise VerifyError("서빙 중인 인증서 없음")
            return int(s, 16)
        return Deployer(cfg, load_bundle(str(self.cert), str(self.key)), State(cfg.state_dir), verifier=verifier or served,
                        notifier=rec or Rec(), sleep=lambda s: None, environ=environ if environ is not None else {"WAF_USER": "wafadmin", "WAF_PASS": "waf-pass-1"})


@pytest.fixture
def waf():
    s = waf_fake.start_waf()
    yield s
    s.shutdown()


@pytest.fixture
def env(tmp_path, waf):
    trace.TRACER.clear()
    return Env(tmp_path, waf)


def test_deploy_through_waf_api_with_login_cookie_token_and_logout(env, waf):
    d = env.deployer()
    (r,) = d.deploy()
    assert r.status == "deployed", r.message
    w = waf.waf
    assert [p for m, p in w["log"] if m == "POST"] == ["/api/login", "/api/ssl/cert", "/api/ssl/apply", "/api/logout"]
    assert w["bodies"][0]["cert"].count("BEGIN CERTIFICATE") == 2 and "PRIVATE KEY" in w["bodies"][0]["key"]      # 자리표시자가 실제 PEM 으로 치환
    assert w["active_serial"] == f"{d.bundle.serial:x}" and w["logged_out"] == 1                                 # 쿠키·토큰으로 인증, 로그아웃 수행
    cur = os.path.join(env.tmp, "state", "api-bundles", "waf1", "current")
    assert stat.S_IMODE(os.stat(cur + "/key.pem").st_mode) == 0o600
    (again,) = env.deployer().deploy()
    assert again.status == "skipped"                                                                              # 멱등: 이미 최신이면 API 호출 없이 건너뜀
    assert [p for m, p in w["log"] if m == "POST"].count("/api/login") == 1


def test_failure_after_first_deploy_rolls_back_to_previous_bundle(env, waf):
    (r1,) = env.deployer().deploy()
    first_serial = waf.waf["active_serial"]
    env.new_cert("b")
    waf.waf["fail_apply"] = 1                                          # 새 인증서 적용만 한 번 실패(롤백의 적용은 성공)
    rec = Rec()
    (r2,) = env.deployer(rec=rec).deploy()
    assert r2.status == "rolled_back" and "이전 인증서로 롤백함" in r2.message, r2.message
    assert waf.waf["active_serial"] == first_serial                      # 장비는 이전 인증서로 복귀
    assert rec.fired and rec.fired[0][0] == "waf1"


def test_http_200_with_error_body_is_a_failure(env, waf):
    waf.waf["fail_upload"] = True
    rec = Rec()
    (r,) = env.deployer(rec=rec).deploy()
    assert r.status == "failed" and "$.code" in r.message and "invalid key" in r.message
    assert waf.waf["applied"] == [] and waf.waf["logged_out"] == 1            # 적용 단계 미실행, 로그아웃은 실행
    assert "이전 배포본 기록이 없어" in r.message                                  # 첫 배포 실패 → 되돌릴 이전본 없음
    assert rec.fired


def test_verify_mismatch_after_apply_triggers_rollback(env, waf):
    (r1,) = env.deployer().deploy()
    env.new_cert("b")
    (r2,) = env.deployer(verifier=lambda h, p, s=None: 1).deploy()        # 서빙 일련번호가 새 인증서와 다름
    assert r2.status == "rolled_back" and "새 인증서가 확인되지 않음" in r2.message


def test_no_rollback_steps_means_manual_attention_message(env, waf):
    env.over = {"rollback_steps": []}
    d = env.deployer()
    d.cfg.targets[0].api["rollback_steps"] = []
    waf.waf["fail_apply"] = True
    (r,) = d.deploy()
    assert r.status == "failed" and "rollback_steps 가 설정되지 않아" in r.message


def test_manual_rollback_restores_previous(env, waf):
    env.deployer().deploy()
    first = waf.waf["active_serial"]
    env.new_cert("b")
    env.deployer().deploy()
    assert waf.waf["active_serial"] != first
    r = env.deployer().rollback("waf1")
    assert r.status == "rolled_back" and waf.waf["active_serial"] == first
    assert env.deployer().rollback("waf1").status == "failed"              # 더 되돌릴 이전본 없음


def test_secrets_never_appear_in_trace_or_failure_messages(env, waf):
    waf.waf["fail_upload"] = True
    (r,) = env.deployer().deploy()
    text = json.dumps(trace.TRACER.events(limit=500)) + r.message
    assert "PRIVATE KEY" not in text and "waf-pass-1" not in text and "tok-abc123" not in text
    assert any(e["component"] == "api" and e["step"] == "login" for e in trace.TRACER.events(limit=500))


def test_missing_env_is_reported_before_any_request(env, waf):
    d = env.deployer(environ={})
    assert any("WAF_USER" in p for p in d.validate_targets())
    (r,) = d.deploy()
    assert r.status == "failed" and "환경변수" in r.message and waf.waf["log"] == []


def test_multipart_upload_and_extract_by_header_and_regex(waf, tmp_path):
    cert, key = make_pki(tmp_path, "m")[:2]
    b = load_bundle(str(cert), str(key))
    api = {"base_url": f"http://127.0.0.1:{waf.server_port}",
           "steps": [{"name": "login", "method": "POST", "url": "/api/login", "json": {"user": "wafadmin", "password": "waf-pass-1"},
                      "extract": {"cookie": "header:Set-Cookie", "tok": "regex:\"token\": \"([^\"]+)\""}},
                     {"name": "upload", "method": "POST", "url": "/api/ssl/upload", "headers": {"Authorization": "Bearer {tok}", "Cookie": "{cookie}"},
                      "multipart": {"fields": {"name": "mp"}, "files": {"cert": {"filename": "c.pem", "content": "{cert_pem}"}}}}]}
    r = apideploy.ApiRunner(api, "t")
    r.vars.update(r.bundle_vars(b))
    r.run(api["steps"])
    assert r.vars["tok"] == "tok-abc123" and "sid=sess42" in r.vars["cookie"]
    assert b"BEGIN CERTIFICATE" in waf.waf["multipart"][0] and b'filename="c.pem"' in waf.waf["multipart"][0]


def test_pfx_variables_need_password_env_and_render(waf, tmp_path):
    cert, key = make_pki(tmp_path, "p")[:2]
    b = load_bundle(str(cert), str(key))
    api = {"base_url": "http://x", "pfx_password_env": "PFXPW", "steps": [{"name": "s", "method": "POST", "url": "/u", "json": {"p": "{pfx_b64}", "pw": "{pfx_password}"}}]}
    r = apideploy.ApiRunner(api, "t", {"PFXPW": "pw-12345"})
    v = r.bundle_vars(b)
    assert len(v["pfx_b64"]) > 500 and v["pfx_password"] == "pw-12345"
    assert "pfx_b64" not in apideploy.ApiRunner(api, "t", {}).bundle_vars(b)


# ------------------------------------------------------------------ 설정 검증 / 도구
BASE = {"certificate": {"cert_file": "/a.crt", "key_file": "/a.key"}}


def tgt(**api_over):
    api = {"base_url": "https://waf.hnu.kr", "steps": [{"name": "up", "method": "POST", "url": "/c", "json": {"c": "{fullchain_pem}"}}]}
    api.update(api_over)
    return {**BASE, "targets": [{"name": "waf", "type": "http_api", "api": api}]}


@pytest.mark.parametrize("over,msg", [
    ({"steps": []}, "api.steps"),
    ({"base_url": "ftp://x"}, "base_url"),
    ({"steps": [{"name": "a", "method": "FETCH", "url": "/x"}]}, "method"),
    ({"steps": [{"name": "a", "method": "GET", "url": "x"}]}, "url"),
    ({"steps": [{"name": "a", "method": "POST", "url": "/x", "json": {}, "form": {}}]}, "하나만"),
    ({"steps": [{"name": "a", "method": "POST", "url": "/x", "json": {"k": "{nope}"}}]}, "알 수 없는 자리표시자 {nope}"),
    ({"steps": [{"name": "a", "method": "POST", "url": "/x", "json": {"k": "{prev_key_pem}"}}]}, "rollback_steps 에서만"),
    ({"steps": [{"name": "a", "method": "POST", "url": "/x", "json": {"k": "{pfx_b64}"}}]}, "pfx_password_env"),
    ({"steps": [{"name": "a", "method": "POST", "url": "/x", "wat": 1}]}, "알 수 없는 항목"),
])
def test_api_config_validation(over, msg):
    with pytest.raises(ConfigError, match=msg.replace("{", r"\{").replace("}", r"\}")):
        parse_config(tgt(**over))


def test_extracted_variable_is_known_to_later_steps_only():
    ok = tgt(steps=[{"name": "a", "method": "POST", "url": "/l", "extract": {"tk": "$.t"}},
                    {"name": "b", "method": "POST", "url": "/c", "headers": {"A": "{tk}"}}])
    assert parse_config(ok).targets[0].api
    bad = tgt(steps=[{"name": "b", "method": "POST", "url": "/c", "headers": {"A": "{tk}"}},
                     {"name": "a", "method": "POST", "url": "/l", "extract": {"tk": "$.t"}}])
    with pytest.raises(ConfigError, match="tk"):
        parse_config(bad)


def test_jsonpath_minimal():
    d = {"a": {"b": [{"c": 5}]}, "x-y": 1}
    assert apideploy.jsonpath(d, "$.a.b[0].c") == 5 and apideploy.jsonpath(d, "$.x-y") == 1
    assert apideploy.jsonpath(d, "$.a.z") is None and apideploy.jsonpath(d, "$.a.b[3]") is None


def test_plan_and_preflight_for_api_targets_hide_bodies(env, waf):
    d = env.deployer()
    text = "\n".join(d.plan())
    assert "POST /api/login" in text and "PRIVATE" not in text and "waf-pass" not in text and "[실패 시 롤백]" in text
    from certdeploy.preflight import run_preflight
    checks = run_preflight(d)
    assert any(c.name == "API 관리 주소" and c.ok for c in checks)
    assert waf.waf["log"] == []                                             # preflight 는 API 요청을 보내지 않는다


def test_cli_plan_and_schema_include_http_api(tmp_path):
    cert, key = make_pki(tmp_path, "c")[:2]
    cfg = {"certificate": {"cert_file": str(cert), "key_file": str(key)}, "state_dir": str(tmp_path / "st"),
           "targets": [{"name": "waf", "type": "http_api", "api": {"base_url": "https://waf.hnu.kr", "steps": [{"name": "up", "method": "POST", "url": "/c", "json": {"c": "{fullchain_pem}"}}]}}]}
    p = tmp_path / "cd.yml"
    p.write_text(yaml.safe_dump(cfg))
    r = CliRunner().invoke(main, ["-c", str(p), "plan"], catch_exceptions=False)
    assert r.exit_code == 0 and "http_api" in r.output and "POST /c" in r.output
    from certdeploy.schema import config_schema
    assert "http_api" in json.dumps(config_schema())
