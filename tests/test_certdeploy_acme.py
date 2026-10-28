"""내장 ACME 클라이언트(DNS-01): 연동(Infoblox)·수동(TXT 안내→재실행) 두 모드, 가짜 CA/WAPI/DNS 로 전 과정 검증."""
import json
import os
import stat

import pytest
import yaml
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

import acme_fake as fk
from certdeploy import acme, dnsprov, dnsquery
from certdeploy.cli import main
from certdeploy.config import ConfigError, parse_config
from pki_helpers import make_pki

DOMAINS = ["*.hnu.kr", "hnu.kr"]            # 와일드카드와 루트는 같은 이름(_acme-challenge.hnu.kr)에 TXT 값이 둘 필요


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


@pytest.fixture
def env(tmp_path):
    from certpilot_core import trace
    trace.TRACER.configure(path="", echo=None)          # CLI 가 설정 파일별로 트레이스 경로를 다시 잡도록
    trace.run_id_var.set(None)
    zone = fk.Zone()
    ca = {}
    make_pki(tmp_path, "seed", shared_ca=ca)
    srv, state, directory = fk.start_acme(zone, ca)
    wapi = fk.start_wapi(zone)
    dns = fk.DnsServer(zone)
    yield type("E", (), {"zone": zone, "ca": ca, "acme": state, "directory": directory, "wapi": wapi, "dns": dns, "tmp": tmp_path})
    for s in (srv, wapi):
        s.shutdown()
    dns.close()


# ------------------------------------------------------------------ 프로토콜 부품
def test_rfc7638_thumbprint_vector():
    jwk = {"kty": "RSA", "e": "AQAB", "n": ("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst"
                                              "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")}
    assert acme.thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_txt_name_and_value_shape():
    assert acme.txt_name("*.hnu.kr") == acme.txt_name("hnu.kr") == "_acme-challenge.hnu.kr"
    jwk = acme.jwk_of(ec.generate_private_key(ec.SECP256R1()))
    v = acme.dns01_value("tok", jwk)
    assert len(v) == 43 and "=" not in v and v == acme.dns01_value("tok", jwk) and v != acme.dns01_value("tok2", jwk)


def test_dns_query_roundtrip_with_real_udp(env):
    env.zone.add("_acme-challenge.hnu.kr", "aaa")
    env.zone.add("_acme-challenge.hnu.kr", "x" * 300)                      # 255 초과 → 여러 문자열 조각
    got = dnsquery.query_txt("_acme-challenge.hnu.kr", "127.0.0.1", env.dns.port)
    assert got == ["aaa", "x" * 300]
    assert dnsquery.query_txt("nothing.hnu.kr", "127.0.0.1", env.dns.port) == []          # NXDOMAIN = 없음
    assert dnsquery.txt_visible("_acme-challenge.hnu.kr", "aaa", [env.dns.resolver])
    assert not dnsquery.txt_visible("_acme-challenge.hnu.kr", "bbb", [env.dns.resolver])
    assert not dnsquery.txt_visible("_acme-challenge.hnu.kr", "aaa", [env.dns.resolver, "127.0.0.1:9"])   # 한 곳이라도 안 보이면 False
    with pytest.raises(dnsquery.DnsError):
        dnsquery.txt_visible("x", "y", [])


def test_client_badnonce_is_retried_once(env, tmp_path):
    env.acme.bad_nonce_once = True
    c = acme.load_account(str(tmp_path / "st"), env.directory, "a@hnu.kr")
    assert c.kid and mode(tmp_path / "st" / "acme") == 0o700
    key_files = [f for f in os.listdir(tmp_path / "st" / "acme") if f.endswith(".key")]
    assert key_files and mode(tmp_path / "st" / "acme" / key_files[0]) == 0o600
    c2 = acme.load_account(str(tmp_path / "st"), env.directory, "a@hnu.kr")      # 재사용(재등록 없음)
    assert c2.kid == c.kid and sum(1 for p, _ in env.acme.requests if p == "/new-acct") == 1


def test_acme_error_carries_problem_detail(env, tmp_path):
    c = acme.load_account(str(tmp_path / "st"), env.directory, None)
    with pytest.raises(acme.AcmeError, match="orderNotReady") as e:
        _, order = c.new_order(["hnu.kr"])
        c.finalize(order, b"x")
    assert e.value.problem["type"].endswith("orderNotReady")


# ------------------------------------------------------------------ Infoblox 제공자
def test_infoblox_provider_present_cleanup_idempotent_and_selective(env):
    w = env.wapi
    p = dnsprov.InfobloxProvider(f"127.0.0.1:{w.server_port}", "acme-svc", "s3cret-pw", view="external", scheme="http")
    p.present("_acme-challenge.hnu.kr", "v1")
    p.present("_acme-challenge.hnu.kr", "v1")                              # 같은 값 재등록은 중복 생성 안 함
    p.present("_acme-challenge.hnu.kr", "v2")
    assert env.zone.get("_acme-challenge.hnu.kr") == ["v1", "v2"] and len(w.records) == 2
    post = [b for m, _, b in w.log if m == "POST"][0]
    assert post == {"name": "_acme-challenge.hnu.kr", "text": "v1", "view": "external"}
    p.cleanup("_acme-challenge.hnu.kr", "v1")
    assert env.zone.get("_acme-challenge.hnu.kr") == ["v2"]                # 다른 값은 그대로
    p.cleanup("_acme-challenge.hnu.kr", "v1")                              # 이미 없어도 오류 없음
    bad = dnsprov.InfobloxProvider(f"127.0.0.1:{w.server_port}", "acme-svc", "wrong", scheme="http")
    with pytest.raises(dnsprov.DnsProviderError, match="401"):
        bad.present("_acme-challenge.hnu.kr", "z")
    w.fail_post = True
    with pytest.raises(dnsprov.DnsProviderError, match="denied"):
        p.present("_acme-challenge.hnu.kr", "w")


def test_build_provider_requires_env_and_known_mode():
    cfg = {"mode": "infoblox", "infoblox": {"host": "h", "user_env": "U_X", "password_env": "P_X"}}
    with pytest.raises(dnsprov.DnsProviderError, match="U_X"):
        dnsprov.build_provider(cfg, {})
    assert dnsprov.build_provider(cfg, {"U_X": "u", "P_X": "p"}).automatic
    assert not dnsprov.build_provider({"mode": "manual"}).automatic
    with pytest.raises(dnsprov.DnsProviderError):
        dnsprov.build_provider({"mode": "route53"})


# ------------------------------------------------------------------ 설정
def base_cfg(tmp, env, mode_="manual", **acme_over):
    a = {"directory": env.directory, "email": "cert-admin@hnu.kr", "domains": DOMAINS,
         "dns": {"mode": mode_, "check_resolvers": [env.dns.resolver], "propagation_timeout": 0}}
    if mode_ == "infoblox":
        a["dns"]["infoblox"] = {"host": f"127.0.0.1:{env.wapi.server_port}", "scheme": "http", "user_env": "WAPI_U", "password_env": "WAPI_P", "view": "external"}
    a.update(acme_over)
    web = tmp / "web"
    web.mkdir(exist_ok=True)
    marks = tmp / "reload.log"
    cfg = {"state_dir": str(tmp / "state"), "acme": a,
           "targets": [{"name": "w1", "type": "generic", "check_cmd": "true", "reload_cmd": f"echo r >> {marks}",
                        "files": [{"path": str(web / "s.crt"), "content": "fullchain"}, {"path": str(web / "s.key"), "content": "key"}]}]}
    p = tmp / "cd.yml"
    p.write_text(yaml.safe_dump(cfg))
    return str(p), marks, web


def cd(cfgp, *args, env=None):
    return CliRunner().invoke(main, ["-c", cfgp, *args], env=env, catch_exceptions=False)


def test_config_acme_validation_and_defaults(tmp_path):
    ok = parse_config({"state_dir": "/var/lib/certdeploy", "acme": {"email": "a@b.c", "domains": ["*.hnu.kr", "hnu.kr"]},
                       "targets": [{"name": "w", "type": "generic", "reload_cmd": "none", "files": [{"path": "/x", "content": "cert"}]}]})
    cs = ok.certs[0]
    assert cs.acme["directory"].startswith("https://acme-v02") and cs.acme["dns"]["mode"] == "manual" and cs.acme["renew_days"] == 30
    assert cs.cert_file == "/var/lib/certdeploy/managed/_.hnu.kr.crt" and cs.key_file.endswith("_.hnu.kr.key")
    base = {"targets": [{"name": "w", "type": "generic", "reload_cmd": "none", "files": [{"path": "/x", "content": "cert"}]}]}
    for bad, msg in (({"domains": []}, "domains 가 필요"), ({"domains": ["a b"]}, "형식"), ({"domains": ["a.kr"], "key_type": "dsa"}, "key_type"),
                     ({"domains": ["a.kr"], "directory": "http://evil.example/dir"}, "https"),
                     ({"domains": ["a.kr"], "dns": {"mode": "infoblox"}}, "infoblox.host"), ({"domains": ["a.kr"], "dns": {"mode": "route53"}}, "dns.mode")):
        with pytest.raises(ConfigError, match=msg):
            parse_config({**base, "acme": bad})
    with pytest.raises(ConfigError, match="함께 쓸 수 없습니다"):
        parse_config({**base, "acme": {"domains": ["a.kr"]}, "lego": {"domains": ["a.kr"], "email": "a@b.c", "dns_provider": "x"}})


# ------------------------------------------------------------------ 연동(자동) 모드 전 과정
def test_auto_infoblox_issues_deploys_and_cleans_up(env):
    cfgp, marks, web = base_cfg(env.tmp, env, "infoblox")
    r = cd(cfgp, "issue", env={"WAPI_U": "acme-svc", "WAPI_P": "s3cret-pw"})
    assert r.exit_code == 0, r.output
    assert "발급 완료" in r.output and "배포 완료" in r.output
    leaf = x509.load_pem_x509_certificates((env.tmp / "state" / "managed" / "_.hnu.kr.crt").read_bytes())
    assert len(leaf) == 2 and {n.value for n in leaf[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value} == set(DOMAINS)
    assert mode(env.tmp / "state" / "managed" / "_.hnu.kr.key") == 0o600
    posts = [b for m, _, b in env.wapi.log if m == "POST"]
    assert len(posts) == 2 and {b["name"] for b in posts} == {"_acme-challenge.hnu.kr"} and len({b["text"] for b in posts}) == 2   # 같은 이름·값 둘
    assert env.zone.get("_acme-challenge.hnu.kr") == [] and not env.wapi.records                # 발급 후 TXT 정리됨
    assert (web / "s.crt").read_bytes().count(b"BEGIN CERTIFICATE") == 2 and marks.read_text().split() == ["r"]
    assert acme.load_pending(str(env.tmp / "state"), "default") is None
    assert not os.path.exists(acme.pending_paths(str(env.tmp / "state"), "default")[1])         # 대기 키 삭제


def test_auto_mode_failure_cleans_txt_notifies_and_backs_off(env):
    cfgp, marks, web = base_cfg(env.tmp, env, "infoblox")
    env.wapi.fail_post = True                                              # TXT 를 못 만들면 검증 실패
    r = cd(cfgp, "issue", env={"WAPI_U": "acme-svc", "WAPI_P": "s3cret-pw"})
    assert r.exit_code == 1 and "발급 실패" in r.output
    assert not (env.tmp / "state" / "managed").exists() and not marks.exists()
    again = cd(cfgp, "issue", env={"WAPI_U": "acme-svc", "WAPI_P": "s3cret-pw"})        # 연속 실패 방지 대기
    assert again.exit_code == 0 and "발급 건너뜀" in again.output


def test_auto_mode_missing_credentials_is_reported(env):
    cfgp, _, _ = base_cfg(env.tmp, env, "infoblox")
    r = cd(cfgp, "issue", env={"WAPI_U": "", "WAPI_P": ""})
    assert r.exit_code == 1 and "WAPI_U" in r.output


# ------------------------------------------------------------------ 수동 모드 전 과정 (TXT 안내 → 사람이 등록 → 재실행)
def test_manual_two_step_flow_end_to_end(env):
    cfgp, marks, web = base_cfg(env.tmp, env, "manual")
    r1 = cd(cfgp, "issue")
    assert r1.exit_code == 4, r1.output
    assert r1.output.count("_acme-challenge.hnu.kr") >= 2 and "TXT" in r1.output
    jp, kp = acme.pending_paths(str(env.tmp / "state"), "default")
    assert mode(kp) == 0o600 and os.path.exists(jp)
    pend = json.load(open(jp))
    values = [c["txt_value"] for c in pend["challenges"]]
    assert len(set(values)) == 2
    r2 = cd(cfgp, "issue")                                                # 아직 등록 전 → 다시 안내, 주문은 그대로
    assert r2.exit_code == 4 and json.load(open(jp))["order_url"] == pend["order_url"]
    assert sum(1 for p, _ in env.acme.requests if p == "/new-order") == 1
    env.zone.add("_acme-challenge.hnu.kr", values[0])                     # 하나만 등록 → 아직 대기
    r3 = cd(cfgp, "issue")
    assert r3.exit_code == 4 and "아직 보이지 않는" in r3.output
    env.zone.add("_acme-challenge.hnu.kr", values[1])                     # 사람이 나머지 TXT 등록
    r4 = cd(cfgp, "issue")
    assert r4.exit_code == 0, r4.output
    assert "발급 완료" in r4.output and "배포 완료" in r4.output and marks.read_text().split() == ["r"]
    assert acme.load_pending(str(env.tmp / "state"), "default") is None
    assert (env.tmp / "state" / "managed" / "_.hnu.kr.crt").exists()


def test_manual_wrong_txt_value_fails_cleanly_and_reset_restarts(env):
    cfgp, _, _ = base_cfg(env.tmp, env, "manual")
    cd(cfgp, "issue")
    pend = json.load(open(acme.pending_paths(str(env.tmp / "state"), "default")[0]))
    for c in pend["challenges"]:
        env.zone.add("_acme-challenge.hnu.kr", c["txt_value"])
    env.acme.zone = fk.Zone()                                             # CA 쪽에서는 TXT 가 안 보이는 상황(전파 불일치)
    r = cd(cfgp, "issue")
    assert r.exit_code == 1 and "검증 실패" in r.output
    assert cd(cfgp, "acme-reset").output.startswith("대기 중인 주문을 폐기")
    assert cd(cfgp, "acme-reset").output.startswith("대기 중인 주문이 없습니다")
    assert acme.load_pending(str(env.tmp / "state"), "default") is None


def test_renew_skips_when_far_from_expiry_and_issue_forces(env):
    cfgp, marks, _ = base_cfg(env.tmp, env, "infoblox")
    e = {"WAPI_U": "acme-svc", "WAPI_P": "s3cret-pw"}
    assert cd(cfgp, "renew", env=e).exit_code == 0
    orders = lambda: sum(1 for p, _ in env.acme.requests if p == "/new-order")
    assert orders() == 1
    r = cd(cfgp, "renew", env=e)                                          # 만료 90일 > renew_days 30 → 발급 안 함
    assert r.exit_code == 0 and "갱신 불필요" in r.output and orders() == 1
    assert cd(cfgp, "issue", env=e).exit_code == 0 and orders() == 2      # issue 는 강제 재발급
    env.acme.days = 20
    assert cd(cfgp, "issue", env=e).exit_code == 0 and orders() == 3
    assert cd(cfgp, "renew", env=e).exit_code == 0 and orders() == 4      # 20일 남음 ≤ 30일 → 갱신 발급


def test_staging_installs_aside_and_never_deploys(env, monkeypatch):
    cfgp, marks, web = base_cfg(env.tmp, env, "infoblox")
    monkeypatch.setattr("certdeploy.cli.LE_STAGING", env.directory)
    r = cd(cfgp, "issue", "--staging", env={"WAPI_U": "acme-svc", "WAPI_P": "s3cret-pw"})
    assert r.exit_code == 0 and "스테이징 발급 성공" in r.output
    assert (env.tmp / "state" / "acme" / "staging" / "default.crt").exists()
    assert not (env.tmp / "state" / "managed").exists() and not marks.exists() and not list(web.iterdir())


def test_pending_from_other_directory_is_discarded(env, monkeypatch):
    cfgp, _, _ = base_cfg(env.tmp, env, "manual")
    cd(cfgp, "issue")
    first = json.load(open(acme.pending_paths(str(env.tmp / "state"), "default")[0]))["order_url"]
    monkeypatch.setattr("certdeploy.cli.LE_STAGING", env.directory + "?staging")
    r = cd(cfgp, "issue", "--staging")
    assert r.exit_code == 4 and "다른 CA" in r.output
    assert json.load(open(acme.pending_paths(str(env.tmp / "state"), "default")[0]))["order_url"] != first


def test_trace_records_acme_steps_without_secrets(env):
    cfgp, _, _ = base_cfg(env.tmp, env, "infoblox")
    cd(cfgp, "issue", env={"WAPI_U": "acme-svc", "WAPI_P": "s3cret-pw"})
    out = cd(cfgp, "trace", "--debug", "-n", "200").output
    for step in ("acme/register_account", "acme/new_order", "acme/dns_present", "acme/challenge", "acme/finalize", "acme/dns_cleanup"):
        assert step in out, step
    assert "s3cret-pw" not in out and "PRIVATE KEY" not in out
