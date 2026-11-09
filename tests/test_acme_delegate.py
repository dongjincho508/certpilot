"""ACME CNAME 위임: _acme-challenge 를 다른 이름/영역으로 CNAME 해 둔 구성 — 설정 검증, TXT 가 대상 이름에 등록·삭제되고 전파 확인도 대상 이름으로, 수동 모드 안내, 발급 전 과정"""
import yaml
import pytest

import acme_fake as fk
from certdeploy import acme, dnsprov, dnsquery
from certdeploy.config import ConfigError, parse_config
from test_certdeploy_acme import base_cfg, cd, env  # noqa: F401  (픽스처·헬퍼 재사용)


class Rec:
    name, automatic = "rec", True

    def __init__(self):
        self.calls = []

    def present(self, f, v):
        self.calls.append(("present", f, v))

    def cleanup(self, f, v):
        self.calls.append(("cleanup", f, v))


def test_delegating_provider_explicit_mapping_and_passthrough():
    inner = Rec()
    p = dnsprov.DelegatingProvider(inner, mapping={"_acme-challenge.hnu.kr.": "_ACME-challenge.acme.example.kr"})
    p.present("_acme-challenge.hnu.kr", "v1")
    p.cleanup("_acme-challenge.hnu.kr", "v1")
    p.present("_acme-challenge.other.kr", "v2")                                  # 매핑에 없으면 원래 이름
    assert inner.calls == [("present", "_acme-challenge.acme.example.kr", "v1"), ("cleanup", "_acme-challenge.acme.example.kr", "v1"),
                           ("present", "_acme-challenge.other.kr", "v2")]
    assert p.name == "rec" and p.automatic is True


def test_delegating_provider_auto_uses_dns_and_survives_lookup_failure():
    inner = Rec()
    p = dnsprov.DelegatingProvider(inner, auto=True, resolvers=["1.2.3.4"], resolve=lambda n, r: "_acme-challenge.x.example.kr" if "hnu" in n else None)
    p.present("_acme-challenge.hnu.kr", "v")
    p.present("_acme-challenge.plain.kr", "w")
    assert [c[1] for c in inner.calls] == ["_acme-challenge.x.example.kr", "_acme-challenge.plain.kr"]

    def boom(n, r):
        raise dnsquery.DnsError("조회 실패")
    q = dnsprov.DelegatingProvider(Rec(), auto=True, resolvers=["1.2.3.4"], resolve=boom)
    q.present("_acme-challenge.hnu.kr", "v")                                      # 조회 실패 → 원래 이름으로 시도(전파 확인에서 드러남)
    assert q.inner.calls[0][1] == "_acme-challenge.hnu.kr"


def test_resolve_cname_chain_and_loop(env):
    env.zone.cname["_acme-challenge.hnu.kr"] = "_acme-challenge.mid.example.kr"
    env.zone.cname["_acme-challenge.mid.example.kr"] = "_acme-challenge.end.example.kr"
    res = [env.dns.resolver]
    assert dnsquery.resolve_cname("_acme-challenge.hnu.kr", res) == "_acme-challenge.end.example.kr"
    assert dnsquery.resolve_cname("_acme-challenge.end.example.kr", res) is None
    env.zone.cname["_acme-challenge.end.example.kr"] = "_acme-challenge.hnu.kr"
    with pytest.raises(dnsquery.DnsError, match="순환"):
        dnsquery.resolve_cname("_acme-challenge.hnu.kr", res)


@pytest.mark.parametrize("delegate,ok", [("auto", True), ({"_acme-challenge.hnu.kr": "_acme-challenge.acme.example.kr"}, True), (None, True),
                                         ("manual", False), ({"hnu.kr": "x.example.kr"}, False), ({"_acme-challenge.hnu.kr": "bad name"}, False), ({}, False), (5, False)])
def test_delegate_config_validation(delegate, ok):
    a = {"domains": ["*.hnu.kr"], "dns": {"mode": "infoblox", "check_resolvers": ["127.0.0.1"], "infoblox": {"host": "h", "user_env": "U", "password_env": "P"}}}
    if delegate is not None:
        a["dns"]["delegate"] = delegate
    cfg = {"acme": a, "targets": [{"name": "w", "type": "apache", "cert_path": "/c", "key_path": "/k"}]}
    if ok:
        c = parse_config(cfg).acme
        assert bool(c["dns"]["delegate_auto"]) == (delegate == "auto") and bool(c["dns"]["delegate_map"]) == isinstance(delegate, dict)
    else:
        with pytest.raises(ConfigError, match="delegate"):
            parse_config(cfg)


def test_auto_delegate_requires_resolvers():
    a = {"domains": ["hnu.kr"], "dns": {"mode": "manual", "delegate": "auto"}}
    with pytest.raises(ConfigError, match="check_resolvers"):
        parse_config({"acme": a, "targets": [{"name": "w", "type": "apache", "cert_path": "/c", "key_path": "/k"}]})


def test_manual_instructions_point_to_delegated_name(env):
    pend = {"challenges": [{"valid": False, "txt_name": "_acme-challenge.hnu.kr", "txt_value": "VAL"}]}
    text = acme.instructions(pend, {"_acme-challenge.hnu.kr": "_acme-challenge.acme.example.kr"})
    assert "이름: _acme-challenge.acme.example.kr" in text and "CNAME 위임" in text and "VAL" in text
    assert "CNAME" not in acme.instructions(pend)


def test_issue_end_to_end_with_cname_delegation(env):
    """CA 가 CNAME 을 따라 검증하는 구성: TXT 는 위임 대상 이름에만 생기고 발급 후 삭제된다."""
    env.zone.cname["_acme-challenge.hnu.kr"] = "_acme-challenge.acme.example.kr"
    seen = []
    orig_add, orig_remove = env.zone.add, env.zone.remove
    env.zone.add = lambda n, v: (seen.append(("add", n)), orig_add(n, v))[1]
    env.zone.remove = lambda n, v: (seen.append(("remove", n)), orig_remove(n, v))[1]
    srv = fk.start_wapi(env.zone)
    try:
        cfgp, marks, web = base_cfg(env.tmp, env, "manual")
        raw = yaml.safe_load(open(cfgp))
        raw["acme"]["dns"] = {"mode": "infoblox", "infoblox": {"host": f"127.0.0.1:{srv.server_port}", "user_env": "IB_U", "password_env": "IB_P", "scheme": "http"},
                              "check_resolvers": [env.dns.resolver], "propagation_timeout": 0,
                              "delegate": {"_acme-challenge.hnu.kr": "_acme-challenge.acme.example.kr"}}
        open(cfgp, "w").write(yaml.safe_dump(raw))
        r = cd(cfgp, "issue", env={"IB_U": "acme-svc", "IB_P": "s3cret-pw"})
        assert r.exit_code == 0, r.output
        assert "발급 완료" in r.output
        assert {n for _, n in seen} == {"_acme-challenge.acme.example.kr"}, seen              # 챌린지 이름이 아니라 위임 대상에만 등록·삭제
        assert env.zone.txt.get("_acme-challenge.acme.example.kr") == [] and not env.zone.txt.get("_acme-challenge.hnu.kr")
    finally:
        srv.shutdown()
