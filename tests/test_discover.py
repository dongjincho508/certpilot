"""인증서 자동 탐색: 범위 계산·인증서 해석·분류·실제 TLS 소켓 조회·CLI·지표·설정 파일 연결"""
import json
import socket
import ssl
import threading
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from certdeploy import discover as dv
from certdeploy.discover_cli import main as cli
from pki_helpers import make_pki

ROOT = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------ 시험용 TLS 서버
class TlsServer:
    def __init__(self, cert, key, minimum=None):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        self.ctx = ctx
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    def run(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                self.ctx.wrap_socket(c, server_side=True).close()
            except (ssl.SSLError, OSError):
                c.close()

    def close(self):
        self.sock.close()


@pytest.fixture
def servers(tmp_path):
    made = []

    def make(name="a", days_to=90, san=("web.hnu.kr",)):
        c, k, _, _ = make_pki(tmp_path, name=name, san=san, days_to=days_to)
        s = TlsServer(c, k)
        made.append(s)
        return s
    yield make
    for s in made:
        s.close()


# ------------------------------------------------------------------ 범위
def test_expand_scope_cidr_and_names():
    s = dv.expand_scope(["10.0.0.0/30"], ["A.hnu.kr", "a.hnu.kr", "# c", ""])
    assert [x[0] for x in s] == ["10.0.0.1", "10.0.0.2", "a.hnu.kr"] and s[-1][1] == "a.hnu.kr"


def test_single_ip_included():
    assert dv.expand_scope(["10.0.0.5/32"], [])[0] == ("10.0.0.5", None)


def test_public_range_refused_unless_allowed():
    with pytest.raises(dv.DiscoverError):
        dv.expand_scope(["8.8.8.0/30"], [])
    assert dv.expand_scope(["8.8.8.8/32"], [], allow_public=True)


def test_max_hosts_guard():
    with pytest.raises(dv.DiscoverError):
        dv.expand_scope(["10.0.0.0/16"], [], max_hosts=4096)


@pytest.mark.parametrize("bad", ["not-a-cidr", "10.0.0.0/99"])
def test_bad_cidr(bad):
    with pytest.raises(dv.DiscoverError):
        dv.expand_scope([bad], [])


def test_bad_name():
    with pytest.raises(dv.DiscoverError):
        dv.expand_scope([], ["a b;c"])


def test_ports():
    assert dv.parse_ports(["443,8443", "9000-9002"]) == [443, 8443, 9000, 9001, 9002]
    for bad in (["0"], ["70000"], ["x"], ["1-5000"]):
        with pytest.raises(dv.DiscoverError):
            dv.parse_ports(bad)


# ------------------------------------------------------------------ 인증서 해석·분류
def test_parse_cert_fields(tmp_path):
    c, _, leaf, _ = make_pki(tmp_path, san=("a.hnu.kr", "*.hnu.kr"), days_to=40)
    from cryptography.hazmat.primitives import serialization
    r = dv.parse_cert(leaf.public_bytes(serialization.Encoding.DER))
    assert r["san"] == ["a.hnu.kr", "*.hnu.kr"] and r["key"].startswith("RSA-") and 39 < r["days_left"] < 41
    assert r["self_signed"] is False and r["sig_hash"] == "sha256"


@pytest.mark.parametrize("pat,host,ok", [("*.hnu.kr", "a.hnu.kr", True), ("*.hnu.kr", "a.b.hnu.kr", False),
                                         ("a.hnu.kr", "A.hnu.kr", True), ("*.hnu.kr", "hnu.kr", False)])
def test_name_matches(pat, host, ok):
    assert dv.name_matches(pat, host) is ok


def _rec(**kw):
    base = dict(addr="10.0.0.5", port=443, sni=None, ptr=None, days_left=100, self_signed=False, key_alg="RSA", key_bits=2048,
                sig_hash="sha256", tls_version="TLSv1.3", san=["web.hnu.kr"], subject="web.hnu.kr")
    base.update(kw)
    return base


def test_classify_flags():
    none = lambda h: set()  # noqa: E731
    r = dv.classify(_rec(days_left=-1, self_signed=True, key_bits=1024, sig_hash="sha1", tls_version="TLSv1"), set(), ["hnu.kr"], none)
    assert set(r["flags"]) == {"unregistered", "expired", "self_signed", "weak_key", "weak_signature", "old_tls"}
    assert r["our_domain"] is True
    assert "expiring" in dv.classify(_rec(days_left=10), set(), [], none)["flags"]
    assert dv.classify(_rec(sni="other.hnu.kr"), set(), [], none)["flags"].count("name_mismatch") == 1


def test_registered_by_name_ip_or_resolution():
    none = lambda h: set()  # noqa: E731
    assert dv.classify(_rec(sni="web.hnu.kr"), {("web.hnu.kr", 443)}, [], none)["registered"]
    assert dv.classify(_rec(), {("10.0.0.5", 443)}, [], none)["registered"]
    assert dv.classify(_rec(ptr="web.hnu.kr"), {("web.hnu.kr", 443)}, [], none)["registered"]
    assert dv.classify(_rec(), {("web.hnu.kr", 443)}, [], lambda h: {"10.0.0.5"})["registered"]      # 호스트명 등록 → IP 로 풀림
    assert not dv.classify(_rec(), {("web.hnu.kr", 8443)}, [], lambda h: {"10.0.0.5"})["registered"]  # 포트가 다르면 별개
    assert not dv.classify(_rec(), {("x.hnu.kr", 443)}, [], lambda h: {"10.9.9.9"})["registered"]


def test_load_known(tmp_path):
    f = tmp_path / "t.yml"
    f.write_text('- targets: ["Web.hnu.kr:443", "[::1]:8443"]\n  labels: {a: b}\n- targets: ["bad"]\n')
    assert dv.load_known([str(tmp_path / "*.yml")]) == {("web.hnu.kr", 443), ("::1", 8443)}
    f.write_text("- [broken")
    with pytest.raises(dv.DiscoverError):
        dv.load_known([str(f)])


# ------------------------------------------------------------------ 실제 소켓 조회
def test_probe_closed_nontls_and_tls(servers):
    s = servers()
    assert dv.probe("127.0.0.1", s.port, "web.hnu.kr", 3)["tls"] is True
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    assert dv.probe("127.0.0.1", port, None, 1) is None
    plain = socket.socket()
    plain.bind(("127.0.0.1", 0))
    plain.listen(1)
    threading.Thread(target=lambda: (plain.accept()[0].sendall(b"hello\r\n")), daemon=True).start()
    assert dv.probe("127.0.0.1", plain.getsockname()[1], None, 2) == {"tls": False}
    plain.close()


def test_scan_end_to_end(servers):
    a, b = servers("a", 90), servers("b", 10)
    scope = dv.expand_scope(["127.0.0.1/32"], [])
    known = {("127.0.0.1", a.port)}
    res = dv.scan(scope, [a.port, b.port, 1], known, ["hnu.kr"], timeout=2, reverser=lambda ip: None)
    s = res["summary"]
    assert (s["tls_endpoints"], s["registered"], s["unregistered"], s["expiring"]) == (2, 1, 1, 1)
    assert res["endpoints"][0]["port"] == b.port                      # 만료 임박 순 정렬
    txt = dv.report_text(res)
    assert "미등록" in txt and "임박" in txt
    ty = yaml.safe_load(dv.targets_yaml(res))
    assert len(ty) == 1 and ty[0]["targets"] == [f"web.hnu.kr:{b.port}"] and ty[0]["labels"]["group"] == "미등록-발견"
    m = dv.metrics_text(res)
    assert "certdeploy_discovery_unregistered 1" in m and "certdeploy_discovery_endpoints 2" in m


def test_diff_previous(servers):
    a = servers("a")
    scope = dv.expand_scope(["127.0.0.1/32"], [])
    r1 = dv.scan(scope, [a.port], set(), [], reverser=lambda ip: None)
    assert dv.diff_previous(r1, None) == {"appeared": [], "disappeared": [], "changed": []}
    r2 = dict(r1, endpoints=[])
    d = dv.diff_previous(r2, r1)
    assert len(d["disappeared"]) == 1 and not d["appeared"]
    assert len(dv.diff_previous(r1, r2)["appeared"]) == 1


# ------------------------------------------------------------------ CLI
def test_cli_flow_and_exit_codes(servers, tmp_path):
    a, b = servers("a"), servers("b")
    known = tmp_path / "known.yml"
    known.write_text(f'- targets: ["127.0.0.1:{a.port}"]\n  labels: {{group: t}}\n')
    out, new = tmp_path / "d.json", tmp_path / "new.yml"
    args = ["--cidr", "127.0.0.1/32", "--port", f"{a.port},{b.port}", "--known", str(known), "--out", str(out),
            "--emit-targets", str(new), "--no-reverse-dns"]
    r = CliRunner().invoke(cli, args)
    assert r.exit_code == 0 and "미등록 1" in r.output
    assert json.loads(out.read_text())["summary"]["unregistered"] == 1 and new.exists()
    assert CliRunner().invoke(cli, args + ["--fail-on-unregistered"]).exit_code == 3
    j = CliRunner().invoke(cli, args + ["--json"])
    assert json.loads(j.output)["delta"]["appeared"] == 0                 # 두 번째 실행부터 비교


def test_cli_errors(tmp_path):
    assert CliRunner().invoke(cli, []).exit_code == 2
    assert CliRunner().invoke(cli, ["--cidr", "8.8.8.0/30"]).exit_code == 2


def test_cli_config_file(servers, tmp_path):
    a = servers("a")
    cfg = tmp_path / "d.yml"
    cfg.write_text(yaml.safe_dump({"cidr": ["127.0.0.1/32"], "port": [str(a.port)], "known": [str(tmp_path / "none.yml")],
                                   "out": str(tmp_path / "o.json"), "no_reverse_dns": True}))
    r = CliRunner().invoke(cli, ["--config", str(cfg)])
    assert r.exit_code == 0 and "TLS 인증서 1개" in r.output
    cfg.write_text("bogus: 1\n")
    assert CliRunner().invoke(cli, ["--config", str(cfg)]).exit_code != 0


# ------------------------------------------------------------------ 배포 파일
def test_example_config_valid_and_keys_known():
    from certdeploy.discover_cli import CONFIG_KEYS
    d = yaml.safe_load((ROOT / "certdeploy/discovery.example.yml").read_text())
    assert set(d) <= CONFIG_KEYS
    dv.expand_scope(d["cidr"], [])
    dv.parse_ports(d["port"])


def test_systemd_units_present():
    s = (ROOT / "certdeploy/systemd/certdeploy-discover.service").read_text()
    assert "certdeploy-discover --config /etc/certdeploy/discovery.yml" in s and "ProtectSystem=strict" in s
    assert "OnCalendar" in (ROOT / "certdeploy/systemd/certdeploy-discover.timer").read_text()


def test_alert_rules_defined():
    r = yaml.safe_load((ROOT / "monitoring/prometheus/rules/certdeploy.yml").read_text())
    names = {x["alert"] for g in r["groups"] for x in g["rules"]}
    assert {"CertDiscoveryUnregistered", "CertDiscoveryExpiredFound", "CertDiscoveryNotRunning"} <= names
