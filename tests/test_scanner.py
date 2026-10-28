from datetime import datetime, timedelta, timezone

import pytest

from certpilot_core.remote import FailureCause, RemoteError, SandboxExecutor
from certpilot_core.scanner import Scanner, Target, TlsProbe
from certpilot_core.status import Status
from conftest import make_cert, pem

FIXED_NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def scanner(box, probe=None, factory=None, sleeps=None, **kw):
    f = factory or (lambda t: SandboxExecutor(box.path, **kw))
    return Scanner(f, probe=probe, clock=lambda: FIXED_NOW,
                   sleep=(sleeps.append if sleeps is not None else (lambda s: None)))


T = Target("s1", "web1", "web1.example", account="certscan", tls_ports=[])


def test_status_samples_from_standard_path(sandbox):  # AC-3, AC-4
    for name, args in {"ok": (-1, 90), "warn": (-60, 10), "exp": (-100, -1), "future": (5, 100)}.items():
        sandbox.put(f"/etc/nginx/ssl/{name}.crt", pem(make_cert(f"{name}.test", *args)[1]))
    res = scanner(sandbox).scan(T)
    by_cn = {r.info.subject.split("=")[1]: r.status for r in res.records}
    assert by_cn == {"ok.test": Status.OK, "warn.test": Status.WARN,
                     "exp.test": Status.EXPIRED, "future.test": Status.NOT_YET}
    assert res.status == Status.EXPIRED  # 최악 우선 집계 (Q-AGG)


def test_not_found_when_nothing(sandbox):  # AC-5
    sandbox.put("/etc/nginx/ssl/readme.txt", "x")
    assert scanner(sandbox).scan(T).status == Status.NOT_FOUND


def test_corrupt_is_unknown_not_ok(sandbox):  # AC-5
    sandbox.put("/etc/nginx/ssl/bad.crt", "-----BEGIN CERTIFICATE-----\nzzz\n-----END CERTIFICATE-----\n")
    sandbox.put("/etc/nginx/ssl/der.cer", b"\x30\x82\x01\x0a binary")
    res = scanner(sandbox).scan(T)
    assert res.status == Status.UNKNOWN
    assert all(r.status == Status.UNKNOWN for r in res.records)


def test_permission_denied_classified(sandbox):
    sandbox.put("/etc/nginx/ssl/a.crt", pem(make_cert()[1]))
    res = scanner(sandbox, denied=["/etc/nginx/ssl/a.crt"]).scan(T)
    assert res.status == Status.FETCH_FAIL and res.cause == FailureCause.PERMISSION


def test_private_key_never_read_or_exposed(sandbox):
    key, cert = make_cert()
    from cryptography.hazmat.primitives import serialization
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    sandbox.put("/etc/nginx/ssl/privkey.pem", key_pem)
    sandbox.put("/etc/nginx/ssl/combined.pem", pem(cert) + key_pem)
    ex_holder = {}

    def factory(t):
        ex_holder["ex"] = SandboxExecutor(sandbox.path)
        return ex_holder["ex"]

    res = scanner(sandbox, factory=factory).scan(T)
    assert not any("privkey" in c for h in ex_holder["ex"].history for c in h)
    assert "PRIVATE KEY" not in repr(res.to_dict())
    assert len(res.records) == 1


def test_bundle_leaf_and_chain_risk(sandbox):  # Q-CHAIN
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    import datetime as dt
    ca_key, ca = make_cert("ca.test", -10, 10)  # CA 만료 임박
    lk, _ = make_cert("leaf.test")
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.test")]))
            .issuer_name(ca.subject).public_key(lk.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1))
            .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=200))
            .sign(ca_key, hashes.SHA256()))
    sandbox.put("/etc/nginx/ssl/chain.crt", pem(leaf) + pem(ca))
    res = scanner(sandbox).scan(T)
    roles = {r.role: r.status for r in res.records}
    assert roles == {"leaf": Status.OK, "root": Status.CHAIN_RISK}
    assert res.status == Status.CHAIN_RISK


def test_custom_path_and_whitelist(sandbox):
    sandbox.put("/srv/app/tls/app.crt", pem(make_cert("app.test")[1]))
    t = Target("s1", "web1", "h", paths=["/srv/app/tls"])
    assert scanner(sandbox).scan(t).status == Status.OK
    # 등록되지 않은 경로는 읽지 않는다
    assert scanner(sandbox).scan(T).status == Status.NOT_FOUND


def test_symlink_out_of_scope_and_broken(sandbox):  # Q-SYMLINK
    sandbox.put("/etc/shadow-ish/secret.pem", pem(make_cert("secret.test")[1]))
    sandbox.link("/etc/nginx/ssl/out.crt", "/etc/shadow-ish/secret.pem")
    sandbox.link("/etc/nginx/ssl/broken.crt", "/etc/nginx/ssl/missing.crt")
    sandbox.put("/etc/nginx/ssl/real.crt", pem(make_cert("real.test")[1]))
    sandbox.link("/etc/nginx/ssl/alias.crt", "real.crt")
    res = scanner(sandbox).scan(T)
    notes = {r.sources[0]: r.note for r in res.records if r.status == Status.UNKNOWN}
    assert "허용 경로 밖" in notes["file:/etc/nginx/ssl/out.crt"]
    assert "깨진" in notes["file:/etc/nginx/ssl/broken.crt"]
    ok = [r for r in res.records if r.status == Status.OK]
    assert len(ok) == 1 and len(ok[0].sources) == 2  # alias 는 같은 지문으로 병합


def test_hash_change_detected_s4(sandbox):  # AC-7
    sandbox.put("/etc/nginx/ssl/a.crt", pem(make_cert("a.test")[1]))
    first = scanner(sandbox).scan(T)
    assert not first.records[0].changed
    sandbox.put("/etc/nginx/ssl/a.crt", pem(make_cert("a.test")[1]))  # 내용이 바뀜
    second = scanner(sandbox).scan(T, prev_hashes=first.file_hashes)
    assert second.records[0].changed and second.status == Status.UNKNOWN
    third = scanner(sandbox).scan(T, prev_hashes=second.file_hashes)
    assert not third.records[0].changed


def test_scan_never_modifies_remote(sandbox):  # AC-7
    f = sandbox.put("/etc/nginx/ssl/a.crt", pem(make_cert()[1]))
    before = (f.read_bytes(), f.stat().st_mtime_ns)
    scanner(sandbox).scan(T)
    assert (f.read_bytes(), f.stat().st_mtime_ns) == before


def test_webcfg_suggestions_not_scanned(sandbox):  # Q-WEBCFG
    sandbox.put("/etc/nginx/conf.d/site.conf",
                "server {\n ssl_certificate /opt/site/fullchain.pem;\n ssl_certificate_key /opt/site/k.key;\n"
                " ssl_certificate /srv/app/tls/app.crt;\n ssl_certificate /etc/x/privkey.pem;\n"
                " ssl_certificate /srv/../etc/shadow.pem;\n}\n")
    sandbox.put("/opt/site/fullchain.pem", pem(make_cert("site.test")[1]))
    res = scanner(sandbox).scan(T)
    assert "/opt/site/fullchain.pem" in res.suggested_paths
    assert "/srv/app/tls/app.crt" in res.suggested_paths     # 표준 루트 밖도 후보로는 제시
    assert not any("privkey" in p or ".." in p or p.endswith(".key") for p in res.suggested_paths)
    assert res.status == Status.NOT_FOUND  # 확정(등록) 전에는 스캔하지 않는다


def test_unsupported_openssh_is_unknown(sandbox):  # Q-SSHVER
    sandbox.put("/etc/nginx/ssl/a.crt", pem(make_cert()[1]))
    res = scanner(sandbox, server_version="SSH-2.0-OpenSSH_6.6").scan(T)
    assert res.status == Status.UNKNOWN


@pytest.mark.parametrize("cause,retries", [
    (FailureCause.DNS, 2), (FailureCause.TIMEOUT, 2),
    (FailureCause.AUTH, 0), (FailureCause.HOSTKEY, 0),
])
def test_retry_policy(sandbox, cause, retries):  # Q-RETRY
    calls, sleeps = [], []

    def factory(t):
        calls.append(1)
        raise RemoteError(cause, "raw secret detail")

    res = scanner(sandbox, factory=factory, sleeps=sleeps).scan(T)
    assert len(calls) == retries + 1
    assert sleeps == [1.0, 2.0][:retries]  # 지수 백오프
    assert res.status == Status.FETCH_FAIL and res.cause == cause
    assert "raw secret detail" not in repr(res.to_dict())  # S-8: 원문 비노출
    assert res.hostkey_blocked == (cause == FailureCause.HOSTKEY)


class FakeProbe(TlsProbe):
    def __init__(self, responses):
        self.responses = responses

    def fetch(self, host, port, sni=None, timeout=10):
        r = self.responses[port]
        if isinstance(r, Exception):
            raise r
        return r


def test_port_based_and_dedup(sandbox):  # Q-MODE (둘 다)
    from cryptography.hazmat.primitives import serialization
    _, cert = make_cert("shared.test")
    sandbox.put("/etc/nginx/ssl/shared.crt", pem(cert))
    der = cert.public_bytes(serialization.Encoding.DER)
    t = Target("s1", "web1", "h", tls_ports=[443, 8443])
    probe = FakeProbe({443: der, 8443: RemoteError(FailureCause.TIMEOUT, "x")})
    res = scanner(sandbox, probe=probe).scan(t)
    merged = [r for r in res.records if r.info]
    assert len(merged) == 1 and set(merged[0].sources) == {"file:/etc/nginx/ssl/shared.crt", "port:443"}
    fails = [r for r in res.records if r.status == Status.FETCH_FAIL]
    assert len(fails) == 1 and fails[0].sources == ["port:8443"]


def test_ports_scanned_even_if_ssh_fails(sandbox):
    from cryptography.hazmat.primitives import serialization
    der = make_cert("only-port.test")[1].public_bytes(serialization.Encoding.DER)

    def factory(t):
        raise RemoteError(FailureCause.AUTH, "")

    t = Target("s1", "web1", "h", tls_ports=[443])
    res = scanner(sandbox, probe=FakeProbe({443: der}), factory=factory).scan(t)
    assert any(r.status == Status.OK for r in res.records)
    assert res.status == Status.FETCH_FAIL  # 일부 실패는 정상으로 가리지 않는다


# ---------------------------------------------------------------- 등록 전 연결 테스트·경로 탐지
def test_check_connection_reports_paths_and_suggestions(sandbox):
    sandbox.put("/etc/nginx/ssl/a.crt", pem(make_cert("a.test")[1]))
    sandbox.put("/etc/nginx/ssl/b.pem", pem(make_cert("b.test")[1]))
    sandbox.put("/etc/nginx/conf.d/s.conf", "ssl_certificate /srv/app/tls/app.crt;\nssl_certificate /etc/nginx/ssl/a.crt;\n")
    out, raw = scanner(sandbox).check_connection(T)
    assert out["connected"] and out["supported"] and out["ssh_version"] == "9.6" and raw == ""
    std = {p["path"]: p["files"] for p in out["standard_paths"]}
    assert std == {"/etc/nginx/ssl": 2}
    assert [s["path"] for s in out["suggested_paths"]] == ["/srv/app/tls/app.crt"]  # 이미 조회되는 경로는 제외
    assert out["suggested_paths"][0]["in_standard_root"] is False


def test_check_connection_failure_is_classified_without_raw(sandbox):
    def factory(t):
        raise RemoteError(FailureCause.AUTH, "user certscan denied SHA256:abc")
    out, raw = scanner(sandbox, factory=factory).check_connection(T)
    assert not out["connected"] and out["cause"] == "AUTH" and out["cause_label"] == "인증 실패"
    assert "SHA256" not in repr(out) and "SHA256:abc" in raw
    assert out["action"]


def test_check_connection_hostkey_and_old_ssh(sandbox):
    def hk(t):
        raise RemoteError(FailureCause.HOSTKEY, "changed")
    assert scanner(sandbox, factory=hk).check_connection(T)[0]["hostkey_blocked"]
    out, _ = scanner(sandbox, server_version="SSH-2.0-OpenSSH_6.6").check_connection(T)
    assert out["connected"] and out["supported"] is False and out["standard_paths"] == []


def test_check_connection_tls_ports_and_extra_paths(sandbox):
    from cryptography.hazmat.primitives import serialization
    sandbox.put("/srv/app/tls/app.crt", pem(make_cert("app.test")[1]))
    der = make_cert("t.test")[1].public_bytes(serialization.Encoding.DER)
    t = Target("p", "probe", "h", paths=["/srv/app/tls"], tls_ports=[443, 8443])
    probe = FakeProbe({443: der, 8443: RemoteError(FailureCause.TIMEOUT, "x")})
    out, _ = scanner(sandbox, probe=probe).check_connection(t)
    assert {p["path"] for p in out["standard_paths"]} == {"/srv/app/tls"}
    tls = {x["port"]: x for x in out["tls"]}
    assert tls[443]["ok"] and tls[443]["subject"] == "CN=t.test"
    assert not tls[8443]["ok"] and tls[8443]["cause_label"] == "연결 시간 초과"
