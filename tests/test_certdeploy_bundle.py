import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from certdeploy.bundle import BundleError, hostname_matches, load_bundle
from pki_helpers import make_pki


def test_load_valid_bundle(tmp_path):
    cert, key, leaf, _ = make_pki(tmp_path)
    b = load_bundle(str(cert), str(key))
    assert b.serial == leaf.serial_number and len(b.chain) == 1
    assert b.names == ["univ.example", "*.univ.example"] and 80 < b.days_left() < 91
    assert b.warnings == []
    assert b.fullchain_pem().count(b"BEGIN CERTIFICATE") == 2 and b.cert_pem().count(b"BEGIN CERTIFICATE") == 1
    assert b.key_pem().startswith(b"-----BEGIN PRIVATE KEY-----")


def test_ec_key_supported(tmp_path):
    cert, key, *_ = make_pki(tmp_path, algo="ec")
    assert load_bundle(str(cert), str(key)).serial


@pytest.mark.parametrize("host,ok", [
    ("univ.example", True), ("www.univ.example", True), ("a.b.univ.example", False),   # 와일드카드는 한 레이블만
    ("other.example", False), ("WWW.UNIV.EXAMPLE.", True),
])
def test_covers(tmp_path, host, ok):
    cert, key, *_ = make_pki(tmp_path)
    assert load_bundle(str(cert), str(key)).covers(host) is ok


def test_hostname_matches_rules():
    assert not hostname_matches("*.univ.example", "univ.example")
    assert not hostname_matches("*.univ.example", ".univ.example")
    assert hostname_matches("a.univ.example", "A.univ.example")


def test_key_mismatch_rejected(tmp_path):
    cert, key, *_ = make_pki(tmp_path)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key.write_bytes(other.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    with pytest.raises(BundleError, match="일치하지 않습니다"):
        load_bundle(str(cert), str(key))


@pytest.mark.parametrize("kwargs,msg", [
    ({"days_to": -1, "days_from": -100}, "만료"),
    ({"days_from": 5, "days_to": 100}, "유효하지 않습니다"),
    ({"days_from": -10, "days_to": 0.3}, "의미가 없습니다"),
])
def test_validity_rejected(tmp_path, kwargs, msg):
    cert, key, *_ = make_pki(tmp_path, **kwargs)
    with pytest.raises(BundleError, match=msg):
        load_bundle(str(cert), str(key))


def test_missing_and_garbage_files(tmp_path):
    cert, key, *_ = make_pki(tmp_path)
    with pytest.raises(BundleError, match="인증서 파일이 없습니다"):
        load_bundle(str(tmp_path / "x.crt"), str(key))
    with pytest.raises(BundleError, match="개인키 파일이 없습니다"):
        load_bundle(str(cert), str(tmp_path / "x.key"))
    bad = tmp_path / "bad.key"
    bad.write_text("-----BEGIN PRIVATE KEY-----\nzzzz\n-----END PRIVATE KEY-----\n")
    with pytest.raises(BundleError, match="해석할 수 없습니다") as e:
        load_bundle(str(cert), str(bad))
    assert "zzzz" not in str(e.value)          # 키 내용은 오류 메시지에 넣지 않는다
    with pytest.raises(BundleError, match="인증서 PEM"):
        load_bundle(str(bad), str(key))


def test_encrypted_key_needs_password(tmp_path):
    cert, key, _, k = make_pki(tmp_path)
    key.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.BestAvailableEncryption(b"pw")))
    with pytest.raises(BundleError, match="암호로 보호"):
        load_bundle(str(cert), str(key))
    assert load_bundle(str(cert), str(key), "pw").serial


def test_warnings_for_missing_chain(tmp_path):
    cert, key, *_ = make_pki(tmp_path, chain=False)
    assert any("체인이 없습니다" in w for w in load_bundle(str(cert), str(key)).warnings)


def test_pkcs12_roundtrip_modern_and_legacy(tmp_path):
    cert, key, leaf, _ = make_pki(tmp_path)
    b = load_bundle(str(cert), str(key))
    for legacy in (False, True):
        data = b.pkcs12("changeit", alias="tomcat", legacy=legacy)
        k, c, extra = pkcs12.load_key_and_certificates(data, b"changeit")
        assert c.serial_number == leaf.serial_number and len(extra) == 1 and k is not None
    with pytest.raises(BundleError):
        b.pkcs12("")


@pytest.mark.skipif(shutil.which("keytool") is None, reason="keytool 없음")
def test_keystores_readable_by_java_keytool(tmp_path):
    """실제 JDK keytool 로 PKCS#12(현대/구형)·JKS 를 열어 별칭과 인증서를 확인한다."""
    cert, key, leaf, _ = make_pki(tmp_path)
    b = load_bundle(str(cert), str(key))
    blobs = {"modern.p12": (b.pkcs12("changeit", "tomcat"), "PKCS12"),
             "legacy.p12": (b.pkcs12("changeit", "tomcat", legacy=True), "PKCS12"),
             "store.jks": (b.jks("changeit", "tomcat"), "JKS")}
    for fname, (data, kind) in blobs.items():
        p = tmp_path / fname
        p.write_bytes(data)
        r = subprocess.run(["keytool", "-list", "-keystore", str(p), "-storetype", kind, "-storepass", "changeit"],
                           capture_output=True, text=True)
        assert r.returncode == 0, (fname, r.stdout, r.stderr)
        assert "tomcat" in r.stdout.lower() and ("PrivateKeyEntry" in r.stdout), (fname, r.stdout)
    bad = subprocess.run(["keytool", "-list", "-keystore", str(tmp_path / "store.jks"), "-storetype", "JKS",
                          "-storepass", "wrong"], capture_output=True, text=True)
    assert bad.returncode != 0


def test_jks_without_keytool_gives_clear_error(tmp_path):
    cert, key, *_ = make_pki(tmp_path)
    with pytest.raises(BundleError, match="keytool"):
        load_bundle(str(cert), str(key)).jks("changeit", keytool="no-such-keytool-binary")
