"""수동 발급 인증서(상용 CA 구매 등) 흐름: CSR 생성 → CA 가 준 파일 정리·검증 → 설치 → 자동 배포."""
import os
import shutil
import stat
import subprocess

import pytest
import yaml
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

from certdeploy import manual as mn
from certdeploy.cli import main
from pki_helpers import make_pki, sign_csr

DOMAINS = ["*.univ.example", "univ.example"]


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def pem(c):
    return c.public_bytes(serialization.Encoding.PEM)


def der(c):
    return c.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def ca(tmp_path):
    """같은 루트/중간 CA. make_pki 를 한 번 호출해 CA 를 만들어 둔다."""
    shared = {}
    make_pki(tmp_path / "unused_ca_dir" if (tmp_path / "unused_ca_dir").mkdir() is None else tmp_path, name="seed", shared_ca=shared)
    return shared


def issue(ca, key_pem, domains=DOMAINS, **kw):
    """CSR 을 만들어 CA 가 서명한 서버 인증서를 돌려준다(키는 호출자가 가진 것)."""
    csr_key, csr = mn.generate_csr(domains)
    return csr_key, csr, sign_csr(csr, ca, **kw)


# ------------------------------------------------------------------ CSR
@pytest.mark.parametrize("key_type", mn.KEY_TYPES)
def test_csr_contents_and_key_types(key_type):
    key_pem, csr_pem = mn.generate_csr(DOMAINS, key_type, {"C": "KR", "O": "Univ", "OU": "전산실"})
    csr = x509.load_pem_x509_csr(csr_pem)
    assert csr.is_signature_valid
    assert csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "*.univ.example"      # CN = 첫 도메인
    assert csr.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value == "KR"
    assert csr.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "전산실"
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert san == DOMAINS
    key = serialization.load_pem_private_key(key_pem, None)
    assert key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == \
        csr.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def test_csr_verified_by_openssl(tmp_path):
    key_pem, csr_pem = mn.generate_csr(DOMAINS)
    f = tmp_path / "a.csr"
    f.write_bytes(csr_pem)
    r = subprocess.run(["openssl", "req", "-in", str(f), "-noout", "-verify", "-text"], capture_output=True, text=True)
    assert r.returncode == 0 and "DNS:*.univ.example" in r.stdout and "verify OK" in r.stderr + r.stdout


@pytest.mark.parametrize("domains", [[], [" "], ["a b.example"], ["*.*.univ.example"], ["a*.univ.example"], ["x/y.example"]])
def test_csr_rejects_bad_domains(domains):
    with pytest.raises(mn.ManualError):
        mn.generate_csr(domains)
    with pytest.raises(mn.ManualError, match="key_type"):
        mn.generate_csr(["a.example"], "dsa")
    with pytest.raises(mn.ManualError, match="subject"):
        mn.generate_csr(["a.example"], "rsa2048", {"X": "y"})


def test_pending_key_is_protected_and_not_overwritten(tmp_path):
    key_pem, csr_pem = mn.generate_csr(DOMAINS)
    kp, cp = mn.save_pending(str(tmp_path / "st"), "wild", key_pem, csr_pem)
    assert mode(kp) == 0o600 and mode(os.path.dirname(kp)) == 0o700 and mode(cp) == 0o644
    with pytest.raises(mn.ManualError, match="이미 대기 중인 키"):
        mn.save_pending(str(tmp_path / "st"), "wild", b"other", b"csr")            # CA 에 제출한 CSR 의 키를 잃지 않도록
    assert open(kp, "rb").read() == key_pem
    k2, c2 = mn.generate_csr(DOMAINS)
    mn.save_pending(str(tmp_path / "st"), "wild", k2, c2, force=True)
    assert open(kp, "rb").read() == k2


# ------------------------------------------------------------------ 인증서 수집·체인 정리
def test_collect_pem_der_pkcs7_and_dedupe(tmp_path, ca):
    key_pem, csr_pem = mn.generate_csr(DOMAINS)
    leaf = sign_csr(csr_pem, ca)
    inter, root = ca["inter"], ca["root"]
    (tmp_path / "leaf.pem").write_bytes(pem(leaf))
    (tmp_path / "leaf.cer").write_bytes(der(leaf))
    (tmp_path / "chain.p7b").write_bytes(pkcs7.serialize_certificates([inter, root], serialization.Encoding.PEM))
    (tmp_path / "chain.der.p7b").write_bytes(pkcs7.serialize_certificates([inter, root], serialization.Encoding.DER))
    (tmp_path / "bundle.pem").write_bytes(pem(inter) + pem(root))
    assert len(mn.collect_certs([str(tmp_path / "leaf.pem")])) == 1
    assert len(mn.collect_certs([str(tmp_path / "leaf.cer")])) == 1
    assert len(mn.collect_certs([str(tmp_path / "chain.p7b")])) == 2
    assert len(mn.collect_certs([str(tmp_path / "chain.der.p7b")])) == 2
    got = mn.collect_certs([str(tmp_path / "leaf.pem"), str(tmp_path / "leaf.cer"), str(tmp_path / "bundle.pem"), str(tmp_path / "chain.p7b")])
    assert len(got) == 3                                                  # 같은 지문은 하나로


def test_collect_errors(tmp_path):
    (tmp_path / "junk").write_bytes(b"not a certificate")
    with pytest.raises(mn.ManualError, match="해석할 수 없습니다"):
        mn.collect_certs([str(tmp_path / "junk")])
    with pytest.raises(mn.ManualError, match="읽을 수 없습니다"):
        mn.collect_certs([str(tmp_path / "missing")])


def test_build_bundle_orders_chain_drops_root_and_unrelated(tmp_path, ca):
    key_pem, csr_pem = mn.generate_csr(DOMAINS)
    key = serialization.load_pem_private_key(key_pem, None)
    leaf = sign_csr(csr_pem, ca)
    other_key, _, other_leaf = issue(ca, None, ["other.example"])
    shuffled = [ca["root"], other_leaf, ca["inter"], leaf]               # 뒤섞인 입력
    b, notes = mn.build_bundle(shuffled, key)
    assert b.serial == leaf.serial_number and [c.subject for c in b.chain] == [ca["inter"].subject]
    assert any("자체 서명 루트" in n for n in notes) and any("연결되지 않는" in n for n in notes)
    assert b.fullchain_pem().count(b"BEGIN CERTIFICATE") == 2            # 서버 + 중간 CA 만
    nochain, notes2 = mn.build_bundle([leaf], key)
    assert nochain.chain == [] and any("중간 CA 가 없습니다" in n for n in notes2)


def test_build_bundle_rejects_wrong_key_expired_and_not_yet(ca):
    key_pem, csr_pem = mn.generate_csr(DOMAINS)
    key = serialization.load_pem_private_key(key_pem, None)
    wrong_key = serialization.load_pem_private_key(mn.generate_csr(DOMAINS)[0], None)
    leaf = sign_csr(csr_pem, ca)
    with pytest.raises(mn.ManualError, match="일치하는 서버 인증서가 없습니다"):
        mn.build_bundle([leaf, ca["inter"]], wrong_key)
    with pytest.raises(mn.ManualError, match="만료"):
        mn.build_bundle([sign_csr(csr_pem, ca, days_from=-300, days_to=-1), ca["inter"]], key)
    with pytest.raises(mn.ManualError, match="유효하지 않습니다"):
        mn.build_bundle([sign_csr(csr_pem, ca, days_from=5, days_to=200), ca["inter"]], key)


def test_build_bundle_prefers_newest_when_old_and_new_both_match(ca):
    """같은 키로 재발급된 이전/신규 인증서가 섞여 있으면 만료가 더 늦은 것을 서버 인증서로 고른다."""
    key_pem, csr_pem = mn.generate_csr(DOMAINS)
    key = serialization.load_pem_private_key(key_pem, None)
    old, new = sign_csr(csr_pem, ca, days_from=-150, days_to=50), sign_csr(csr_pem, ca, days_from=-1, days_to=200)
    b, _ = mn.build_bundle([old, new, ca["inter"]], key)
    assert b.serial == new.serial_number


def test_pfx_roundtrip_and_wrong_password(tmp_path, ca):
    key_pem, csr_pem = mn.generate_csr(DOMAINS)
    key = serialization.load_pem_private_key(key_pem, None)
    leaf = sign_csr(csr_pem, ca)
    pfx = tmp_path / "x.pfx"
    pfx.write_bytes(pkcs12.serialize_key_and_certificates(b"w", key, leaf, [ca["inter"]], serialization.BestAvailableEncryption(b"pw1234")))
    k, certs = mn.load_pfx(str(pfx), "pw1234")
    assert len(certs) == 2 and mn.build_bundle(certs, k)[0].serial == leaf.serial_number
    with pytest.raises(mn.ManualError, match="PFX 를 열 수 없습니다"):
        mn.load_pfx(str(pfx), "wrong")
    nokey = tmp_path / "nokey.pfx"
    nokey.write_bytes(pkcs12.serialize_key_and_certificates(b"w", None, leaf, None, serialization.NoEncryption()))
    with pytest.raises(mn.ManualError, match="개인키"):
        mn.load_pfx(str(nokey), None)


def test_install_bundle_permissions_atomic_and_backup(tmp_path, ca):
    key_pem, csr_pem = mn.generate_csr(DOMAINS)
    key = serialization.load_pem_private_key(key_pem, None)
    b, _ = mn.build_bundle([sign_csr(csr_pem, ca), ca["inter"]], key)
    cert_f, key_f = tmp_path / "live" / "w.crt", tmp_path / "live" / "w.key"
    assert mn.install_bundle(str(cert_f), str(key_f), b) == []                    # 처음 설치: 백업 없음
    assert mode(cert_f) == 0o644 and mode(key_f) == 0o600 and cert_f.read_bytes() == b.fullchain_pem()
    k2, c2 = mn.generate_csr(DOMAINS)
    b2, _ = mn.build_bundle([sign_csr(c2, ca), ca["inter"]], serialization.load_pem_private_key(k2, None))
    baks = mn.install_bundle(str(cert_f), str(key_f), b2)
    assert len(baks) == 2 and all(mode(x) == 0o600 for x in baks)                  # 키가 든 백업도 600
    assert open([x for x in baks if x.startswith(str(key_f))][0], "rb").read() == key_pem
    assert not [p for p in os.listdir(cert_f.parent) if p.startswith(".tmp")]


# ------------------------------------------------------------------ CLI 전 과정: CSR → CA 발급 → 가져오기 → 자동 배포
@pytest.fixture
def stack(tmp_path):
    web = tmp_path / "web"
    web.mkdir()
    marks = tmp_path / "reload.log"
    cfg = {"state_dir": str(tmp_path / "state"),
           "certificate": {"cert_file": str(tmp_path / "managed" / "wildcard.crt"), "key_file": str(tmp_path / "managed" / "wildcard.key")},
           "targets": [{"name": "web1", "type": "generic", "check_cmd": "true", "reload_cmd": f"echo r >> {marks}",
                        "files": [{"path": str(web / "site.crt"), "content": "fullchain"}, {"path": str(web / "site.key"), "content": "key"}]}]}
    path = tmp_path / "cd.yml"
    path.write_text(yaml.safe_dump(cfg))
    return type("S", (), {"cfg": str(path), "web": web, "marks": marks, "tmp": tmp_path, "raw": cfg})


def cli(stack, *args, env=None):
    return CliRunner().invoke(main, ["-c", stack.cfg, *args], env=env, catch_exceptions=False)


def test_manual_wildcard_flow_csr_to_auto_deploy(stack, ca):
    r = cli(stack, "csr", "--domains", "*.univ.example,univ.example", "--country", "KR", "--org", "Univ")
    assert r.exit_code == 0 and "BEGIN CERTIFICATE REQUEST" in r.output and "개인키는 외부로 보내지 마세요" in r.output
    pending = stack.tmp / "state" / "pending" / "default"
    assert mode(pending / "key.pem") == 0o600 and (pending / "default.csr").exists()
    assert cli(stack, "csr", "--domains", "x.example").exit_code != 0            # 대기 키 보호

    # --- 여기서 CA 가 CSR 에 서명해 서버 인증서와 중간 CA 번들(p7b)을 보낸다고 가정
    leaf = sign_csr((pending / "default.csr").read_bytes(), ca)
    (stack.tmp / "server.cer").write_bytes(der(leaf))
    (stack.tmp / "intermediates.p7b").write_bytes(pkcs7.serialize_certificates([ca["inter"], ca["root"]], serialization.Encoding.PEM))

    dry = cli(stack, "import", "--file", str(stack.tmp / "server.cer"), "--file", str(stack.tmp / "intermediates.p7b"), "--dry-run")
    assert dry.exit_code == 0 and "중간 CA 1개" in dry.output and "자체 서명 루트" in dry.output and "설치하지 않았습니다" in dry.output
    assert not (stack.tmp / "managed" / "wildcard.crt").exists()

    r = cli(stack, "import", "--file", str(stack.tmp / "server.cer"), "--file", str(stack.tmp / "intermediates.p7b"), "--deploy")
    assert r.exit_code == 0, r.output
    assert "설치 완료" in r.output and "배포 완료" in r.output
    assert mode(stack.tmp / "managed" / "wildcard.key") == 0o600
    fullchain = (stack.web / "site.crt").read_bytes()
    assert fullchain.count(b"BEGIN CERTIFICATE") == 2 and (stack.web / "site.key").read_bytes() == (stack.tmp / "managed" / "wildcard.key").read_bytes()
    assert stack.marks.read_text().split() == ["r"]
    assert not (pending / "key.pem").exists()                                    # 개인키 사본이 두 곳에 남지 않음
    assert cli(stack, "validate").exit_code == 0
    # 같은 인증서를 다시 배포하면 멱등(재로드 없음)
    assert "건너뜀" in cli(stack, "deploy").output and stack.marks.read_text().split() == ["r"]


def test_import_error_messages_and_exit_codes(stack, ca, tmp_path):
    key_pem, csr_pem = mn.generate_csr(DOMAINS)
    leaf = sign_csr(csr_pem, ca)
    (tmp_path / "leaf.pem").write_bytes(pem(leaf))
    r = cli(stack, "import", "--file", str(tmp_path / "leaf.pem"))                  # 키 없음
    assert r.exit_code == 2 and "개인키가 없습니다" in r.output and "certdeploy csr" in r.output
    other_key = tmp_path / "other.key"
    other_key.write_bytes(mn.generate_csr(DOMAINS)[0])
    r2 = cli(stack, "import", "--file", str(tmp_path / "leaf.pem"), "--key-file", str(other_key))
    assert r2.exit_code == 2 and "일치하는 서버 인증서가 없습니다" in r2.output
    r3 = cli(stack, "import")
    assert r3.exit_code == 2 and "--file" in r3.output
    expired = sign_csr(csr_pem, ca, days_from=-300, days_to=-1)
    (tmp_path / "old.pem").write_bytes(pem(expired))
    good_key = tmp_path / "good.key"
    good_key.write_bytes(key_pem)
    r4 = cli(stack, "import", "--file", str(tmp_path / "old.pem"), "--key-file", str(good_key))
    assert r4.exit_code == 2 and "만료" in r4.output
    r5 = cli(stack, "import", "--file", str(tmp_path / "leaf.pem"), "--key-file", str(good_key))   # 정상(체인 없음 → 주의만)
    assert r5.exit_code == 0 and "중간 CA 가 없습니다" in r5.output
    assert "BEGIN" not in r.output + r2.output + r4.output                           # 키 내용은 출력되지 않음


def test_import_from_pfx_with_password_env(stack, ca, tmp_path):
    key_pem, csr_pem = mn.generate_csr(DOMAINS)
    key = serialization.load_pem_private_key(key_pem, None)
    pfx = tmp_path / "vendor.pfx"
    pfx.write_bytes(pkcs12.serialize_key_and_certificates(b"w", key, sign_csr(csr_pem, ca), [ca["inter"]], serialization.BestAvailableEncryption(b"vendorpw1")))
    r = cli(stack, "import", "--pfx", str(pfx), "--pfx-pass-env", "PFX_PW", "--deploy", env={"PFX_PW": "vendorpw1"})
    assert r.exit_code == 0 and "배포 완료" in r.output
    assert cli(stack, "import", "--pfx", str(pfx), "--pfx-pass-env", "PFX_PW", env={"PFX_PW": "wrong"}).exit_code == 2


def test_import_replaces_existing_and_keeps_backup(stack, ca, tmp_path):
    for i in range(2):
        key_pem, csr_pem = mn.generate_csr(DOMAINS)
        (tmp_path / f"k{i}.key").write_bytes(key_pem)
        (tmp_path / f"c{i}.pem").write_bytes(pem(sign_csr(csr_pem, ca)) + pem(ca["inter"]))
    assert cli(stack, "import", "--file", str(tmp_path / "c0.pem"), "--key-file", str(tmp_path / "k0.key")).exit_code == 0
    r = cli(stack, "import", "--file", str(tmp_path / "c1.pem"), "--key-file", str(tmp_path / "k1.key"))
    assert r.exit_code == 0 and r.output.count("이전 파일 백업") == 2
    assert sorted(p for p in os.listdir(tmp_path / "managed") if ".bak-" in p) != []


def test_csr_and_import_need_cert_name_when_multiple(tmp_path, stack):
    raw = stack.raw
    two = {"state_dir": raw["state_dir"], "certificates": [
        {"name": "a", "certificate": raw["certificate"], "targets": raw["targets"]},
        {"name": "b", "certificate": {"cert_file": "/x/b.crt", "key_file": "/x/b.key"}, "targets": [{**raw["targets"][0]}]}]}
    open(stack.cfg, "w").write(yaml.safe_dump(two))
    r = CliRunner().invoke(main, ["-c", stack.cfg, "csr", "--domains", "a.example"])
    assert r.exit_code != 0 and "--cert" in r.output
    ok = CliRunner().invoke(main, ["-c", stack.cfg, "--cert", "a", "csr", "--domains", "a.example"])
    assert ok.exit_code == 0 and os.path.exists(tmp_path / "state" / "a" / "pending" / "a" / "key.pem")
