from certpilot_core.cert_parser import parse_jks, parse_pem_certificates, parse_pkcs12


def test_parse_valid_pem(cert_dir):
    certs = parse_pem_certificates(str(cert_dir / "valid.pem"))
    assert len(certs) == 1
    assert "valid.test" in certs[0].subject
    assert not certs[0].is_expired and not certs[0].is_not_yet_valid


def test_expired_and_future_flags(cert_dir):
    assert parse_pem_certificates(str(cert_dir / "expired.pem"))[0].is_expired
    assert parse_pem_certificates(str(cert_dir / "not_yet_valid.pem"))[0].is_not_yet_valid


def test_corrupt_pem_yields_nothing(cert_dir):
    assert parse_pem_certificates(str(cert_dir / "corrupt.pem")) == []


def test_san_extracted(cert_dir):
    certs = parse_pem_certificates(str(cert_dir / "valid.pem"))
    assert any("valid.test" in s for s in certs[0].subject_alt_name)


def test_public_key_bits(cert_dir):
    # 알려진 결함: Public-Key 정규식이 "(2048 bit)" 형식과 맞지 않아 0 으로 남는다.
    assert parse_pem_certificates(str(cert_dir / "valid.pem"))[0].public_key_bits == 2048


def test_pkcs12(pkcs12_file):
    certs = parse_pkcs12(str(pkcs12_file), "changeit")
    assert len(certs) == 1 and "p12.test" in certs[0].subject


def test_jks(jks_file):
    certs = parse_jks(str(jks_file))
    assert len(certs) == 1 and "jks.test" in certs[0].subject
