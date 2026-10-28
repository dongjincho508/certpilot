import json

from click.testing import CliRunner

from certpilot_cli.cli import main
from certpilot_core.audit_storage import AuditLogWriter


def test_check_file_ok_exit_0(cert_dir):
    r = CliRunner().invoke(main, ["check-file", str(cert_dir / "valid.pem")])
    assert r.exit_code == 0 and "정상" in r.output


def test_check_file_warn_and_expired_exit_1(cert_dir):
    assert CliRunner().invoke(main, ["check-file", str(cert_dir / "expiring.pem")]).exit_code == 1
    r = CliRunner().invoke(main, ["check-file", str(cert_dir / "expired.pem"), "--json"])
    assert r.exit_code == 1 and json.loads(r.output)[0]["status"] == "EXPIRED"


def test_check_file_corrupt_exit_2(cert_dir):
    assert CliRunner().invoke(main, ["check-file", str(cert_dir / "corrupt.pem")]).exit_code == 2


def test_check_pkcs12_with_password(pkcs12_file):
    r = CliRunner().invoke(main, ["check-file", str(pkcs12_file), "--password", "changeit"])
    assert r.exit_code == 0


def test_audit_verify(tmp_path):
    w = AuditLogWriter(str(tmp_path))
    w.write({"event_type": "a"})
    assert CliRunner().invoke(main, ["audit-verify", str(tmp_path)]).exit_code == 0
    text = open(w.log_file).read().replace('"a"', '"b"')
    open(w.log_file, "w").write(text)
    assert CliRunner().invoke(main, ["audit-verify", str(tmp_path)]).exit_code == 1
