import pytest

from certpilot_core.remote import CommandPolicy, PolicyViolation, path_allowed

WL = ["/etc/ssl", "/opt/app/certs"]


@pytest.mark.parametrize("argv", [
    ["cat", "/etc/ssl/a.pem"],
    ["head", "-c", "1000", "/etc/ssl/a.pem"],
    ["tail", "-n", "5", "/opt/app/certs/x.crt"],
    ["ls", "-1", "-p", "/etc/ssl"],
    ["ls", "-l", "/etc/ssl/a.pem"],
    ["sha256sum", "/etc/ssl/a.pem"],
    ["grep", "-n", "ssl_certificate", "/etc/ssl/nginx.conf"],
    ["find", "/etc/ssl", "-maxdepth", "2", "-type", "f", "-name", "x.pem"],
    ["openssl", "x509", "-noout", "-dates", "/etc/ssl/a.pem"],
])
def test_allowed(argv):
    CommandPolicy(WL).validate(argv)


@pytest.mark.parametrize("argv", [
    ["sudo", "cat", "/etc/ssl/a.pem"],
    ["rm", "/etc/ssl/a.pem"],
    ["chmod", "777", "/etc/ssl/a.pem"],
    ["curl", "http://evil"],
    ["scp", "/etc/ssl/a.pem", "x:"],
    ["ssh", "host"],
    ["cat", "/etc/shadow"],                      # 화이트리스트 밖
    ["cat", "/etc/ssl/../shadow"],               # 상위 이탈
    ["cat", "/etc/ssl/a.pem; rm -rf /"],         # 셸 메타문자
    ["cat", "/etc/ssl/a.pem|sh"],
    ["cat", "$(id)"],
    ["find", "/etc/ssl", "-exec", "rm", "{}"],
    ["find", "/etc/ssl", "-delete"],
    ["grep", "-r", "x", "/etc/ssl"],
    ["openssl", "genrsa"],
    ["openssl", "x509", "-in", "/etc/ssl/a.pem", "-out", "/tmp/x"],
    ["ls", "-R", "/etc/ssl"],
    [],
])
def test_denied(argv):
    with pytest.raises(PolicyViolation):
        CommandPolicy(WL).validate(argv)


def test_path_allowed_prefix_boundary():
    assert not path_allowed("/etc/ssl-evil/a", ["/etc/ssl"])
    assert path_allowed("/etc/ssl", ["/etc/ssl"])
    assert not path_allowed("relative/path", ["/etc/ssl"])
