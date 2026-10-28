import base64
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from certpilot_core.sshkey import KeyError_, key_from_env, normalize_private_key


def openssh_key(passphrase=None):
    k = ed25519.Ed25519PrivateKey.generate()
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, enc).decode()


def pem_rsa_key():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                           serialization.NoEncryption()).decode()


def squash(t):
    return "".join(t.split())


def test_valid_key_passes_unchanged():
    k = openssh_key()
    assert squash(key_from_env({"CERTPILOT_SSH_PRIVATE_KEY": k})) == squash(k)


@pytest.mark.parametrize("mangle", [
    lambda k: k.replace("\n", "\r\n"),                    # CRLF
    lambda k: k.replace("\n", "\\n"),                     # 리터럴 \n
    lambda k: k.replace("\n", " "),                       # 줄바꿈이 공백으로 합쳐짐
    lambda k: '"' + k.replace("\n", "\\n") + '"',         # 따옴표로 감싼 한 줄
    lambda k: "\n\n  " + k + "  \n",                      # 앞뒤 공백
])
def test_mangled_openssh_key_is_repaired(mangle):
    k = openssh_key()
    fixed = key_from_env({"CERTPILOT_SSH_PRIVATE_KEY": mangle(k)})
    assert fixed.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\n") and fixed.endswith("-----END OPENSSH PRIVATE KEY-----\n")
    # 복원된 키가 원본과 같은 키여야 한다
    a = serialization.load_ssh_private_key(fixed.encode(), None).public_key().public_bytes_raw()
    b = serialization.load_ssh_private_key(k.encode(), None).public_key().public_bytes_raw()
    assert a == b


def test_mangled_rsa_pem_is_repaired():
    k = pem_rsa_key()
    fixed = key_from_env({"CERTPILOT_SSH_PRIVATE_KEY": k.replace("\n", " ")})
    serialization.load_pem_private_key(fixed.encode(), None)


def test_base64_variant():
    k = openssh_key()
    b64 = base64.b64encode(k.encode()).decode()
    assert squash(key_from_env({"CERTPILOT_SSH_PRIVATE_KEY_B64": b64})) == squash(k)


@pytest.mark.parametrize("env,msg", [
    ({"CERTPILOT_SSH_PRIVATE_KEY": ""}, "비어"),
    ({"CERTPILOT_SSH_PRIVATE_KEY": "ssh-ed25519 AAAA... me@host"}, "형식이 아닙니다"),
    ({"CERTPILOT_SSH_PRIVATE_KEY": "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"}, "개인키가 아닌"),
    ({"CERTPILOT_SSH_PRIVATE_KEY": openssh_key(b"secret")}, "passphrase"),
    ({"CERTPILOT_SSH_PRIVATE_KEY": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"}, "해석할 수 없습니다"),
])
def test_clear_errors(env, msg):
    with pytest.raises(KeyError_, match=msg):
        key_from_env(env)


def test_error_never_leaks_key_material():
    k = openssh_key(b"secret")
    body = k.splitlines()[1]
    with pytest.raises(KeyError_) as e:
        key_from_env({"CERTPILOT_SSH_PRIVATE_KEY": k})
    assert body not in str(e.value)


def test_cli_exit_codes(tmp_path):
    k = openssh_key()
    ok = subprocess.run([sys.executable, "-m", "certpilot_core.sshkey"], capture_output=True, text=True,
                        env={"CERTPILOT_SSH_PRIVATE_KEY": k.replace("\n", " "), "PATH": ""})
    assert ok.returncode == 0 and squash(ok.stdout) == squash(k)
    bad = subprocess.run([sys.executable, "-m", "certpilot_core.sshkey"], capture_output=True, text=True,
                         env={"CERTPILOT_SSH_PRIVATE_KEY": "nope", "PATH": ""})
    assert bad.returncode == 1 and "SSH 키 오류" in bad.stderr and bad.stdout == ""
