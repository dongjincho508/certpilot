"""환경변수로 받은 SSH 개인키를 ssh-add 가 읽을 수 있는 형태로 정규화·검증한다.

Render 같은 환경변수 UI 는 여러 줄 값의 줄바꿈이 깨지거나(공백으로 합쳐짐), `\\n` 문자 그대로 들어오는 일이 많다.
키 내용은 절대 출력하지 않고, 실패 사유(형식/암호/지원 안 함)만 stderr 로 알린다.
사용: `python -m certpilot_core.sshkey` — 정규화한 키를 stdout, 실패 시 사유를 stderr 로 내고 종료 코드 1.
"""
import base64
import os
import re
import sys
import textwrap

from cryptography.hazmat.primitives import serialization

_BLOCK = re.compile(r"(-----BEGIN [A-Z0-9 ]+-----)(.*?)(-----END [A-Z0-9 ]+-----)", re.DOTALL)


class KeyError_(Exception):
    pass


def normalize_private_key(raw: str) -> str:
    """CRLF·리터럴 \\n·줄바꿈이 공백으로 합쳐진 키를 표준 PEM/OpenSSH 형식으로 복원한다."""
    text = raw.strip().strip('"').strip("'").replace("\r", "")
    text = text.replace("\\n", "\n")
    m = _BLOCK.search(text)
    if not m:
        raise KeyError_("개인키 형식이 아닙니다 (-----BEGIN ... PRIVATE KEY----- 헤더가 없음)")
    header, body, footer = m.group(1), m.group(2), m.group(3)
    if "PRIVATE KEY" not in header:
        raise KeyError_("개인키가 아닌 PEM 블록입니다 (공개키/인증서를 넣지 않았는지 확인)")
    # PEM 헤더 줄(Proc-Type/DEK-Info)은 암호화된 키의 표지 — 본문과 분리해 보존
    lines = [l.strip() for l in re.split(r"[\n]", body) if l.strip()]
    if len(lines) <= 1:  # 한 줄로 합쳐졌다면 공백 기준으로 다시 나눈다
        tokens = body.split()
        headers = [t for t in tokens if re.match(r"^(Proc-Type:|DEK-Info:)", t)]
        if headers:
            raise KeyError_("암호(passphrase)로 보호된 구형 PEM 키입니다. 암호 없는 키를 사용하세요")
        lines = tokens
    b64 = "".join(l for l in lines if ":" not in l)
    width = 70 if "OPENSSH" in header else 64
    return "\n".join([header, *textwrap.wrap(b64, width), footer]) + "\n"


def load_and_validate(key_text: str) -> None:
    """암호 없이 로드 가능한지 확인한다. 실패 시 KeyError_ (사유에 키 내용 없음)."""
    data = key_text.encode()
    try:
        if "OPENSSH PRIVATE KEY" in key_text:
            serialization.load_ssh_private_key(data, password=None)
        else:
            serialization.load_pem_private_key(data, password=None)
    except TypeError:
        raise KeyError_("암호(passphrase)로 보호된 키입니다. 암호 없는 키(ssh-keygen -t ed25519 -N \"\")를 사용하세요")
    except ValueError as e:
        msg = str(e).lower()
        if "bcrypt" in msg or "encrypted" in msg or "passphrase" in msg or "password" in msg:
            raise KeyError_("암호(passphrase)로 보호된 키입니다. 암호 없는 키를 사용하세요")
        raise KeyError_("키 내용을 해석할 수 없습니다 (줄바꿈 손상·일부 누락·잘못된 붙여넣기)")
    except Exception:
        raise KeyError_("지원하지 않는 키 형식입니다 (ed25519/RSA/ECDSA 권장)")


def key_from_env(environ=os.environ) -> str:
    b64 = environ.get("CERTPILOT_SSH_PRIVATE_KEY_B64", "").strip()
    raw = environ.get("CERTPILOT_SSH_PRIVATE_KEY", "")
    if b64:
        try:
            raw = base64.b64decode(b64, validate=False).decode()
        except Exception:
            raise KeyError_("CERTPILOT_SSH_PRIVATE_KEY_B64 가 올바른 base64 가 아닙니다")
    if not raw.strip():
        raise KeyError_("CERTPILOT_SSH_PRIVATE_KEY(또는 _B64)가 비어 있습니다")
    key = normalize_private_key(raw)
    load_and_validate(key)
    return key


def main() -> int:
    try:
        sys.stdout.write(key_from_env())
        return 0
    except KeyError_ as e:
        print(f"SSH 키 오류: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
