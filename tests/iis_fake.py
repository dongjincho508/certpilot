"""IIS 시험용 가짜 Windows: SSH 로 전달된 PowerShell 스크립트를 해석하지 않고, 스크립트 속 바인딩 목록을 읽어
메모리 속 IIS 상태(바인딩→지문)를 갱신하고 실제 스크립트와 같은 형식의 출력(BIND|…/REVERT|…/OK/ERR|…)을 돌려준다.
전달된 PFX 가 정말 열리는지(비밀번호·지문)도 검사한다."""
import base64
import re

from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes

from certdeploy.transport import Result, Transport

ROW = re.compile(r"@\('([^']*)','([^']*)','([^']*)','([^']*)','([^']*)'\)")


class FakeWindows(Transport):
    def __init__(self, bindings=None, store=None):
        self.bindings = dict(bindings or {})          # "사이트|포트|호스트헤더" → 지문
        self.store = set(store or [])                 # 저장소에 있는 지문
        self.calls, self.scripts = [], []
        self.fail_on = None                           # "import" | "bind" | "rollback"
        self.closed = False
        self.fail_next_bind_after = None              # 이 개수의 바인딩을 바꾼 뒤 실패

    def run(self, cmd, stdin=None, timeout=60):
        self.calls.append(cmd)
        script = (stdin or b"").decode("utf-8")
        self.scripts.append(script)
        rows = ROW.findall(script)
        out = []
        try:
            if "AddSslCertificate($old" in script:                               # 롤백
                if self.fail_on == "rollback":
                    raise RuntimeError("롤백 시험 실패")
                for site, port, hh, ip, old in rows:
                    if old not in self.store:
                        raise RuntimeError("이전 인증서가 저장소에 없습니다: " + old)
                    self._need(site, port, hh)
                    self.bindings[f"{site}|{port}|{hh}"] = old
                    out.append(f"REVERT|{site}|{port}|{hh}|{old}")
            elif "FromBase64String" in script:                                  # 배포
                thumb = re.search(r"\$cert\.Thumbprint -ne '([0-9A-F]+)'", script).group(1)
                pfx = base64.b64decode(re.search(r"FromBase64String\('([^']*)'\)", script).group(1))
                pw = re.search(r"X509Certificate2\(\$bytes, '([^']*)'", script).group(1)
                key, cert, _ = pkcs12.load_key_and_certificates(pfx, pw.encode())
                assert cert.fingerprint(hashes.SHA1()).hex().upper() == thumb          # nosec - 시험
                if self.fail_on == "import":
                    raise RuntimeError("Import 실패(시험)")
                self.store.add(thumb)
                changed = 0
                for site, port, hh, ip, _ in rows:
                    if self.fail_next_bind_after is not None and changed >= self.fail_next_bind_after:
                        raise RuntimeError("바인딩 적용 실패(시험)")
                    self._need(site, port, hh)
                    prev = self.bindings[f"{site}|{port}|{hh}"]
                    self.bindings[f"{site}|{port}|{hh}"] = thumb
                    out.append(f"BIND|{site}|{port}|{hh}|{prev}|{thumb}")
                    changed += 1
            else:                                                               # 점검(읽기 전용)
                for site, port, hh, ip, _ in rows:
                    self._need(site, port, hh)
                    out.append(f"BIND|{site}|{port}|{hh}|{self.bindings[f'{site}|{port}|{hh}']}")
        except RuntimeError as e:
            return Result(1, "\n".join(out + [f"ERR|{e}"]), "")
        return Result(0, "\n".join(out + ["OK"]), "")

    def _need(self, site, port, hh):
        if f"{site}|{port}|{hh}" not in self.bindings:
            raise RuntimeError(f"바인딩을 찾을 수 없거나 여러 개입니다: {site} {port} {hh}")

    def close(self):
        self.closed = True
