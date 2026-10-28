"""웹방화벽/어플라이언스 관리 API 가짜 서버(로그인 쿠키+토큰 → 인증서 업로드 → 적용 → 로그아웃). 실패 주입 지원."""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509


class WafHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        w = self.server.waf
        ok = self.headers.get("Authorization") == f"Bearer {w['token']}" and f"sid={w['sid']}" in (self.headers.get("Cookie") or "")
        if not ok:
            self._send(401, {"code": 401, "msg": "unauthorized"})
        return ok

    def do_GET(self):
        w = self.server.waf
        w["log"].append(("GET", self.path))
        if self.path == "/api/active":
            return self._send(200, {"serial": w["active_serial"]})
        self._send(404, {})

    def do_POST(self):
        w = self.server.waf
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n)
        ctype = self.headers.get("Content-Type", "")
        w["log"].append(("POST", self.path))
        if self.path == "/api/login":
            b = json.loads(raw)
            if (b["user"], b["password"]) != (w["user"], w["password"]):
                return self._send(401, {"code": 401, "msg": "bad credentials"})
            return self._send(200, {"code": 0, "data": {"token": w["token"]}}, {"Set-Cookie": f"sid={w['sid']}; Path=/"})
        if self.path == "/api/logout":
            w["logged_out"] += 1
            return self._send(200, {"code": 0})
        if not self._auth():
            return
        if self.path == "/api/ssl/cert":
            b = json.loads(raw)
            w["bodies"].append(b)
            if w["fail_upload"]:
                return self._send(200, {"code": 5, "msg": "invalid key"})           # HTTP 200 이지만 본문은 실패
            w["certs"][b["name"]] = (b["cert"], b["key"])
            return self._send(200, {"code": 0})
        if self.path == "/api/ssl/upload":
            assert ctype.startswith("multipart/form-data; boundary=")
            w["multipart"].append(raw)
            names = re.findall(rb'name="([^"]+)"', raw)
            cert = re.search(rb"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)", raw, re.S).group(1)
            w["certs"]["mp"] = (cert.decode(), "")
            return self._send(200, {"code": 0, "fields": [x.decode() for x in names]})
        if self.path == "/api/ssl/apply":
            b = json.loads(raw)
            w["applied"].append(b["name"])
            fa = w["fail_apply"]                              # True = 항상 실패, 정수 n = n 번만 실패
            if fa:
                if fa is not True:
                    w["fail_apply"] = fa - 1
                return self._send(500, {"code": 500, "msg": "apply failed"})
            cert_pem = w["certs"][b["name"]][0]
            w["active_serial"] = f"{x509.load_pem_x509_certificates(cert_pem.encode())[0].serial_number:x}"
            return self._send(200, {"code": 0})
        self._send(404, {})


def start_waf(user="wafadmin", password="waf-pass-1"):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), WafHandler)
    srv.waf = {"user": user, "password": password, "token": "tok-abc123", "sid": "sess42", "certs": {}, "bodies": [], "multipart": [], "log": [],
               "applied": [], "active_serial": None, "fail_upload": False, "fail_apply": False, "logged_out": 0}
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
