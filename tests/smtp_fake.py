"""시험용 최소 SMTP 서버(평문, 인증 없음): 받은 메일을 모은다. 지정하면 AUTH 를 요구한다."""
import socketserver
import threading


class _H(socketserver.StreamRequestHandler):
    def _w(self, line):
        self.wfile.write((line + "\r\n").encode())

    def handle(self):
        srv = self.server
        self._w("220 fake ESMTP")
        mail = {"from": None, "to": [], "data": ""}
        while True:
            line = self.rfile.readline().decode(errors="replace").rstrip("\r\n")
            if not line:
                return
            cmd = line.split(" ", 1)[0].upper()
            if cmd in ("EHLO", "HELO"):
                self.wfile.write(b"250-fake\r\n" + (b"250-AUTH PLAIN LOGIN\r\n" if srv.require_auth else b"") + b"250 OK\r\n")
            elif cmd == "AUTH":
                import base64
                parts = line.split()
                cred = base64.b64decode(parts[2]).split(b"\0") if len(parts) > 2 else []
                if len(cred) == 3 and (cred[1].decode(), cred[2].decode()) == srv.require_auth:
                    srv.logins.append(cred[1].decode())
                    self._w("235 ok")
                else:
                    self._w("535 5.7.8 authentication failed")
            elif cmd == "MAIL":
                if srv.require_auth and not srv.logins:
                    self._w("530 authentication required")
                else:
                    mail["from"] = line.split(":", 1)[1].strip()
                    self._w("250 ok")
            elif cmd == "RCPT":
                if srv.reject_rcpt:
                    self._w("550 relay denied")
                else:
                    mail["to"].append(line.split(":", 1)[1].strip())
                    self._w("250 ok")
            elif cmd == "DATA":
                self._w("354 go")
                body = []
                while True:
                    ln = self.rfile.readline().decode(errors="replace")
                    if ln in (".\r\n", ".\n", ""):
                        break
                    body.append(ln)
                mail["data"] = "".join(body)
                srv.mails.append(dict(mail))
                self._w("250 queued")
            elif cmd == "QUIT":
                self._w("221 bye")
                return
            else:
                self._w("250 ok")


class SmtpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, require_auth=None, reject_rcpt=False):
        super().__init__(("127.0.0.1", 0), _H)
        self.require_auth, self.reject_rcpt = require_auth, reject_rcpt
        self.mails, self.logins = [], []
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def port(self):
        return self.server_address[1]
