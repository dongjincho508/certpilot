"""ACME(RFC 8555)·Infoblox WAPI·DNS 의 로컬 가짜 서버. JWS 서명·nonce·키 인증을 실제로 검증한다.
세 서버가 같은 `zone`(이름 → TXT 값 목록)을 공유해, TXT 를 실제로 등록해야만 CA 검증이 통과한다."""
import base64
import hashlib
import json
import os
import re
import socket
import struct
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from pki_helpers import sign_csr


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Zone:
    def __init__(self):
        self.txt = {}
        self.lock = threading.Lock()

    def add(self, name, value):
        with self.lock:
            self.txt.setdefault(name.rstrip(".").lower(), []).append(value)

    def remove(self, name, value):
        with self.lock:
            vals = self.txt.get(name.rstrip(".").lower(), [])
            if value in vals:
                vals.remove(value)

    def get(self, name):
        with self.lock:
            return list(self.txt.get(name.rstrip(".").lower(), []))


class _Server(ThreadingHTTPServer):
    daemon_threads = True


def _serve(handler_cls, **attrs):
    srv = _Server(("127.0.0.1", 0), handler_cls)
    for k, v in attrs.items():
        setattr(srv, k, v)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ------------------------------------------------------------------ ACME
class AcmeState:
    def __init__(self, zone, ca, days=90):
        self.zone, self.ca, self.days = zone, ca, days
        self.nonces, self.accounts, self.orders, self.authzs, self.chals, self.certs = set(), {}, {}, {}, {}, {}
        self.bad_nonce_once = False
        self.requests = []
        self.lock = threading.Lock()
        self.n = 0

    def next(self):
        with self.lock:
            self.n += 1
            return self.n


class AcmeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    @property
    def st(self):
        return self.server.state

    @property
    def base(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def _send(self, code, body=b"", headers=None, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        nonce = b64u(os.urandom(12))
        self.st.nonces.add(nonce)
        self.send_response(code)
        self.send_header("Replay-Nonce", nonce)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _problem(self, code, typ, detail):
        self._send(code, {"type": "urn:ietf:params:acme:error:" + typ, "detail": detail}, ctype="application/problem+json")

    def do_HEAD(self):
        self._send(200)

    def do_GET(self):
        if self.path.split("?")[0] == "/directory":
            self._send(200, {"newNonce": self.base + "/new-nonce", "newAccount": self.base + "/new-acct", "newOrder": self.base + "/new-order"})
        else:
            self._send(404, {"type": "x", "detail": "nf"})

    def _verify(self):
        n = int(self.headers["Content-Length"])
        jws = json.loads(self.rfile.read(n))
        prot = json.loads(b64u_dec(jws["protected"]))
        if self.st.bad_nonce_once:
            self.st.bad_nonce_once = False
            return None, self._problem(400, "badNonce", "injected")
        if prot["nonce"] not in self.st.nonces:
            return None, self._problem(400, "badNonce", "unknown nonce")
        self.st.nonces.discard(prot["nonce"])
        if prot["url"] != self.base + self.path or prot["alg"] != "ES256":
            return None, self._problem(400, "malformed", "url/alg mismatch")
        jwk = prot.get("jwk") or self.st.accounts.get(prot.get("kid"))
        if not jwk:
            return None, self._problem(401, "accountDoesNotExist", "no account")
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(b64u_dec(jwk["x"]), "big"), int.from_bytes(b64u_dec(jwk["y"]), "big"), ec.SECP256R1()).public_key()
        sig = b64u_dec(jws["signature"])
        try:
            pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                       f"{jws['protected']}.{jws['payload']}".encode(), ec.ECDSA(hashes.SHA256()))
        except Exception:   # noqa: BLE001
            return None, self._problem(400, "malformed", "bad signature")
        payload = json.loads(b64u_dec(jws["payload"])) if jws["payload"] else None
        return (prot, jwk, payload), None

    def do_POST(self):
        res, err = self._verify()
        if res is None:
            return
        prot, jwk, payload = res
        st, path = self.st, self.path
        self.st.requests.append((path, payload))
        if path == "/new-acct":
            assert payload.get("termsOfServiceAgreed") is True
            kid = f"{self.base}/acct/{st.next()}"
            st.accounts[kid] = jwk
            return self._send(201, {"status": "valid", "contact": payload.get("contact", [])}, {"Location": kid})
        if path == "/new-order":
            oid = st.next()
            authz_urls = []
            for ident in payload["identifiers"]:
                value = ident["value"]
                wildcard = value.startswith("*.")
                aid, cid = st.next(), st.next()
                token = b64u(os.urandom(16))
                st.authzs[aid] = {"status": "pending", "identifier": {"type": "dns", "value": value[2:] if wildcard else value},
                                  "wildcard": wildcard, "chal": cid, "jwk": jwk, "order": oid}
                st.chals[cid] = {"token": token, "status": "pending", "authz": aid}
                authz_urls.append(f"{self.base}/authz/{aid}")
            st.orders[oid] = {"status": "pending", "identifiers": payload["identifiers"], "authz": authz_urls, "jwk": jwk}
            return self._send(201, self._order(oid), {"Location": f"{self.base}/order/{oid}"})
        m = re.fullmatch(r"/(authz|order|chal|finalize|cert)/(\d+)", path)
        if not m:
            return self._send(404, {"type": "x", "detail": "nf"})
        kind, i = m.group(1), int(m.group(2))
        if kind == "authz":
            a = st.authzs[i]
            c = st.chals[a["chal"]]
            return self._send(200, {"status": a["status"], "identifier": a["identifier"], "wildcard": a["wildcard"],
                                    "challenges": [{"type": "dns-01", "url": f"{self.base}/chal/{a['chal']}", "token": c["token"], "status": c["status"],
                                                    **({"error": c["error"]} if c.get("error") else {})}]})
        if kind == "chal":
            c = st.chals[i]
            a = st.authzs[c["authz"]]
            thumb = b64u(hashlib.sha256(json.dumps({k: a["jwk"][k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True).encode()).digest())
            expect = b64u(hashlib.sha256(f"{c['token']}.{thumb}".encode()).digest())
            name = "_acme-challenge." + a["identifier"]["value"]
            if expect in st.zone.get(name):
                c["status"], a["status"] = "valid", "valid"
            else:
                c["status"], a["status"] = "invalid", "invalid"
                c["error"] = {"type": "urn:ietf:params:acme:error:unauthorized", "detail": f"No TXT record found at {name}"}
            return self._send(200, {"type": "dns-01", "url": self.base + path, "status": c["status"], "token": c["token"]})
        if kind == "order":
            return self._send(200, self._order(i))
        if kind == "finalize":
            o = st.orders[i]
            if o["status"] != "ready":
                return self._problem(403, "orderNotReady", f"order is {o['status']}")
            csr_pem = x509.load_der_x509_csr(b64u_dec(payload["csr"])).public_bytes(serialization.Encoding.PEM)
            leaf = sign_csr(csr_pem, st.ca, days_to=st.days)
            st.certs[i] = leaf.public_bytes(serialization.Encoding.PEM) + st.ca["inter"].public_bytes(serialization.Encoding.PEM)
            o["status"] = "valid"
            return self._send(200, self._order(i))
        if kind == "cert":
            return self._send(200, st.certs[i], ctype="application/pem-certificate-chain")

    def _order(self, oid):
        st = self.st
        o = st.orders[oid]
        if o["status"] == "pending":
            states = [st.authzs[int(u.rsplit("/", 1)[1])]["status"] for u in o["authz"]]
            if "invalid" in states:
                o["status"] = "invalid"
            elif all(s == "valid" for s in states):
                o["status"] = "ready"
        out = {"status": o["status"], "identifiers": o["identifiers"], "authorizations": o["authz"], "finalize": f"{self.base}/finalize/{oid}"}
        if o["status"] == "valid":
            out["certificate"] = f"{self.base}/cert/{oid}"
        return out


def start_acme(zone, ca, days=90):
    st = AcmeState(zone, ca, days)
    srv = _serve(AcmeHandler, state=st)
    return srv, st, f"http://127.0.0.1:{srv.server_port}/directory"


# ------------------------------------------------------------------ Infoblox WAPI
class WapiHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _auth(self):
        if self.headers.get("Authorization") != "Basic " + base64.b64encode(f"{self.server.user}:{self.server.password}".encode()).decode():
            self.send_response(401)
            self.end_headers()
            return False
        return True

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._auth():
            return
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        self.server.log.append(("GET", u.path, q))
        if u.path.endswith("/record:txt"):
            self._json(200, [{"_ref": ref, "name": n, "text": t} for ref, (n, t) in self.server.records.items()
                             if n == q.get("name") and t == q.get("text")])
        else:
            self._json(404, {"Error": "nf"})

    def do_POST(self):
        if not self._auth():
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.log.append(("POST", self.path, body))
        if self.server.fail_post:
            return self._json(400, {"Error": "AdmConDataError", "text": "denied"})
        ref = f"record:txt/ZG5z{len(self.server.records) + 1}:{body['name']}/{body.get('view', 'default')}"
        self.server.records[ref] = (body["name"], body["text"])
        self.server.zone.add(body["name"], body["text"])
        self._json(201, ref)

    def do_DELETE(self):
        if not self._auth():
            return
        ref = urllib.parse.unquote(self.path.split("/wapi/v2.12/", 1)[1])
        self.server.log.append(("DELETE", ref, None))
        if ref in self.server.records:
            n, t = self.server.records.pop(ref)
            self.server.zone.remove(n, t)
            return self._json(200, ref)
        self._json(404, {"Error": "nf"})


def start_wapi(zone, user="acme-svc", password="s3cret-pw"):
    srv = _serve(WapiHandler, zone=zone, user=user, password=password, records={}, log=[], fail_post=False)
    return srv


# ------------------------------------------------------------------ DNS (UDP)
def _dns_response(query, zone):
    qid, = struct.unpack(">H", query[:2])
    off, labels = 12, []
    while query[off]:
        labels.append(query[off + 1:off + 1 + query[off]].decode())
        off += 1 + query[off]
    qname = ".".join(labels)
    question = query[12:off + 5]
    vals = zone.get(qname)
    answers = b""
    for v in vals:
        data = v.encode()
        chunks = b"".join(bytes([len(data[i:i + 255])]) + data[i:i + 255] for i in range(0, len(data), 255))
        answers += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(chunks)) + chunks
    rcode = 0 if vals else 3
    return struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, len(vals), 0, 0) + question + answers


class DnsServer:
    def __init__(self, zone):
        self.zone = zone
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self._stop = False
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(512)
            except OSError:
                continue
            try:
                self.sock.sendto(_dns_response(data, self.zone), addr)
            except Exception:   # noqa: BLE001
                pass

    def close(self):
        self._stop = True
        self.t.join(1)
        self.sock.close()

    @property
    def resolver(self):
        return f"127.0.0.1:{self.port}"


# ------------------------------------------------------------------ Cloudflare / PowerDNS / Webhook (HTTP)
class _JsonHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n)) if n else None

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class CloudflareHandler(_JsonHandler):
    def _ok(self):
        if self.headers.get("Authorization") != f"Bearer {self.server.token}":
            self._send(403, {"success": False, "errors": [{"message": "bad token"}]})
            return False
        return True

    def do_GET(self):
        if not self._ok():
            return
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        self.server.log.append(("GET", u.path))
        if u.path == "/client/v4/zones":
            res = [{"id": "zone-" + n, "name": n} for n in self.server.zones if n == q.get("name")]
            return self._send(200, {"success": True, "result": res})
        m = re.fullmatch(r"/client/v4/zones/zone-([^/]+)/dns_records", u.path)
        if m:
            return self._send(200, {"success": True, "result": [{"id": rid, "name": n, "content": c} for rid, (n, c) in self.server.records.items()
                                                                if n == q.get("name") and c == q.get("content")]})
        self._send(404, {"success": False})

    def do_POST(self):
        if not self._ok():
            return
        body = self._body()
        self.server.log.append(("POST", self.path, body))
        rid = f"rec{len(self.server.records) + 1}"
        self.server.records[rid] = (body["name"], body["content"])
        self.server.zone.add(body["name"], body["content"])
        self._send(200, {"success": True, "result": {"id": rid}})

    def do_DELETE(self):
        if not self._ok():
            return
        rid = self.path.rsplit("/", 1)[1]
        n, c = self.server.records.pop(rid)
        self.server.zone.remove(n, c)
        self._send(200, {"success": True, "result": {"id": rid}})


def start_cloudflare(zone, token="cf-token-123", zones=("hnu.kr",)):
    return _serve(CloudflareHandler, zone=zone, token=token, zones=list(zones), records={}, log=[])


class PowerDnsHandler(_JsonHandler):
    def _ok(self):
        if self.headers.get("X-API-Key") != self.server.key:
            self._send(401, {"error": "Unauthorized"})
            return False
        return True

    def do_GET(self):
        if not self._ok():
            return
        rrsets = [{"name": n, "type": "TXT", "records": [{"content": c, "disabled": False} for c in v]} for n, v in self.server.rr.items() if v]
        self._send(200, {"name": self.server.zonename, "rrsets": rrsets})

    def do_PATCH(self):
        if not self._ok():
            return
        for rr in self._body()["rrsets"]:
            self.server.log.append((rr["changetype"], rr["name"], [r["content"] for r in rr.get("records", [])]))
            old = list(self.server.rr.get(rr["name"], []))
            new = [r["content"] for r in rr.get("records", [])] if rr["changetype"] == "REPLACE" else []
            self.server.rr[rr["name"]] = new
            plain = rr["name"].rstrip(".")
            for c in old:
                if c not in new:
                    self.server.zone.remove(plain, c.strip('"'))
            for c in new:
                if c not in old:
                    self.server.zone.add(plain, c.strip('"'))
        self.send_response(204)
        self.end_headers()


def start_powerdns(zone, key="pdns-key", zonename="hnu.kr."):
    return _serve(PowerDnsHandler, zone=zone, key=key, zonename=zonename, rr={}, log=[])


class WebhookHandler(_JsonHandler):
    def do_POST(self):
        if self.headers.get("Authorization") != self.server.auth:
            return self._send(401, {"error": "no"})
        b = self._body()
        self.server.log.append(b)
        if self.server.fail:
            return self._send(500, {"error": "boom"})
        (self.server.zone.add if b["action"] == "present" else self.server.zone.remove)(b["fqdn"], b["value"])
        self._send(200, {"ok": True})


def start_webhook(zone, auth="Bearer hook-secret"):
    return _serve(WebhookHandler, zone=zone, auth=auth, log=[], fail=False)


# ------------------------------------------------------------------ RFC 2136 (TCP, TSIG 검증)
class Rfc2136Server:
    def __init__(self, zone, zonename="hnu.kr", key_name="acme-key.", secret_b64=None):
        import hmac as _hmac
        self._hmac = _hmac
        self.zone, self.zonename, self.key_name, self.secret = zone, zonename, key_name, secret_b64
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.log = []
        self._stop = False
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    @property
    def server(self):
        return f"127.0.0.1:{self.port}"

    def close(self):
        self._stop = True
        self.t.join(1)
        self.sock.close()

    def _run(self):
        while not self._stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                continue
            with c:
                try:
                    n = struct.unpack(">H", c.recv(2))[0]
                    msg = b""
                    while len(msg) < n:
                        msg += c.recv(n - len(msg))
                    rc = self._handle(msg)
                    resp = struct.pack(">HHHHHH", struct.unpack(">H", msg[:2])[0], 0x8000 | (5 << 11) | (9 if rc >= 16 else rc), 0, 0, 0, 0)   # TSIG 오류(BADSIG 등)는 헤더에는 NOTAUTH
                    c.sendall(struct.pack(">H", len(resp)) + resp)
                except Exception:   # noqa: BLE001
                    pass

    @staticmethod
    def _name(msg, off):
        labels = []
        while msg[off]:
            labels.append(msg[off + 1:off + 1 + msg[off]].decode())
            off += 1 + msg[off]
        return ".".join(labels), off + 1

    def _handle(self, msg):
        qid, flags, zo, pr, up, ar = struct.unpack(">HHHHHH", msg[:12])
        if (flags >> 11) & 0xF != 5:
            return 4
        off = 12
        zname, off = self._name(msg, off)
        off += 4
        if zname.lower() != self.zonename:
            return 10                                           # NOTZONE
        recs = []
        for _ in range(up):
            n, off = self._name(msg, off)
            t, cl, ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
            off += 10
            rd = msg[off:off + rdlen]
            off += rdlen
            recs.append((n, t, cl, rd))
        if self.secret:
            if ar != 1:
                return 9                                        # NOTAUTH: 서명 없음
            tsig_start = off
            kn, off = self._name(msg, off)
            t, cl, ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
            off += 10
            rd = msg[off:off + rdlen]
            algo, p = self._name(rd, 0)
            th, tl, fudge, maclen = struct.unpack(">HIHH", rd[p:p + 10])
            mac = rd[p + 10:p + 10 + maclen]
            if t != 250 or kn.lower() != self.key_name.rstrip(".").lower():
                return 17
            unsigned = bytearray(msg[:tsig_start])
            unsigned[10:12] = struct.pack(">H", ar - 1)
            from certdeploy.dnsquery import _encode_name
            variables = (_encode_name(kn.lower()) + struct.pack(">HI", 255, 0) + _encode_name(algo.lower())
                         + struct.pack(">HIHHH", th, tl, fudge, 0, 0))
            expect = self._hmac.new(base64.b64decode(self.secret), bytes(unsigned) + variables, hashlib.sha256).digest()
            if not self._hmac.compare_digest(expect, mac):
                return 16                                       # BADSIG
        for n, t, cl, rd in recs:
            if t != 16:
                continue
            text, p = b"", 0
            while p < len(rd):
                text += rd[p + 1:p + 1 + rd[p]]
                p += 1 + rd[p]
            self.log.append(("add" if cl == 1 else "delete", n, text.decode()))
            (self.zone.add if cl == 1 else self.zone.remove)(n, text.decode())
        return 0
