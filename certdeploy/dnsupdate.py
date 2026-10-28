"""RFC 2136 동적 DNS 갱신(+ RFC 8945 TSIG). BIND·PowerDNS·Windows DNS·Infoblox(DDNS) 등 표준 지원 서버에서 TXT 를 넣고 뺀다."""
import base64
import hashlib
import hmac
import os
import socket
import struct
import time
from typing import Optional

from .dnsquery import DnsError, _encode_name

TYPE_TXT, TYPE_SOA, TYPE_TSIG = 16, 6, 250
CLASS_IN, CLASS_NONE, CLASS_ANY = 1, 254, 255
ALGOS = {"hmac-sha256": hashlib.sha256, "hmac-sha384": hashlib.sha384, "hmac-sha512": hashlib.sha512}
RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
          16: "BADSIG", 17: "BADKEY", 18: "BADTIME"}


def _txt_rdata(text: str) -> bytes:
    b = text.encode()
    return b"".join(bytes([len(b[i:i + 255])]) + b[i:i + 255] for i in range(0, max(len(b), 1), 255))


def build_update(zone: str, name: str, text: str, add: bool, ttl: int = 60, qid: int = 0) -> bytes:
    """UPDATE 메시지(TSIG 없음): zone 섹션 + (add: IN TXT 추가 | delete: NONE 클래스로 해당 RR 만 삭제)."""
    hdr = struct.pack(">HHHHHH", qid, 5 << 11, 1, 0, 1, 0)          # opcode UPDATE, ZOCOUNT=1, UPCOUNT=1
    zsec = _encode_name(zone) + struct.pack(">HH", TYPE_SOA, CLASS_IN)
    rd = _txt_rdata(text)
    rr = _encode_name(name) + struct.pack(">HHIH", TYPE_TXT, CLASS_IN if add else CLASS_NONE, ttl if add else 0, len(rd)) + rd
    return hdr + zsec + rr


def _tsig_vars(key_name: str, algo: str, signed: int, fudge: int, error: int = 0) -> bytes:
    return (_encode_name(key_name.lower()) + struct.pack(">HI", CLASS_ANY, 0) + _encode_name(algo.lower())
            + struct.pack(">HIHHH", signed >> 32, signed & 0xFFFFFFFF, fudge, error, 0))


def tsig_sign(msg: bytes, key_name: str, secret_b64: str, algo: str = "hmac-sha256", now: Optional[int] = None, fudge: int = 300) -> bytes:
    if algo not in ALGOS:
        raise DnsError(f"지원하지 않는 TSIG 알고리즘: {algo}")
    signed = int(time.time()) if now is None else now
    secret = base64.b64decode(secret_b64)
    mac = hmac.new(secret, msg + _tsig_vars(key_name, algo, signed, fudge), ALGOS[algo]).digest()
    rdata = (_encode_name(algo.lower()) + struct.pack(">HIH", signed >> 32, signed & 0xFFFFFFFF, fudge) + struct.pack(">H", len(mac)) + mac
             + struct.pack(">HHH", struct.unpack(">H", msg[:2])[0], 0, 0))
    rr = _encode_name(key_name.lower()) + struct.pack(">HHIH", TYPE_TSIG, CLASS_ANY, 0, len(rdata)) + rdata
    hdr = bytearray(msg)
    ar = struct.unpack(">H", hdr[10:12])[0] + 1
    hdr[10:12] = struct.pack(">H", ar)
    return bytes(hdr) + rr


def send_update(server: str, msg: bytes, timeout: float = 10.0) -> int:
    host, _, port = server.partition(":")
    try:
        with socket.create_connection((host, int(port or 53)), timeout=timeout) as s:
            s.sendall(struct.pack(">H", len(msg)) + msg)
            n = struct.unpack(">H", _recv(s, 2))[0]
            resp = _recv(s, n)
    except OSError as e:
        raise DnsError(f"{server} 갱신 요청 실패: {type(e).__name__}: {e}") from e
    return struct.unpack(">H", resp[2:4])[0] & 0xF


def _recv(s, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise DnsError("DNS 서버가 응답 도중 연결을 닫았습니다")
        data += chunk
    return data


def update_txt(server: str, zone: str, name: str, text: str, add: bool, key_name: Optional[str], secret_b64: Optional[str],
               algo: str = "hmac-sha256", ttl: int = 60, qid: Optional[int] = None) -> None:
    msg = build_update(zone, name, text, add, ttl, qid if qid is not None else int.from_bytes(os.urandom(2), "big"))
    if key_name and secret_b64:
        msg = tsig_sign(msg, key_name, secret_b64, algo)
    rc = send_update(server, msg)
    if rc != 0:
        raise DnsError(f"DNS UPDATE 거부됨: {RCODES.get(rc, rc)} (zone={zone}, name={name})")
