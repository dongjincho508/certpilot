"""최소 DNS TXT 조회(UDP, 잘림 시 TCP). 외부 의존성 없이 '챌린지 TXT 가 공개 DNS 에 보이는지' 확인하는 용도."""
import os
import random
import socket
import struct
from typing import List, Optional


class DnsError(Exception):
    pass


def system_resolvers() -> List[str]:
    out = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as f:
            for line in f:
                p = line.split()
                if len(p) >= 2 and p[0] == "nameserver" and ":" not in p[1]:
                    out.append(p[1])
    except OSError:
        pass
    return out


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("idna") if not label.isascii() else label.encode()
        if not 0 < len(b) < 64:
            raise DnsError(f"잘못된 도메인 이름: {name!r}")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _read_name(msg: bytes, off: int):
    labels, jumped, end = [], False, off
    for _ in range(128):
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            jumped, off = True, ptr
            continue
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    else:
        raise DnsError("DNS 응답의 이름 압축이 올바르지 않습니다")
    return ".".join(labels), (end if jumped else off)


def build_query(name: str, qid: Optional[int] = None) -> bytes:
    qid = random.randrange(65536) if qid is None else qid
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack(">HH", 16, 1)


def parse_txt_response(msg: bytes) -> List[str]:
    if len(msg) < 12:
        raise DnsError("DNS 응답이 너무 짧습니다")
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", msg[:12])
    rcode = flags & 0xF
    if rcode not in (0, 3):                                  # 3 = NXDOMAIN(레코드 없음)
        raise DnsError(f"DNS 오류 응답(rcode={rcode})")
    off = 12
    for _ in range(qd):
        _, off = _read_name(msg, off)
        off += 4
    out = []
    for _ in range(an):
        _, off = _read_name(msg, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        if rtype == 16:
            data, p, parts = msg[off:off + rdlen], 0, []
            while p < len(data):
                ln = data[p]
                parts.append(data[p + 1:p + 1 + ln].decode("utf-8", "replace"))
                p += 1 + ln
            out.append("".join(parts))
        off += rdlen
    return out


def query_txt(name: str, server: str, port: int = 53, timeout: float = 3.0) -> List[str]:
    q = build_query(name)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(q, (server, port))
            data, _ = s.recvfrom(4096)
        if struct.unpack(">H", data[2:4])[0] & 0x0200:        # TC: 잘림 → TCP 재시도
            with socket.create_connection((server, port), timeout=timeout) as t:
                t.sendall(struct.pack(">H", len(q)) + q)
                n = struct.unpack(">H", t.recv(2))[0]
                data = b""
                while len(data) < n:
                    chunk = t.recv(n - len(data))
                    if not chunk:
                        break
                    data += chunk
        return parse_txt_response(data)
    except OSError as e:
        raise DnsError(f"{server} 조회 실패: {type(e).__name__}") from e


def txt_visible(name: str, value: str, resolvers: List[str]) -> bool:
    """모든 resolver 에서 name 의 TXT 에 value 가 보이면 True(한 곳이라도 안 보이면 False)."""
    if not resolvers:
        raise DnsError("확인할 DNS 서버가 없습니다(acme.dns.check_resolvers 를 지정하세요)")
    for r in resolvers:
        host, _, port = r.partition(":")
        try:
            if value not in query_txt(name, host, int(port or 53)):
                return False
        except DnsError:
            return False
    return True
