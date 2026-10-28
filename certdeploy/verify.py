"""배포 후 확인: 서비스 포트에 TLS 로 접속해 실제로 서빙되는 인증서의 일련번호를 읽는다."""
import socket
import ssl
from typing import Optional

from cryptography import x509


class VerifyError(Exception):
    pass


def tls_serial(host: str, port: int = 443, sni: Optional[str] = None, timeout: float = 10.0) -> int:
    """서버가 제시하는 리프 인증서의 일련번호(정수). 검증이 아니라 '무엇이 서빙되는가' 확인이므로 신뢰 검증은 하지 않는다."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni or host) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as e:
        raise VerifyError(f"{host}:{port} TLS 접속 실패({type(e).__name__})")
    if not der:
        raise VerifyError(f"{host}:{port} 가 인증서를 제시하지 않았습니다")
    return x509.load_der_x509_certificate(der).serial_number
