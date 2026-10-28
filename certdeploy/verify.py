"""배포 후 확인: 서비스 포트에 TLS 로 접속해 실제로 서빙되는 인증서를 확인한다.

- 기본: 어떤 인증서가 서빙되는지(일련번호)만 읽는다(신뢰 검증 없음).
- strict: 신뢰 저장소(또는 지정한 CA 번들)로 체인과 호스트명까지 검증한다 — 중간 CA 누락·호스트명 불일치를 잡는다.
"""
import socket
import ssl
import urllib.error
import urllib.request
from typing import Optional

from cryptography import x509


class VerifyError(Exception):
    pass


def tls_serial(host: str, port: int = 443, sni: Optional[str] = None, timeout: float = 10.0,
               strict: bool = False, cafile: Optional[str] = None, lenient: bool = False) -> int:
    """서버가 제시하는 리프 인증서의 일련번호(정수)."""
    if strict:
        ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        if lenient:       # 오래된 사설 CA 인증서(AKI 등 확장 누락)를 허용: RFC 5280 엄격 검사만 끈다(체인·호스트명 검증은 유지)
            ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni or host) as tls:
                der = tls.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as e:
        raise VerifyError(f"{host}:{port} 인증서 검증 실패: {getattr(e, 'verify_message', None) or e.reason}")
    except (OSError, ssl.SSLError) as e:
        raise VerifyError(f"{host}:{port} TLS 접속 실패({type(e).__name__})")
    if not der:
        raise VerifyError(f"{host}:{port} 가 인증서를 제시하지 않았습니다")
    return x509.load_der_x509_certificate(der).serial_number


def http_health(url: str, expect: int = 200, timeout: float = 10.0, insecure: bool = False) -> None:
    """배포 후 서비스가 실제로 응답하는지 확인한다(HTTP 상태 코드). 실패하면 VerifyError."""
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx) if ctx else urllib.request.HTTPSHandler())
    try:
        resp = opener.open(urllib.request.Request(url, method="GET"), timeout=timeout)
        code = resp.status
    except urllib.error.HTTPError as e:
        code = e.code
    except (OSError, ssl.SSLError) as e:
        raise VerifyError(f"헬스체크 접속 실패({type(e).__name__})")
    if code != expect:
        raise VerifyError(f"헬스체크 상태 코드 {code} (기대 {expect})")
