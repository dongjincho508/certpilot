"""외부 HTTP 호출 공용: 설정으로 받은 주소가 file:// 등 http(s) 가 아닌 스킴이면 거부한다."""
import urllib.parse
import urllib.request


def http_url(url: str) -> str:
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        raise OSError(f"http/https 주소만 허용됩니다: {url.split('://')[0]}://…")     # 호출부가 OSError 로 처리한다
    return url


def urlopen(req, timeout: float = 10.0):
    """http/https 만 여는 urllib.request.urlopen (Request 객체 또는 URL 문자열)."""
    http_url(req if isinstance(req, str) else req.full_url)
    return urllib.request.urlopen(req, timeout=timeout)     # nosec B310 — 위에서 스킴 검증
