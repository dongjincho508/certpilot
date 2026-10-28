"""가짜 lego: run/renew 를 흉내 낸다(renew 는 만료가 임박했을 때만 새 인증서를 쓴다).
환경변수: FAKE_LEGO_FAIL=1 → 실패(429), FAKE_LEGO_COUNT=<파일> → 호출 횟수 기록."""
import os
import sys
import textwrap

TESTS_DIR = os.path.dirname(__file__)

FAKE_LEGO = textwrap.dedent('''\
    #!{python}
    import datetime as dt, os, sys
    sys.path.insert(0, {tests!r})
    from cryptography import x509
    from pki_helpers import make_pki
    from pathlib import Path
    args = sys.argv[1:]
    if os.environ.get("FAKE_LEGO_COUNT"):
        open(os.environ["FAKE_LEGO_COUNT"], "a").write("call\\n")
    path = Path(args[args.index("--path") + 1]) / "certificates"
    doms = [args[i + 1] for i, a in enumerate(args) if a == "--domains"]
    if os.environ.get("FAKE_LEGO_FAIL"):
        print("acme: error 429 rate limited", file=sys.stderr); sys.exit(1)
    base = doms[0].replace("*", "_")
    crt = path / (base + ".crt")
    if "renew" in args and crt.exists():
        days = int(args[args.index("--days") + 1])
        left = (x509.load_pem_x509_certificates(crt.read_bytes())[0].not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).days
        if left > days:
            print("no renewal needed"); sys.exit(0)
    path.mkdir(parents=True, exist_ok=True)
    c, k, *_ = make_pki(path, name=base, san=tuple(doms))
    os.chmod(k, 0o600)
    print("certificate written")
''')


def install_fake_lego(tmp_path, name="fake-lego"):
    p = tmp_path / name
    p.write_text(FAKE_LEGO.format(python=sys.executable, tests=TESTS_DIR))
    p.chmod(0o755)
    return str(p)
