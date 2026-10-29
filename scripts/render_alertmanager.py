#!/usr/bin/env python3
"""저장소의 alertmanager.yml(예시 값)에서 운영용 설정을 만든다. 원본은 건드리지 않는다(git pull 충돌 방지).

사용: render_alertmanager.py --in alertmanager.yml --out alertmanager.local.yml --smarthost smtp.hnu.kr:587 --from cert-monitor@hnu.kr \
        --to a@hnu.kr,b@hnu.kr [--user ID] [--no-tls] [--webhook]
- --user 를 주지 않으면 SMTP 인증 줄을 제거한다(인증 없는 내부 릴레이). --webhook 을 주지 않으면 웹훅 블록을 제거한다.
"""
import argparse
import re
import sys


def render(text: str, smarthost: str, sender: str, to: str, user: str = "", tls: bool = True, webhook: bool = False) -> str:
    for bad in (smarthost, sender, to, user):
        if any(c in bad for c in '"\n\r\\'):
            raise ValueError("값에 따옴표·역슬래시·줄바꿈을 넣을 수 없습니다")
    out = re.sub(r'(?m)^(\s*smtp_smarthost:\s*)".*?"', lambda m: f'{m.group(1)}"{smarthost}"', text)
    out = re.sub(r'(?m)^(\s*smtp_from:\s*)".*?"', lambda m: f'{m.group(1)}"{sender}"', out)
    if user:
        out = re.sub(r'(?m)^(\s*smtp_auth_username:\s*)".*?"', lambda m: f'{m.group(1)}"{user}"', out)
    else:
        out = re.sub(r'(?m)^\s*smtp_auth_username:.*\n', "", out)
        out = re.sub(r'(?m)^\s*smtp_auth_password_file:.*\n', "", out)
    out = re.sub(r'(?m)^(\s*smtp_require_tls:\s*)\w+', lambda m: f'{m.group(1)}{"true" if tls else "false"}', out)
    out = re.sub(r'(?m)^(\s*-?\s*to:\s*)"[^"\n]*"', lambda m: f'{m.group(1)}"{to}"', out)
    if not webhook:
        out = re.sub(r'(?m)^    webhook_configs:\n(?:      #.*\n)*      - url_file:.*\n        send_resolved: \w+\n', "", out)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="src", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--smarthost", required=True)
    ap.add_argument("--from", dest="sender", required=True)
    ap.add_argument("--to", required=True, help="수신 주소(여러 명이면 쉼표)")
    ap.add_argument("--user", default="")
    ap.add_argument("--no-tls", action="store_true")
    ap.add_argument("--webhook", action="store_true")
    a = ap.parse_args(argv)
    with open(a.src, encoding="utf-8") as f:
        text = f.read()
    try:
        out = render(text, a.smarthost, a.sender, a.to, a.user, not a.no_tls, a.webhook)
    except ValueError as e:
        print(f"오류: {e}", file=sys.stderr)
        return 2
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
