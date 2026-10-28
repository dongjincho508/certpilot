#!/usr/bin/env python3
"""Prometheus 에서 인증서 인벤토리를 조회하고 '교체 체크리스트'를 만든다 (표준 라이브러리만 사용).

  list                      현재 서비스 중인 인증서를 만료 임박 순으로 출력
  serials                   일련번호별로 사용 서버 수와 최소 잔여일 출력(같은 인증서를 쓰는 서버 파악)
  snapshot --serial N       교체 전: 해당 일련번호를 쓰는 대상 목록을 CSV 로 저장
  check --snapshot F        교체 후: 스냅샷 대상 중 교체 완료/미완료/조회 실패를 판정(미완료가 있으면 종료 코드 1)

예) 와일드카드 인증서(일련번호 123...)를 교체하기 전과 후:
  python cert_inventory.py snapshot --serial 123456789 -o before.csv
  (...인증서 배포...)
  python cert_inventory.py check --snapshot before.csv --serial 123456789
Prometheus 는 기본 http://localhost:9090 (옵션 --url 또는 환경변수 PROMETHEUS_URL).
"""
import argparse
import csv
import json
import os
import sys
import urllib.parse
import urllib.request

LEAF = '{dnsnames!=""}'


def query(base, expr, timeout=30):
    url = base.rstrip("/") + "/api/v1/query?" + urllib.parse.urlencode({"query": expr})
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        raise SystemExit("Prometheus 주소는 http/https 여야 합니다")
    with urllib.request.urlopen(url, timeout=timeout) as r:  # nosec B310 — 위에서 스킴 검증
        body = json.load(r)
    if body.get("status") != "success":
        raise RuntimeError(f"Prometheus 오류: {body}")
    return body["data"]["result"]


def fetch_certs(base):
    """서비스 중인(SAN 이 있는) 인증서 목록. days = 남은 일수(소수)"""
    out = []
    for r in query(base, f"(ssl_cert_not_after{LEAF} - time()) / 86400"):
        m = r["metric"]
        out.append({"instance": m.get("instance", ""), "group": m.get("group", ""), "service": m.get("service", ""),
                    "os": m.get("os", ""), "owner": m.get("owner", ""), "cn": m.get("cn", ""),
                    "issuer": m.get("issuer_cn", ""), "serial": m.get("serial_no", ""), "days": float(r["value"][1])})
    return sorted(out, key=lambda c: (c["days"], c["instance"]))


def failed_instances(base):
    return {r["metric"].get("instance", "") for r in query(base, "ssl_probe_success == 0")}


def fmt_days(d):
    return "만료" if d <= 0 else f"{int(d)}일"


def print_table(rows, cols, out=sys.stdout):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h)) for i, h in enumerate(cols)]
    line = lambda vals: "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(vals))
    print(line(cols), file=out)
    print("  ".join("-" * w for w in widths), file=out)
    for r in rows:
        print(line(r), file=out)


def cmd_list(a):
    rows = [(c["instance"], c["group"], c["service"], c["os"], c["cn"], fmt_days(c["days"]), c["serial"][:12] + "…")
            for c in fetch_certs(a.url)]
    print_table(rows, ["대상", "그룹", "서비스", "OS", "CN", "잔여", "일련번호"])
    return 0


def cmd_serials(a):
    by = {}
    for c in fetch_certs(a.url):
        e = by.setdefault(c["serial"], {"cn": c["cn"], "issuer": c["issuer"], "n": 0, "min": c["days"], "hosts": []})
        e["n"] += 1
        e["min"] = min(e["min"], c["days"])
        e["hosts"].append(c["instance"])
    rows = sorted(((s, e["cn"], e["issuer"], e["n"], fmt_days(e["min"])) for s, e in by.items()), key=lambda r: r[4])
    print_table(rows, ["일련번호", "CN", "발급자", "서버 수", "최소 잔여"])
    return 0


def cmd_snapshot(a):
    rows = [c for c in fetch_certs(a.url) if c["serial"] == a.serial]
    if not rows:
        print(f"일련번호 {a.serial} 를 쓰는 대상이 없습니다.", file=sys.stderr)
        return 2
    with open(a.output, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["instance", "group", "service", "os", "owner", "cn", "old_serial"])
        for c in rows:
            w.writerow([c["instance"], c["group"], c["service"], c["os"], c["owner"], c["cn"], c["serial"]])
    print(f"{len(rows)}개 대상을 {a.output} 에 저장했습니다.")
    return 0


def cmd_check(a):
    with open(a.snapshot, newline="", encoding="utf-8") as f:
        targets = list(csv.DictReader(f))
    current = {}
    for c in fetch_certs(a.url):
        current.setdefault(c["instance"], set()).add(c["serial"])
    failed = failed_instances(a.url)
    result, counts = [], {"교체 완료": 0, "미교체": 0, "조회 실패": 0}
    for t in targets:
        inst, old = t["instance"], a.serial or t["old_serial"]
        if inst in failed or inst not in current:
            status = "조회 실패"
        elif old in current[inst]:
            status = "미교체"
        else:
            status = "교체 완료"
        counts[status] += 1
        result.append((inst, t["group"], t["service"], t["os"], t["owner"], status))
    order = ("미교체", "조회 실패", "교체 완료")  # 조치가 필요한 항목을 위로
    result.sort(key=lambda r: (order.index(r[5]), r[0]))
    print_table(result, ["대상", "그룹", "서비스", "OS", "담당", "상태"])
    print(f"\n교체 완료 {counts['교체 완료']} / 미교체 {counts['미교체']} / 조회 실패 {counts['조회 실패']}  (전체 {len(targets)})")
    if a.output:
        with open(a.output, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["instance", "group", "service", "os", "owner", "status"])
            w.writerows(result)
    return 0 if counts["미교체"] == 0 and counts["조회 실패"] == 0 else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("PROMETHEUS_URL", "http://localhost:9090"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    sub.add_parser("serials").set_defaults(fn=cmd_serials)
    s = sub.add_parser("snapshot")
    s.add_argument("--serial", required=True)
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(fn=cmd_snapshot)
    c = sub.add_parser("check")
    c.add_argument("--snapshot", required=True)
    c.add_argument("--serial", help="교체 전 일련번호(생략하면 스냅샷의 값 사용)")
    c.add_argument("-o", "--output", help="결과 CSV")
    c.set_defaults(fn=cmd_check)
    a = ap.parse_args(argv)
    try:
        return a.fn(a)
    except (OSError, RuntimeError) as e:
        print(f"오류: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
