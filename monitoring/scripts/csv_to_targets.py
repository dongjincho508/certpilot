#!/usr/bin/env python3
"""서버 목록 CSV → Prometheus 감시 대상 파일(targets/*.yml) 변환.

CSV 열: host(필수), port(기본 443), group, service, os, owner, module(기본 tcp; 메일은 smtp)
예)  host,port,group,service,os,owner
     www.univ.example,443,대표홈페이지,apache,linux,전산실
사용: python csv_to_targets.py servers.csv -o ../prometheus/targets/servers.yml
"""
import argparse
import csv
import re
import sys
from collections import OrderedDict

import yaml

HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$|^\[[0-9A-Fa-f:]+\]$")
LABEL_COLS = ("group", "service", "os", "owner", "module")
VALID_OS = {"linux", "windows", "other"}


class RowError(ValueError):
    pass


def convert(rows):
    """CSV 행(dict 목록) → file_sd 구조. 같은 레이블 조합끼리 묶고 중복 대상은 오류로 처리한다."""
    groups = OrderedDict()
    seen = {}
    for n, raw in enumerate(rows, start=2):  # 1행은 헤더
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items()}
        host = row.get("host", "")
        if not host or host.startswith("#"):
            continue
        if not HOST_RE.match(host):
            raise RowError(f"{n}행: 호스트 형식이 올바르지 않습니다: {host!r}")
        try:
            port = int(row.get("port") or 443)
        except ValueError:
            raise RowError(f"{n}행: 포트가 숫자가 아닙니다: {row.get('port')!r}")
        if not 1 <= port <= 65535:
            raise RowError(f"{n}행: 포트 범위는 1~65535 입니다: {port}")
        os_name = row.get("os", "").lower()
        if os_name and os_name not in VALID_OS:
            raise RowError(f"{n}행: os 는 {sorted(VALID_OS)} 중 하나여야 합니다: {os_name!r}")
        target = f"{host}:{port}"
        if target in seen:
            raise RowError(f"{n}행: {target} 가 {seen[target]}행과 중복됩니다")
        seen[target] = n
        labels = {c: (os_name if c == "os" else row.get(c, "")) for c in LABEL_COLS}
        labels = {k: v for k, v in labels.items() if v}
        key = tuple(sorted(labels.items()))
        groups.setdefault(key, {"targets": [], "labels": labels})["targets"].append(target)
    return list(groups.values())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_file")
    ap.add_argument("-o", "--output", help="출력 파일(기본: 표준 출력)")
    args = ap.parse_args(argv)
    with open(args.csv_file, newline="", encoding="utf-8-sig") as f:  # Excel 의 BOM 허용
        try:
            data = convert(csv.DictReader(f))
        except RowError as e:
            print(f"오류: {e}", file=sys.stderr)
            return 1
    text = "# csv_to_targets.py 로 생성됨 — CSV 를 수정하고 다시 생성하세요.\n" + \
           yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            out.write(text)
        print(f"{sum(len(g['targets']) for g in data)}개 대상을 {args.output} 에 기록했습니다.")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
