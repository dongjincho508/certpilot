"""CertPilot CLI: 로컬 인증서 파일 점검과 감사 로그 무결성 검증 (서버 조회는 API/UI 에서 수행)"""
import json
import sys

import click

from certpilot_core import status as st
from certpilot_core.audit_storage import AuditLogReader
from certpilot_core.cert_parser import parse_jks, parse_pem_certificates, parse_pkcs12


@click.group()
def main():
    """CertPilot 도구 모음"""


@main.command("check-file")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--warn-days", default=st.DEFAULT_WARN_DAYS, show_default=True, help="만료 임박 기준(일)")
@click.option("--password", default=None, envvar="CERTPILOT_KEYSTORE_PASSWORD",
              help="PKCS#12/JKS 비밀번호 (환경변수 CERTPILOT_KEYSTORE_PASSWORD 권장)")
@click.option("--json", "as_json", is_flag=True, help="JSON 출력")
def check_file(path, warn_days, password, as_json):
    """로컬 인증서 파일(PEM/PKCS#12/JKS)의 만료 상태를 판정한다. 하나라도 정상이 아니면 종료 코드 1."""
    low = path.lower()
    if low.endswith((".p12", ".pfx")):
        certs = parse_pkcs12(path, password)
    elif low.endswith(".jks"):
        certs = parse_jks(path, password=password or "changeit")
    else:
        certs = parse_pem_certificates(path)
    now = st.utcnow()
    rows, bad = [], False
    for c in certs:
        s = st.classify(c.not_before, c.not_after, now, warn_days)
        bad = bad or s != st.Status.OK
        rows.append({"subject": c.subject, "status": s.value, "label": st.LABELS[s],
                     "not_after": st.iso_z(c.not_after),
                     "remaining_days": None if s == st.Status.NOT_YET else st.remaining_days(c.not_after, now)})
    if not rows:
        click.echo("인증서를 찾지 못했거나 형식 오류입니다 (확인 필요).", err=True)
        sys.exit(2)
    if as_json:
        click.echo(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        for r in rows:
            click.echo(f"[{r['label']}] {r['subject']}  만료 {r['not_after']}  잔여 {r['remaining_days']}일")
    sys.exit(1 if bad else 0)


@main.command("audit-verify")
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
def audit_verify(directory):
    """감사 로그 해시 체인 무결성을 검증한다. 변조가 있으면 종료 코드 1."""
    r = AuditLogReader(directory).verify_integrity()
    click.echo(json.dumps(r, ensure_ascii=False, indent=2))
    sys.exit(0 if r["integrity_valid"] else 1)


@main.command("export-targets")
@click.option("--db", required=True, type=click.Path(exists=True, dir_okay=False), help="CertPilot SQLite 파일(certpilot.db)")
@click.option("-o", "--output", type=click.Path(), help="출력 파일(기본: 표준 출력). Prometheus file_sd 형식")
def export_targets(db, output):
    """등록된 서버를 Prometheus 감시 대상(file_sd)으로 내보낸다(호스트:TLS포트, 그룹·OS 레이블). 서버 목록을 두 곳에서 관리하지 않게 한다."""
    import yaml
    from certpilot_core.store import Store
    groups = {}
    for sv in Store(db).list_servers():
        os_label = {"auto": "", "debian": "linux", "rhel": "linux", "suse": "linux", "alpine": "linux", "generic": "linux"}.get(sv.get("os_type") or "auto", "")
        labels = {k: v for k, v in {"group": sv.get("group"), "os": os_label}.items() if v}
        for port in sv.get("tls_ports") or [443]:
            groups.setdefault(tuple(sorted(labels.items())), {"targets": [], "labels": labels})["targets"].append(f"{sv['hostname']}:{port}")
    data = list(groups.values())
    text = "# certpilot-cli export-targets 로 생성됨\n" + yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(text)
        click.echo(f"{sum(len(g['targets']) for g in data)}개 대상을 {output} 에 기록했습니다.")
    else:
        click.echo(text, nl=False)


if __name__ == "__main__":
    main()
