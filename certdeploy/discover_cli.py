"""certdeploy-discover: 인증서 자동 탐색 CLI (읽기 전용)."""
import sys

import click
import yaml

from . import __version__, discover as dv

CONFIG_KEYS = {"cidr", "name", "names_file", "port", "known", "domain", "out", "state", "emit_targets", "pushgateway",
               "max_hosts", "concurrency", "timeout", "allow_public", "no_reverse_dns"}


def _load_defaults(ctx, param, value):
    if not value:
        return value
    try:
        data = yaml.safe_load(open(value, encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        raise click.BadParameter(f"설정 파일을 읽을 수 없습니다: {e}")
    unknown = set(data) - CONFIG_KEYS
    if unknown:
        raise click.BadParameter(f"알 수 없는 키: {', '.join(sorted(unknown))}")
    ctx.default_map = {k: ([v] if k in ("cidr", "name", "port", "known", "domain") and not isinstance(v, list) else v)
                       for k, v in data.items()}
    return value


@click.command()
@click.version_option(__version__)
@click.option("--config", type=click.Path(), callback=_load_defaults, is_eager=True, expose_value=False, help="YAML 설정(아래 옵션과 같은 이름의 키)")
@click.option("--cidr", multiple=True, help="조사할 대역(여러 번 지정 가능). 예: 10.10.0.0/24")
@click.option("--name", multiple=True, help="조사할 호스트명(여러 번 지정 가능)")
@click.option("--names-file", type=click.Path(exists=True), help="호스트명 목록 파일(한 줄에 하나; Infoblox 내보내기 등)")
@click.option("--port", multiple=True, help=f"조사할 포트(쉼표·범위 가능). 기본 {','.join(map(str, dv.DEFAULT_PORTS))}")
@click.option("--known", multiple=True, default=("/opt/cert-monitor/src/monitoring/prometheus/targets/*.yml",),
              show_default=True, help="이미 등록된 감시 대상 파일(glob)")
@click.option("--domain", multiple=True, default=("hnu.kr", "hannam.ac.kr"), show_default=True, help="우리 도메인(표시용)")
@click.option("--out", "out_json", default="/var/lib/certdeploy/discovery.json", show_default=True, help="결과 JSON(다음 조사와 비교에도 사용)")
@click.option("--state", "state_path", default=None, help="비교 기준 JSON(기본: --out 의 이전 내용)")
@click.option("--emit-targets", type=click.Path(), help="미등록 인증서를 감시 대상 파일 형식으로 저장할 경로")
@click.option("--pushgateway", help="지표를 보낼 Pushgateway 주소(예: http://127.0.0.1:9091)")
@click.option("--max-hosts", default=4096, show_default=True)
@click.option("--concurrency", default=64, show_default=True)
@click.option("--timeout", default=3.0, show_default=True, help="연결·핸드셰이크 제한(초)")
@click.option("--allow-public", is_flag=True, help="사설이 아닌 대역도 허용(조사 권한이 있을 때만)")
@click.option("--no-reverse-dns", is_flag=True)
@click.option("--fail-on-unregistered", is_flag=True, help="미등록 인증서가 있으면 종료 코드 3")
@click.option("--json", "as_json", is_flag=True, help="결과를 JSON 으로 출력")
def main(cidr, name, names_file, port, known, domain, out_json, state_path, emit_targets, pushgateway, max_hosts,
         concurrency, timeout, allow_public, no_reverse_dns, fail_on_unregistered, as_json):
    """등록되지 않은 인증서와 위험한 인증서를 찾는다(서버에 변경 없음, 접속·인증서 조회만)."""
    try:
        names = list(name)
        if names_file:
            names += [ln.split("#")[0].strip() for ln in open(names_file, encoding="utf-8")]
        if not cidr and not [n for n in names if n]:
            raise dv.DiscoverError("--cidr 또는 --name/--names-file 중 하나는 지정해야 합니다")
        scope = dv.expand_scope(cidr, names, max_hosts, allow_public)
        ports = dv.parse_ports(port) if port else list(dv.DEFAULT_PORTS)
        known_set = dv.load_known(known)
        prev = dv.load_json(state_path or out_json)
        result = dv.scan(scope, ports, known_set, domain, timeout, concurrency, not no_reverse_dns)
        delta = dv.diff_previous(result, prev)
        result["delta"] = {k: len(v) for k, v in delta.items()}
        dv.save_json(out_json, result)
        if emit_targets:
            open(emit_targets, "w", encoding="utf-8").write(dv.targets_yaml(result))
        if pushgateway and not dv.push_metrics(pushgateway, dv.metrics_text(result)):
            click.echo("주의: Pushgateway 전송 실패", err=True)
    except dv.DiscoverError as e:
        click.echo(f"오류: {e}", err=True)
        sys.exit(2)
    click.echo(dv.json.dumps(result, ensure_ascii=False, indent=1) if as_json else dv.report_text(result, delta))
    if emit_targets and not as_json:
        click.echo(f"\n미등록 후보 파일: {emit_targets} (검토 후 targets/ 에 반영)")
    sys.exit(3 if fail_on_unregistered and result["summary"]["unregistered"] else 0)


if __name__ == "__main__":
    main()
