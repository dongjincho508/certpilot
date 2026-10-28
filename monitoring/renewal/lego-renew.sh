#!/usr/bin/env bash
# [초안·미검증] lego 로 와일드카드 인증서를 DNS-01(Infoblox)로 발급/갱신하고, 갱신되면 배포 훅을 실행한다.
# 발급 전용 서버 1대에서 root 가 아닌 전용 계정으로 실행하고, 크론/systemd 타이머로 하루 1~2회 호출한다.
#   처음 한 번:  ./lego-renew.sh run       (계정 등록 + 첫 발급)
#   이후 반복:   ./lego-renew.sh renew     (만료 30일 이내일 때만 실제 갱신)
# 먼저 반드시 스테이징 CA 로 시험하세요: LEGO_SERVER=https://acme-staging-v02.api.letsencrypt.org/directory
#
# 필요한 환경변수는 /etc/lego/lego.env (권한 600, 소유자 lego 계정) 에 둔다. 예:
#   LEGO_EMAIL=cert-admin@univ.example
#   LEGO_DOMAINS="univ.example,*.univ.example"
#   INFOBLOX_HOST=infoblox.univ.example  INFOBLOX_USERNAME=...  INFOBLOX_PASSWORD=...  (아래 '주의' 참고)
#   LEGO_DNS_RESOLVERS=203.0.113.10:53     # 위임 영역을 직접 질의할 권한 DNS (선택)
#
# 주의: Infoblox 연동 환경변수 이름은 lego 버전마다 다를 수 있으니 반드시 확인하세요:
#       lego dnshelp -c infoblox
set -euo pipefail

ENV_FILE="${LEGO_ENV_FILE:-/etc/lego/lego.env}"
LEGO_PATH="${LEGO_PATH:-/var/lib/lego}"
HOOK="${LEGO_DEPLOY_HOOK:-/opt/cert-deploy/deploy.sh}"
LEGO_BIN="${LEGO_BIN:-lego}"
[ -r "$ENV_FILE" ] || { echo "환경 파일을 읽을 수 없습니다: $ENV_FILE" >&2; exit 2; }
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a
: "${LEGO_EMAIL:?LEGO_EMAIL 필요}" "${LEGO_DOMAINS:?LEGO_DOMAINS 필요}"

args=(--accept-tos --email "$LEGO_EMAIL" --dns infoblox --path "$LEGO_PATH")
[ -n "${LEGO_SERVER:-}" ] && args+=(--server "$LEGO_SERVER")
[ -n "${LEGO_DNS_RESOLVERS:-}" ] && args+=(--dns.resolvers "$LEGO_DNS_RESOLVERS")
IFS=',' read -r -a domains <<< "$LEGO_DOMAINS"
for d in "${domains[@]}"; do args+=(--domains "$d"); done

case "${1:-}" in
  run)   exec "$LEGO_BIN" "${args[@]}" run --run-hook "$HOOK" ;;
  renew) exec "$LEGO_BIN" "${args[@]}" renew --days "${LEGO_RENEW_DAYS:-30}" --renew-hook "$HOOK" ;;
  *) echo "사용: $0 run|renew" >&2; exit 2 ;;
esac
