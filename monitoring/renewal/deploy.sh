#!/usr/bin/env bash
# [초안·미검증] lego 가 발급·갱신 직후 호출하는 배포 훅. 환경변수 LEGO_CERT_PATH / LEGO_CERT_KEY_PATH 를 받는다.
# 대상 목록(targets.conf)의 각 줄: <이름>|<방식>|<ssh 대상 user@host>|<원격 인증서 경로 접두>
#   방식: apache | tomcat | webtob | jeus | nodejs   (IIS 는 deploy-iis.ps1 참고)
# 안전 원칙: 한 대씩 배포 → 재로드 → TLS 확인 → 실패하면 중단(다음 서버로 넘어가지 않음).
# 개인키는 전용 배포 계정(SSH 키, 대상 서버에서 해당 명령만 허용)으로만 전달하고 로그에 남기지 않는다.
set -euo pipefail

CONF="${DEPLOY_TARGETS:-/opt/cert-deploy/targets.conf}"
CERT="${LEGO_CERT_PATH:?lego 훅에서 호출해야 합니다}"
KEY="${LEGO_CERT_KEY_PATH:?}"
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10)

verify_tls() {  # host:port 로 접속해 새 인증서의 일련번호가 보이는지 확인
  local hostport="$1" want got
  want=$(openssl x509 -in "$CERT" -noout -serial | cut -d= -f2)
  got=$(echo | openssl s_client -connect "$hostport" -servername "${hostport%%:*}" 2>/dev/null | openssl x509 -noout -serial | cut -d= -f2)
  [ "$want" = "$got" ]
}

deploy_one() {
  local name="$1" kind="$2" target="$3" prefix="$4" hostport="${5:-}"
  echo "[$name] 배포 시작 ($kind → $target)"
  scp "${SSH_OPTS[@]}" -q "$CERT" "$target:${prefix}.crt.new"
  scp "${SSH_OPTS[@]}" -q "$KEY"  "$target:${prefix}.key.new"
  case "$kind" in
    apache)  remote='install -m 640 "'$prefix'.crt.new" "'$prefix'.crt" && install -m 600 "'$prefix'.key.new" "'$prefix'.key" && rm -f "'$prefix'.crt.new" "'$prefix'.key.new" && apachectl configtest && systemctl reload httpd 2>/dev/null || systemctl reload apache2' ;;
    nodejs)  remote='install -m 640 "'$prefix'.crt.new" "'$prefix'.crt" && install -m 600 "'$prefix'.key.new" "'$prefix'.key" && rm -f "'$prefix'.crt.new" "'$prefix'.key.new" && systemctl restart app-nodejs' ;;   # TODO: 서비스명
    tomcat)  remote='echo "TODO: PEM 직접 참조 또는 PKCS#12 변환 후 키스토어 교체 + 재로드(Tomcat 버전별 문서 확인)"; false' ;;
    webtob)  remote='echo "TODO: WebtoB 인증서 경로·재기동 명령은 제품 문서로 확인"; false' ;;
    jeus)    remote='echo "TODO: JEUS 키스토어(JKS/PKCS12) 교체·재로드는 제품 문서로 확인"; false' ;;
    *) echo "알 수 없는 방식: $kind" >&2; return 2 ;;
  esac
  ssh -n "${SSH_OPTS[@]}" "$target" "$remote"   # -n: 표준입력을 읽지 않아 아래 while 루프 입력을 먹지 않게 함
  if [ -n "$hostport" ]; then
    verify_tls "$hostport" || { echo "[$name] 배포 후 TLS 확인 실패 — 중단합니다" >&2; return 1; }
  fi
  echo "[$name] 완료"
}

while IFS='|' read -r name kind target prefix hostport <&3; do
  [[ -z "${name// }" || "$name" == \#* ]] && continue
  deploy_one "$name" "$kind" "$target" "$prefix" "$hostport"
done 3< "$CONF"
