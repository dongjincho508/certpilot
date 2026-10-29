#!/usr/bin/env bash
# Rocky Linux 10 관리 서버 자동 설치: 감시 스택(Docker) + certdeploy + 관리자 화면 + nginx(HTTPS)
#
# 사용:  sudo bash scripts/install-mgmt-server.sh --hostname mgmt.hnu.kr --mail-to cert-admin@hnu.kr --smtp-host smtp.hnu.kr:587 [옵션]
#        sudo bash scripts/install-mgmt-server.sh --dry-run ...     # 실제 변경 없이 할 일만 출력
# 도움말: bash scripts/install-mgmt-server.sh --help
# 특징: 단계별로 끊어서 실행되고(이미 끝난 단계는 건너뜀 → 실패 후 같은 명령으로 재실행 가능), 비밀번호는 자동 생성해
#       /root/cert-install-summary.txt(0600)에만 저장한다(로그·화면 로그에는 남기지 않음).
# 주의: 이 스크립트는 Rocky 10 실제 VM 에서 아직 실행해 보지 못했다(문법·dry-run·설정 생성 부분만 시험됨). 막히면 출력과 /var/log/cert-install.log 를 전달.
set -Eeuo pipefail

STATE_DIR=/var/lib/cert-install
SUMMARY=/root/cert-install-summary.txt
LOG=/var/log/cert-install.log

# ---- 기본값(옵션·--config 로 변경)
HOSTNAME_FQDN=""
TIMEZONE="Asia/Seoul"
REPO_URL="https://github.com/dongjincho508/certpilot.git"
LOCAL_SRC=""
SRC_DIR=/opt/cert-monitor/src
SMTP_SMARTHOST=""
SMTP_FROM=""
MAIL_TO=""
SMTP_USER=""
SMTP_PASSWORD_ENV="SMTP_PASSWORD"
WEBHOOK_URL_ENV=""
SMTP_NO_TLS=0
ADMIN_USER="certadmin2"
ADMIN_CIDR=""
CONFIG_TEMPLATE="manual"
ENABLE_RENEW_TIMER=0
DISCOVER_CIDR=""
REQUIRE_MFA=0
ENABLE_BACKUP=0
BACKUP_COPY_DIR=""
SKIP_UPDATE=0
SKIP_OS_CHECK=0
NO_NETWORK_CHECK=0
DRY_RUN=0
ASSUME_YES=0
FORCE=0
ONLY=""

STEPS=(preflight base docker source monitoring nginx certdeploy admin verify)
CONFIG_KEYS="HOSTNAME_FQDN TIMEZONE REPO_URL LOCAL_SRC SMTP_SMARTHOST SMTP_FROM MAIL_TO SMTP_USER SMTP_PASSWORD_ENV WEBHOOK_URL_ENV ADMIN_USER ADMIN_CIDR CONFIG_TEMPLATE ENABLE_RENEW_TIMER DISCOVER_CIDR REQUIRE_MFA ENABLE_BACKUP BACKUP_COPY_DIR SMTP_NO_TLS"

usage() {
  cat <<'USAGE'
Rocky Linux 10 관리 서버 자동 설치 (감시 스택 + certdeploy + 관리자 화면 + nginx HTTPS)

필수에 가까운 옵션
  --hostname FQDN          관리 서버 호스트명(nginx·Grafana 주소에 사용), 예: mgmt.hnu.kr
  --mail-to A,B            알림 수신 주소(쉼표 구분)
  --smtp-host HOST:PORT    메일 릴레이 주소, 예: smtp.hnu.kr:587
  --smtp-from ADDR         발신 주소, 예: cert-monitor@hnu.kr
선택
  --smtp-user ID           SMTP 계정(인증 없는 릴레이면 생략). 비밀번호는 환경변수 SMTP_PASSWORD 로 전달
  --smtp-no-tls            STARTTLS 를 쓰지 않는 릴레이(포트 25 등)
  --webhook-url-env NAME   웹훅 URL 이 든 환경변수 이름(Teams 등; 생략하면 웹훅 없음)
  --admin-user NAME        관리자 화면 최초 관리자 계정(기본 certadmin2)
  --admin-cidr CIDR        관리자 화면(8443)을 허용할 관리자 PC 대역(권장), 예: 10.10.0.0/24
  --config-template T      certdeploy 설정 예시: manual(기본)|acme|waf-manual|none
  --enable-renew-timer     자동 발급(내장 ACME/lego) 갱신 타이머 설치
  --discover-cidr A,B      인증서 자동 탐색 대역(예: 10.10.0.0/24); 지정하면 주 1회 탐색 타이머 설치
  --enable-backup          매일 암호화 백업 타이머 설치(백업 비밀번호 자동 생성 → 요약 파일에만 표시)
  --backup-copy-dir DIR    백업을 추가로 복사할 마운트 폴더(NAS 등; 같은 서버에만 두지 않기 위해 권장)
  --require-mfa            관리자 화면 2단계 인증(TOTP) 강제(미등록 계정은 등록 창만 사용 가능)
  --timezone TZ            기본 Asia/Seoul
  --repo-url URL           소스 저장소(기본 GitHub)
  --local-src DIR          GitHub 에 접속할 수 없을 때: 이미 내려받은 소스 폴더를 복사해 사용
  --config FILE            KEY=VALUE 설정 파일(위 옵션과 같은 이름의 대문자 키)
동작
  --dry-run                실제 변경 없이 실행할 내용만 출력
  --yes                    확인 질문 없이 진행
  --only STEP[,STEP]       일부 단계만(단계: preflight base docker source monitoring nginx certdeploy admin verify)
  --force                  이미 끝난 단계도 다시 실행
  --skip-update            dnf update 생략
  --skip-os-check          Rocky 10 확인 생략(시험용)
  --no-network-check       외부 접속 사전 점검 생략(프록시·반입 환경)
USAGE
}

# ---------------------------------------------------------------- 공통 함수
log() { local m; m="$(date '+%F %T') $*"; echo "$m"; if [ "$DRY_RUN" -eq 0 ] && [ -d "$(dirname "$LOG")" ]; then echo "$m" >>"$LOG"; fi; }
warn() { log "[주의] $*"; }
die() { log "[오류] $*"; exit 1; }
run() { if [ "$DRY_RUN" -eq 1 ]; then echo "  + $*"; else "$@"; fi; }
sh_run() { if [ "$DRY_RUN" -eq 1 ]; then echo "  + $1"; else bash -c "$1"; fi; }
gen_pw() { openssl rand -hex 12 | sed 's/$/-Ak/'; }   # 소문자·숫자·대문자·특수문자 4종, 27자(관리자 화면 비밀번호 정책 충족)

# write_file PATH MODE OWNER:GROUP  (내용은 표준 입력)
write_file() {
  local path="$1" mode="$2" owner="$3" tmp
  if [ "$DRY_RUN" -eq 1 ]; then echo "  + (파일 작성) $path mode=$mode owner=$owner"; cat >/dev/null; return 0; fi
  mkdir -p "$(dirname "$path")"
  tmp="$(mktemp "$(dirname "$path")/.tmp-XXXXXX")"
  cat >"$tmp"
  chmod "$mode" "$tmp"
  chown "$owner" "$tmp"
  mv -f "$tmp" "$path"
}

load_config() {
  local file="$1" line key val
  [ -r "$file" ] || die "설정 파일을 읽을 수 없습니다: $file"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|\#*) continue ;; esac
    key="${line%%=*}"; val="${line#*=}"
    val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
    case " $CONFIG_KEYS " in *" $key "*) printf -v "$key" '%s' "$val" ;; *) die "설정 파일의 알 수 없는 키: $key" ;; esac
  done <"$file"
}

# ---------------------------------------------------------------- 옵션 파싱
while [ $# -gt 0 ]; do
  case "$1" in
    --hostname) HOSTNAME_FQDN="$2"; shift 2 ;;
    --mail-to) MAIL_TO="$2"; shift 2 ;;
    --smtp-host) SMTP_SMARTHOST="$2"; shift 2 ;;
    --smtp-from) SMTP_FROM="$2"; shift 2 ;;
    --smtp-user) SMTP_USER="$2"; shift 2 ;;
    --smtp-no-tls) SMTP_NO_TLS=1; shift ;;
    --webhook-url-env) WEBHOOK_URL_ENV="$2"; shift 2 ;;
    --admin-user) ADMIN_USER="$2"; shift 2 ;;
    --admin-cidr) ADMIN_CIDR="$2"; shift 2 ;;
    --config-template) CONFIG_TEMPLATE="$2"; shift 2 ;;
    --enable-renew-timer) ENABLE_RENEW_TIMER=1; shift ;;
    --require-mfa) REQUIRE_MFA=1; shift ;;
    --enable-backup) ENABLE_BACKUP=1; shift ;;
    --backup-copy-dir) BACKUP_COPY_DIR="$2"; ENABLE_BACKUP=1; shift 2 ;;
    --discover-cidr) DISCOVER_CIDR="$2"; shift 2 ;;
    --timezone) TIMEZONE="$2"; shift 2 ;;
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --local-src) LOCAL_SRC="$2"; shift 2 ;;
    --config) load_config "$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --only) ONLY="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --skip-update) SKIP_UPDATE=1; shift ;;
    --skip-os-check) SKIP_OS_CHECK=1; shift ;;
    --no-network-check) NO_NETWORK_CHECK=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "알 수 없는 옵션: $1 (도움말: --help)"; exit 2 ;;
  esac
done

# 입력 검증(셸·YAML 에 들어가는 값이라 허용 문자를 제한)
valid() { [[ "$2" =~ $1 ]] || die "$3 형식이 올바르지 않습니다: $2"; }
[ -z "$HOSTNAME_FQDN" ] || valid '^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$' "$HOSTNAME_FQDN" "호스트명"
[ -z "$MAIL_TO" ] || valid '^[^@[:space:],]+@[^@[:space:],]+(,[^@[:space:],]+@[^@[:space:],]+)*$' "$MAIL_TO" "수신 주소"
[ -z "$SMTP_SMARTHOST" ] || valid '^[A-Za-z0-9.-]+:[0-9]{1,5}$' "$SMTP_SMARTHOST" "SMTP 주소(host:port)"
[ -z "$SMTP_FROM" ] || valid '^[^@[:space:]]+@[^@[:space:]]+$' "$SMTP_FROM" "발신 주소"
[ -z "$SMTP_USER" ] || valid '^[A-Za-z0-9._@+-]+$' "$SMTP_USER" "SMTP 계정"
valid '^[a-z_][a-z0-9_-]{2,31}$' "$ADMIN_USER" "관리자 계정"
[ -z "$BACKUP_COPY_DIR" ] || valid '^/[A-Za-z0-9._/-]+$' "$BACKUP_COPY_DIR" "백업 복사 폴더"
[ -z "$DISCOVER_CIDR" ] || valid '^[0-9./,]+$' "$DISCOVER_CIDR" "탐색 대역"
valid '^[A-Za-z_]+/[A-Za-z_+-]+$' "$TIMEZONE" "시간대"
[ -z "$ADMIN_CIDR" ] || valid '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' "$ADMIN_CIDR" "관리자 PC 대역(CIDR)"
case "$CONFIG_TEMPLATE" in manual|acme|waf-manual|none) ;; *) die "--config-template 은 manual|acme|waf-manual|none 중 하나" ;; esac
[ -z "$ONLY" ] || for s in ${ONLY//,/ }; do case " ${STEPS[*]} " in *" $s "*) ;; *) die "알 수 없는 단계: $s" ;; esac; done
if [ -n "$SMTP_SMARTHOST$SMTP_FROM$MAIL_TO" ] && { [ -z "$SMTP_SMARTHOST" ] || [ -z "$SMTP_FROM" ] || [ -z "$MAIL_TO" ]; }; then
  die "메일 설정은 --smtp-host, --smtp-from, --mail-to 를 함께 지정해야 합니다(생략하면 설치 후 Alertmanager 설정을 직접 채워야 합니다)"
fi

step_selected() { [ -z "$ONLY" ] || [[ ",$ONLY," == *",$1,"* ]]; }

# ---------------------------------------------------------------- 1) 사전 점검
step_preflight() {
  [ "$(id -u)" -eq 0 ] || [ "$DRY_RUN" -eq 1 ] || die "root 로 실행하세요(sudo bash $0 ...)"
  if [ "$SKIP_OS_CHECK" -eq 0 ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    [ "${ID:-}" = rocky ] && [[ "${VERSION_ID:-}" == 10* ]] || die "Rocky Linux 10.x 에서만 실행합니다(현재: ${PRETTY_NAME:-알 수 없음}). 시험용이면 --skip-os-check"
    for f in avx2 bmi2 fma; do grep -qw "$f" /proc/cpuinfo || warn "CPU 플래그 $f 없음 — Rocky 10 은 x86-64-v3 CPU 가 필요합니다(VMware EVC/CPU 호환성 확인)"; done
    [ "$(getenforce 2>/dev/null || echo Unknown)" = Enforcing ] || die "SELinux 가 Enforcing 이 아닙니다. 끄지 말고 Enforcing 으로 설치하세요(getenforce)"
  fi
  local mem_kb disk_kb
  mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  [ "$mem_kb" -ge 7000000 ] || warn "메모리 ${mem_kb} KB — 권장 8 GB 이상"
  disk_kb="$(df -Pk /var 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)"
  [ "${disk_kb:-0}" -ge 30000000 ] || warn "/var 여유 공간 ${disk_kb:-0} KB — 권장 40 GB 이상"
  if [ "$NO_NETWORK_CHECK" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then
    log "외부 접속 사전 점검 생략"
  else
    local bad=0 h
    for h in download.docker.com registry-1.docker.io pypi.org files.pythonhosted.org; do
      curl -sS -o /dev/null -m 10 -I "https://$h" || { warn "접속 불가: $h"; bad=1; }
    done
    [ -n "$LOCAL_SRC" ] || curl -sS -o /dev/null -m 10 -I "https://github.com" || { warn "접속 불가: github.com (--local-src 로 소스 폴더를 지정하면 우회 가능)"; bad=1; }
    [ "$bad" -eq 0 ] || die "필수 외부 접속이 막혀 있습니다. 방화벽/프록시를 확인하거나 이미지·소스 반입 절차를 사용하세요(--no-network-check 로 무시 가능)"
  fi
}

# ---------------------------------------------------------------- 2) 기본 설정
step_base() {
  [ "$SKIP_UPDATE" -eq 1 ] || run dnf -y update
  [ -z "$HOSTNAME_FQDN" ] || run hostnamectl set-hostname "$HOSTNAME_FQDN"
  run timedatectl set-timezone "$TIMEZONE"
  run dnf -y install git python3 python3-pip python3-pyyaml openssl bind-utils nginx policycoreutils-python-utils dnf-plugins-core curl tar chrony firewalld
  run systemctl enable --now chronyd
  run systemctl enable --now firewalld
  run firewall-cmd --permanent --add-service=ssh
  if [ "$DRY_RUN" -eq 1 ] || [ "$(systemd-detect-virt 2>/dev/null || true)" = vmware ]; then
    run dnf -y install open-vm-tools
    run systemctl enable --now vmtoolsd
    sh_run "vmware-toolbox-cmd timesync disable || true"      # 시간 동기화는 chrony 하나만 사용
  fi
}

# ---------------------------------------------------------------- 3) Docker
step_docker() {
  run dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  run dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  if [ "$DRY_RUN" -eq 1 ] || [ ! -f /etc/docker/daemon.json ]; then
    printf '{ "log-driver": "json-file", "log-opts": { "max-size": "20m", "max-file": "5" } }\n' | write_file /etc/docker/daemon.json 0644 root:root
  fi
  run systemctl enable --now docker
  run systemctl restart docker
  run docker run --rm hello-world
}

# ---------------------------------------------------------------- 4) 소스
step_source() {
  run mkdir -p "$(dirname "$SRC_DIR")"
  if [ -n "$LOCAL_SRC" ]; then
    [ "$DRY_RUN" -eq 1 ] || [ -d "$LOCAL_SRC/certdeploy" ] || die "--local-src 에 certdeploy 폴더가 없습니다: $LOCAL_SRC"
    run mkdir -p "$SRC_DIR"
    sh_run "tar -C '$LOCAL_SRC' --exclude=.git -cf - . | tar -C '$SRC_DIR' -xf -"
  elif [ "$DRY_RUN" -eq 0 ] && [ -d "$SRC_DIR/.git" ]; then
    run git -C "$SRC_DIR" pull --ff-only
  else
    run git clone "$REPO_URL" "$SRC_DIR"
  fi
}

# ---------------------------------------------------------------- 5) 감시 스택
step_monitoring() {
  local mon="$SRC_DIR/monitoring" gpw smtp_pw="" hook=""
  if [ "$DRY_RUN" -eq 0 ] && [ ! -f "$mon/.env" ]; then
    gpw="$(gen_pw)"
    cp "$mon/.env.example" "$mon/.env"
    chmod 600 "$mon/.env"
    sed -i "s|^GRAFANA_ADMIN_PASSWORD=.*|GRAFANA_ADMIN_PASSWORD=$gpw|" "$mon/.env"
    [ -z "$HOSTNAME_FQDN" ] || sed -i "s|^GRAFANA_ROOT_URL=.*|GRAFANA_ROOT_URL=https://$HOSTNAME_FQDN|" "$mon/.env"
    printf 'GRAFANA_ADMIN_USER=admin\nGRAFANA_ADMIN_PASSWORD=%s\n' "$gpw" >"$STATE_DIR/grafana.cred"
    chmod 600 "$STATE_DIR/grafana.cred"
  else
    echo "  + (.env 생성: Grafana 관리자 비밀번호 자동 생성, 권한 600)"
  fi
  # Alertmanager 비밀 폴더: 컨테이너(nobody, uid 65534)가 읽을 수 있어야 하므로 소유자를 맞추고 700/600 유지
  run mkdir -p "$mon/alertmanager/secrets"
  if [ -n "${!SMTP_PASSWORD_ENV:-}" ]; then smtp_pw="${!SMTP_PASSWORD_ENV}"; fi
  if [ -n "$WEBHOOK_URL_ENV" ]; then hook="${!WEBHOOK_URL_ENV:-}"; [ -n "$hook" ] || die "환경변수 $WEBHOOK_URL_ENV 가 비어 있습니다"; fi
  printf '%s\n' "${smtp_pw:-CHANGE_ME}" | write_file "$mon/alertmanager/secrets/smtp_password" 0600 65534:65534
  printf '%s\n' "${hook:-https://chat.example/hooks/unused}" | write_file "$mon/alertmanager/secrets/webhook_url" 0600 65534:65534
  run chown 65534:65534 "$mon/alertmanager/secrets"
  run chmod 700 "$mon/alertmanager/secrets"
  if [ -n "$SMTP_SMARTHOST" ]; then
    local args=(--in "$mon/alertmanager/alertmanager.yml" --out "$mon/alertmanager/alertmanager.local.yml" --smarthost "$SMTP_SMARTHOST" --from "$SMTP_FROM" --to "$MAIL_TO")
    [ -z "$SMTP_USER" ] || args+=(--user "$SMTP_USER")
    [ "$SMTP_NO_TLS" -eq 0 ] || args+=(--no-tls)
    [ -z "$hook" ] || args+=(--webhook)
    run python3 "$SRC_DIR/scripts/render_alertmanager.py" "${args[@]}"
    # 원본(alertmanager.yml)은 git 추적 파일이라 그대로 두고, 운영용 사본을 compose override 로 연결한다
    printf 'services:\n  alertmanager:\n    volumes:\n      - ./alertmanager/alertmanager.local.yml:/etc/alertmanager/alertmanager.yml:ro,z\n' \
      | write_file "$mon/docker-compose.override.yml" 0644 root:root
  else
    warn "메일 설정(--smtp-host/--smtp-from/--mail-to)이 없어 Alertmanager 설정은 예시 값 그대로입니다 — alertmanager/alertmanager.yml 의 TODO 를 직접 채우세요"
  fi
  if [ "$DRY_RUN" -eq 1 ] || [ ! -f "$mon/prometheus/targets/servers.yml" ]; then
    run cp "$mon/prometheus/targets/servers.yml.example" "$mon/prometheus/targets/servers.yml"
    warn "감시 대상(prometheus/targets/servers.yml)은 예시입니다 — 실제 서버로 수정하세요(또는 csv_to_targets.py)"
  fi
  # 기동 전 설정 검증(공식 이미지의 도구)
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  + (검증) promtool check config / test rules, amtool check-config (compose 에 지정된 이미지 태그 사용)"
  else
    local pimg aimg
    pimg="$(grep -o 'prom/prometheus:[^ ]*' "$mon/docker-compose.yml" | head -1)"
    aimg="$(grep -o 'prom/alertmanager:[^ ]*' "$mon/docker-compose.yml" | head -1)"
    docker run --rm -v "$mon/prometheus:/etc/prometheus:ro,z" --entrypoint promtool "$pimg" check config /etc/prometheus/prometheus.yml
    docker run --rm -v "$mon/prometheus:/etc/prometheus:ro,z" --entrypoint promtool "$pimg" test rules /etc/prometheus/tests/cert-expiry.test.yml
    if [ -n "$SMTP_SMARTHOST" ]; then
      docker run --rm -v "$mon/alertmanager:/etc/alertmanager:ro,z" --entrypoint amtool "$aimg" check-config /etc/alertmanager/alertmanager.local.yml
    fi
  fi
  sh_run "cd '$mon' && docker compose config -q && docker compose up -d"
  local svc
  for svc in "9090 Prometheus" "9093 Alertmanager" "9091 Pushgateway"; do
    wait_ready "http://127.0.0.1:${svc%% *}/-/ready" "${svc#* }"
  done
}

wait_ready() {
  local url="$1" name="$2"
  if [ "$DRY_RUN" -eq 1 ]; then echo "  + (대기) $name $url"; return 0; fi
  for _ in $(seq 1 60); do
    curl -fsS -m 3 "$url" >/dev/null 2>&1 && { log "$name 준비됨"; return 0; }
    sleep 2
  done
  die "$name 이 기동되지 않았습니다 — docker compose logs --tail=100 로 확인하세요"
}

# ---------------------------------------------------------------- 6) nginx(HTTPS) + 방화벽
step_nginx() {
  local host="${HOSTNAME_FQDN:-$(hostname -f 2>/dev/null || hostname)}" crt=/etc/pki/tls/certs/mgmt.crt key=/etc/pki/tls/private/mgmt.key
  if [ "$DRY_RUN" -eq 1 ] || [ ! -f "$crt" ]; then
    run openssl req -x509 -newkey rsa:2048 -nodes -keyout "$key" -out "$crt" -days 365 -subj "/CN=$host" -addext "subjectAltName=DNS:$host"
    run chmod 600 "$key"
    warn "임시 자체 서명 인증서입니다 — 브라우저 경고가 뜨며, 정식 인증서로 교체하세요(설치 매뉴얼 6단계)"
  fi
  local f
  for f in grafana certdeploy-admin; do
    sh_run "sed -e 's|monitor.univ.example|$host|g; s|mgmt.univ.example|$host|g; s|/etc/pki/tls/certs/monitor.crt|$crt|; s|/etc/pki/tls/private/monitor.key|$key|' '$SRC_DIR/monitoring/nginx/$f.conf.example' > /etc/nginx/conf.d/$f.conf"
  done
  run setsebool -P httpd_can_network_connect on
  run nginx -t
  run systemctl enable --now nginx
  run systemctl reload nginx
  run firewall-cmd --permanent --add-service=https
  if [ -n "$ADMIN_CIDR" ]; then
    run firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$ADMIN_CIDR\" port port=\"8443\" protocol=\"tcp\" accept"
  else
    warn "관리자 화면 포트 8443 을 모든 곳에 엽니다 — 관리자 PC 대역만 허용하려면 --admin-cidr 를 지정하세요"
    run firewall-cmd --permanent --add-port=8443/tcp
  fi
  run firewall-cmd --reload
}

# ---------------------------------------------------------------- 7) certdeploy
step_certdeploy() {
  if [ "$DRY_RUN" -eq 1 ] || ! id certdeploy >/dev/null 2>&1; then
    run useradd --system --create-home --home-dir /var/lib/certdeploy --shell /sbin/nologin certdeploy
  fi
  run install -d -m 700 -o certdeploy -g certdeploy /var/lib/certdeploy/.ssh /var/lib/certdeploy/managed /var/lib/certdeploy-admin
  run install -d -m 750 -o root -g certdeploy /etc/certdeploy
  if [ "$DRY_RUN" -eq 1 ] || [ ! -x /opt/certdeploy/venv/bin/certdeploy ]; then
    run python3 -m venv /opt/certdeploy/venv
  fi
  # 관리자 화면이 소스의 frontend/ 폴더를 직접 읽으므로 editable(소스 폴더 참조) 설치
  run /opt/certdeploy/venv/bin/pip install --quiet -e "$SRC_DIR"
  local tpl
  case "$CONFIG_TEMPLATE" in
    manual) tpl=certdeploy.manual.example.yml ;;
    acme) tpl=certdeploy.acme.example.yml ;;
    waf-manual) tpl=certdeploy.waf-manual.example.yml ;;
    none) tpl="" ;;
  esac
  if [ -n "$tpl" ] && { [ "$DRY_RUN" -eq 1 ] || [ ! -f /etc/certdeploy/certdeploy.yml ]; }; then
    run install -m 640 -o root -g certdeploy "$SRC_DIR/certdeploy/$tpl" /etc/certdeploy/certdeploy.yml
    warn "/etc/certdeploy/certdeploy.yml 은 예시($tpl)입니다 — 대상 서버·경로를 실제 값으로 수정하세요"
  fi
  if [ "$DRY_RUN" -eq 1 ] || [ ! -f /etc/certdeploy/env ]; then
    run install -m 600 -o certdeploy -g certdeploy /dev/null /etc/certdeploy/env
  fi
  if [ "$DRY_RUN" -eq 1 ] || [ ! -f /var/lib/certdeploy/.ssh/id_ed25519 ]; then
    run runuser -u certdeploy -- ssh-keygen -q -t ed25519 -N "" -f /var/lib/certdeploy/.ssh/id_ed25519
  fi
  if [ "$ENABLE_RENEW_TIMER" -eq 1 ]; then
    run cp "$SRC_DIR/certdeploy/systemd/certdeploy-renew.service" "$SRC_DIR/certdeploy/systemd/certdeploy-renew.timer" /etc/systemd/system/
    run systemctl daemon-reload
    run systemctl enable --now certdeploy-renew.timer
  fi
  if [ -n "$DISCOVER_CIDR" ]; then
    local cidr_yaml="" c
    for c in ${DISCOVER_CIDR//,/ }; do cidr_yaml="$cidr_yaml  - $c\n"; done
    # shellcheck disable=SC2059
    printf "cidr:\n$cidr_yaml"'port: ["443", "8443", "9443", "8444", "993", "636"]\ndomain: ["hnu.kr", "hannam.ac.kr"]\nout: /var/lib/certdeploy/discovery.json\nemit_targets: /var/lib/certdeploy/discovery-new-targets.yml\npushgateway: http://127.0.0.1:9091\n' \
      | write_file /etc/certdeploy/discovery.yml 0640 root:certdeploy
    run cp "$SRC_DIR/certdeploy/systemd/certdeploy-discover.service" "$SRC_DIR/certdeploy/systemd/certdeploy-discover.timer" /etc/systemd/system/
    run systemctl daemon-reload
    run systemctl enable --now certdeploy-discover.timer
  fi
  if [ "$ENABLE_BACKUP" -eq 1 ]; then
    run install -d -m 700 -o root -g root /var/backups/certdeploy
    if [ "$DRY_RUN" -eq 1 ] || [ ! -f /etc/certdeploy/backup.env ]; then
      if [ "$DRY_RUN" -eq 0 ]; then
        local bpw
        bpw="$(gen_pw)"
        printf 'CERTDEPLOY_BACKUP_PASSPHRASE=%s\n' "$bpw" | write_file /etc/certdeploy/backup.env 0600 root:root
        printf 'BACKUP_PASSPHRASE=%s\n' "$bpw" >"$STATE_DIR/backup.cred"
        chmod 600 "$STATE_DIR/backup.cred"
      else
        echo "  + (파일 작성) /etc/certdeploy/backup.env mode=0600 (백업 비밀번호 자동 생성)"
      fi
    fi
    if [ "$DRY_RUN" -eq 1 ] || ! grep -q '^backup:' /etc/certdeploy/certdeploy.yml 2>/dev/null; then
      local copy=""
      [ -z "$BACKUP_COPY_DIR" ] || copy="  copy_to:\n    - {kind: dir, name: nas, path: $BACKUP_COPY_DIR}\n"
      if [ "$DRY_RUN" -eq 1 ]; then
        echo "  + (설정 추가) /etc/certdeploy/certdeploy.yml 에 backup: 항목(passphrase_env=CERTDEPLOY_BACKUP_PASSPHRASE${BACKUP_COPY_DIR:+, 외부 복사 $BACKUP_COPY_DIR})"
      else
        # shellcheck disable=SC2059
        printf "\nbackup:\n  dir: /var/backups/certdeploy\n  passphrase_env: CERTDEPLOY_BACKUP_PASSPHRASE\n$copy" >>/etc/certdeploy/certdeploy.yml
      fi
    fi
    run cp "$SRC_DIR/certdeploy/systemd/certdeploy-backup.service" "$SRC_DIR/certdeploy/systemd/certdeploy-backup.timer" /etc/systemd/system/
    run systemctl daemon-reload
    run systemctl enable --now certdeploy-backup.timer
    [ -z "$BACKUP_COPY_DIR" ] || warn "백업 복사 폴더($BACKUP_COPY_DIR)가 쓰기 가능해야 합니다 — certdeploy-backup.service 의 ReadWritePaths 에도 추가하세요(systemctl edit)"
  fi
}

# ---------------------------------------------------------------- 8) 관리자 화면
step_admin() {
  if [ "$DRY_RUN" -eq 0 ] && [ ! -f /etc/certdeploy/admin.env ]; then
    local apw
    apw="$(gen_pw)"
    printf 'CERTPILOT_ADMIN_USER=%s\nCERTPILOT_ADMIN_PASSWORD=%s\nCERTDEPLOY_CONFIG=/etc/certdeploy/certdeploy.yml\nCERTPILOT_DATA_DIR=/var/lib/certdeploy-admin\nCERTPILOT_SECURE_COOKIE=1\nCERTPILOT_REQUIRE_MFA=%s\n' \
      "$ADMIN_USER" "$apw" "$REQUIRE_MFA" | write_file /etc/certdeploy/admin.env 0600 certdeploy:certdeploy
    printf 'ADMIN_USER=%s\nADMIN_PASSWORD=%s\n' "$ADMIN_USER" "$apw" >"$STATE_DIR/admin.cred"
    chmod 600 "$STATE_DIR/admin.cred"
  else
    echo "  + (파일 작성) /etc/certdeploy/admin.env mode=0600 (관리자 비밀번호 자동 생성)"
  fi
  run cp "$SRC_DIR/certdeploy/systemd/certdeploy-admin.service" /etc/systemd/system/
  run systemctl daemon-reload
  run systemctl enable --now certdeploy-admin
  wait_ready "http://127.0.0.1:8081/health" "관리자 화면"
}

# ---------------------------------------------------------------- 9) 점검과 요약
CHECK_FAIL=0
check() { # 설명 명령...
  local desc="$1"; shift
  if [ "$DRY_RUN" -eq 1 ]; then echo "  + (점검) $desc"; return 0; fi
  if "$@" >/dev/null 2>&1; then log "  OK    $desc"; else log "  실패  $desc"; CHECK_FAIL=1; fi
}

step_verify() {
  local host="${HOSTNAME_FQDN:-$(hostname -f 2>/dev/null || hostname)}"
  check "컨테이너 5개 실행" bash -c "[ \"\$(cd '$SRC_DIR/monitoring' && docker compose ps --status running -q | wc -l)\" -ge 5 ]"
  check "Prometheus ready" curl -fsS -m 5 http://127.0.0.1:9090/-/ready
  check "Alertmanager ready" curl -fsS -m 5 http://127.0.0.1:9093/-/ready
  check "Pushgateway ready" curl -fsS -m 5 http://127.0.0.1:9091/-/ready
  check "Grafana HTTPS(nginx 443)" curl -fsSk -m 8 "https://127.0.0.1/api/health" -H "Host: $host"
  check "관리자 화면 HTTPS(nginx 8443)" curl -fsSk -m 8 "https://127.0.0.1:8443/health" -H "Host: $host"
  check "certdeploy 실행 파일" /opt/certdeploy/venv/bin/certdeploy --version
  check "chronyd 동작" systemctl is-active chronyd
  check "firewalld 동작" systemctl is-active firewalld
  check "SELinux Enforcing" bash -c '[ "$(getenforce)" = Enforcing ]'
  [ "$DRY_RUN" -eq 1 ] || [ "$CHECK_FAIL" -eq 0 ] || warn "일부 점검이 실패했습니다 — 위 '실패' 항목과 /var/log/cert-install.log 를 확인하세요"
}

print_summary() {
  [ "$DRY_RUN" -eq 0 ] || { echo; echo "(dry-run 이므로 요약 파일을 만들지 않았습니다)"; return 0; }
  local host="${HOSTNAME_FQDN:-$(hostname -f 2>/dev/null || hostname)}" gpw="(이전 설치 때 생성됨 — monitoring/.env 참고)" apw="(이전 설치 때 생성됨 — /etc/certdeploy/admin.env 참고)" pub=""
  [ ! -f "$STATE_DIR/grafana.cred" ] || gpw="$(sed -n 's/^GRAFANA_ADMIN_PASSWORD=//p' "$STATE_DIR/grafana.cred")"
  [ ! -f "$STATE_DIR/admin.cred" ] || apw="$(sed -n 's/^ADMIN_PASSWORD=//p' "$STATE_DIR/admin.cred")"
  [ ! -f /var/lib/certdeploy/.ssh/id_ed25519.pub ] || pub="$(cat /var/lib/certdeploy/.ssh/id_ed25519.pub)"
  local bkp=""
  if [ -f "$STATE_DIR/backup.cred" ]; then
    bkp="
백업 비밀번호(매일 02:10 암호화 백업, /var/backups/certdeploy): $(sed -n 's/^BACKUP_PASSPHRASE=//p' "$STATE_DIR/backup.cred")
  → 이 비밀번호를 서버 밖(봉인 봉투·금고·비밀번호 관리자)에도 따로 보관하세요. 잃으면 백업을 복구할 수 없습니다."
  fi
  umask 077
  cat >"$SUMMARY" <<SUM
=== 관리 서버 설치 요약 ($(date '+%F %T')) — 이 파일에는 비밀번호가 있습니다(권한 600). 확인 후 안전한 곳에 옮기고 삭제하세요 ===

Grafana(감시 대시보드)   https://$host/            계정 admin / 비밀번호 $gpw
관리자 화면(발급·배포 설정) https://$host:8443/      계정 $ADMIN_USER / 비밀번호 $apw
  → 로그인 후 「발급·배포 설정」에서 메일 입력·시험, 인증서별 개인키 보호 선택
임시 자체 서명 인증서를 쓰고 있으므로 브라우저 경고가 뜹니다(정식 인증서로 교체 필요).

배포용 SSH 공개키(각 대상 서버의 deploy 계정 authorized_keys 에 등록):
$pub
$bkp

남은 수동 작업 (설치 매뉴얼 docs/ops/vm-install-and-test.md)
 1. 감시 대상 등록: $SRC_DIR/monitoring/prometheus/targets/servers.yml (또는 scripts/csv_to_targets.py)
 2. /etc/certdeploy/certdeploy.yml 의 대상(targets)·경로를 실제 값으로 수정 → 대상 서버 준비(8단계) → known_hosts 등록(7-4)
 3. 인증서 준비(9단계: csr/import 또는 자동 발급 7-3) → 시험 T-01~T-22
 4. 메일: 관리자 화면에서 시험 메일 확인(설치 시 --smtp-host 를 준 경우 Alertmanager 에는 이미 반영됨)
 5. 임시 자체 서명 인증서 교체, 8443 허용 대역 확인, 이 요약 파일 삭제
로그: $LOG
SUM
  echo
  cat "$SUMMARY"
}

# ---------------------------------------------------------------- 실행
log "관리 서버 자동 설치 시작(dry-run=$DRY_RUN)"
if [ "$DRY_RUN" -eq 0 ]; then
  [ "$(id -u)" -eq 0 ] || die "root 로 실행하세요(sudo bash $0 ...)"
  mkdir -p "$STATE_DIR" "$(dirname "$LOG")"
  chmod 700 "$STATE_DIR"
  if [ "$ASSUME_YES" -eq 0 ]; then
    read -r -p "이 서버에 감시 스택·certdeploy·nginx 를 설치합니다. 계속할까요? [y/N] " ans
    case "$ans" in y|Y|yes) ;; *) echo "중단했습니다."; exit 1 ;; esac
  fi
fi

n=0; total=${#STEPS[@]}
for s in "${STEPS[@]}"; do
  n=$((n + 1))
  step_selected "$s" || continue
  if [ "$DRY_RUN" -eq 0 ] && [ -f "$STATE_DIR/$s.done" ] && [ "$FORCE" -eq 0 ] && [ "$s" != verify ]; then
    log "[$n/$total] $s — 이미 완료(건너뜀, 다시 하려면 --force)"
    continue
  fi
  log "[$n/$total] $s"
  "step_$s"
  [ "$DRY_RUN" -eq 1 ] || touch "$STATE_DIR/$s.done"
done
print_summary
log "완료"
exit "$CHECK_FAIL"
