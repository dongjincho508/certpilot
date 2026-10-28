#!/bin/sh
# CertPilot 시작: (선택) ssh-agent 에 키를 올리고 gunicorn 으로 API+UI 를 포그라운드 실행한다.
set -e
PORT="${PORT:-${CERTPILOT_API_PORT:-8080}}"
DATA_DIR="${CERTPILOT_DATA_DIR:-/data}"

# root 로 시작했다면 데이터 디스크 소유권을 앱 사용자에게 맞추고 권한을 내려 다시 실행한다.
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA_DIR"
  chown -R 10001:10001 "$DATA_DIR" || echo "경고: $DATA_DIR 소유권 변경 실패" >&2
  export HOME=/tmp   # 권한을 내린 뒤 /root 에 쓰지 않도록
  exec setpriv --reuid=10001 --regid=10001 --clear-groups sh "$0" "$@"
fi

if [ -z "$CERTPILOT_ADMIN_USER" ] || [ -z "$CERTPILOT_ADMIN_PASSWORD" ]; then
  echo "경고: CERTPILOT_ADMIN_USER / CERTPILOT_ADMIN_PASSWORD 가 없으면 최초 관리자가 만들어지지 않아 로그인할 수 없습니다." >&2
fi

# Render 등 ssh-agent 가 없는 환경: 비밀 환경변수의 개인키를 컨테이너 안 ssh-agent 메모리에만 올린다.
# 키는 디스크에 쓰지 않는다. 줄바꿈이 깨진 키는 자동 복원하고, 실패하면 사유(키 내용 제외)를 로그에 남긴다.
# CERTPILOT_SSH_PRIVATE_KEY(여러 줄) 또는 CERTPILOT_SSH_PRIVATE_KEY_B64(한 줄, 권장) 를 지원한다.
if [ -n "$CERTPILOT_SSH_PRIVATE_KEY" ] || [ -n "$CERTPILOT_SSH_PRIVATE_KEY_B64" ]; then
  if KEY="$(python -m certpilot_core.sshkey)"; then
    eval "$(ssh-agent -s)" >/dev/null
    if ADD_ERR="$(printf '%s\n' "$KEY" | ssh-add - 2>&1 >/dev/null)"; then
      echo "ssh-agent 에 조회용 키를 로드했습니다."
    else
      echo "오류: ssh-add 실패 — $(printf '%s' "$ADD_ERR" | head -c 200). SSH 조회는 실패합니다." >&2
    fi
  else
    echo "오류: 위 사유로 SSH 키를 ssh-agent 에 올리지 못했습니다. SSH 조회는 실패합니다." >&2
  fi
  unset KEY ADD_ERR CERTPILOT_SSH_PRIVATE_KEY CERTPILOT_SSH_PRIVATE_KEY_B64
elif [ -z "$SSH_AUTH_SOCK" ]; then
  echo "알림: SSH_AUTH_SOCK 도 CERTPILOT_SSH_PRIVATE_KEY 도 없어 SSH 조회는 '인증 실패'로 표시됩니다(TLS 포트 조회는 가능)." >&2
fi

# 단일 워커·다중 스레드: SQLite 와 해시 체인 감사 로그의 동시 쓰기 안전성을 위해 프로세스는 1개로 둔다.
exec gunicorn --workers 1 --threads 8 --timeout 600 --bind "0.0.0.0:${PORT}" \
  'certpilot_api.app:create_app()'
