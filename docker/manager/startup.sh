#!/bin/sh
# CertPilot 시작: (선택) ssh-agent 에 키를 올리고 gunicorn 으로 API+UI 를 포그라운드 실행한다.
set -e
PORT="${PORT:-${CERTPILOT_API_PORT:-8080}}"

if [ -z "$CERTPILOT_ADMIN_USER" ] || [ -z "$CERTPILOT_ADMIN_PASSWORD" ]; then
  echo "경고: CERTPILOT_ADMIN_USER / CERTPILOT_ADMIN_PASSWORD 가 없으면 최초 관리자가 만들어지지 않아 로그인할 수 없습니다." >&2
fi

# Render 등 ssh-agent 가 없는 환경: 비밀 환경변수의 개인키를 컨테이너 안 ssh-agent 메모리에만 올린다.
# 키는 디스크에 쓰지 않고, 로드 직후 환경변수에서 지운다. (키는 암호 없는 키여야 한다)
if [ -n "$CERTPILOT_SSH_PRIVATE_KEY" ]; then
  eval "$(ssh-agent -s)" >/dev/null
  if printf '%s\n' "$CERTPILOT_SSH_PRIVATE_KEY" | ssh-add - >/dev/null 2>&1; then
    echo "ssh-agent 에 조회용 키를 로드했습니다."
  else
    echo "오류: CERTPILOT_SSH_PRIVATE_KEY 를 ssh-agent 에 로드하지 못했습니다(형식·암호 확인). SSH 조회는 실패합니다." >&2
  fi
  unset CERTPILOT_SSH_PRIVATE_KEY
elif [ -z "$SSH_AUTH_SOCK" ]; then
  echo "알림: SSH_AUTH_SOCK 도 CERTPILOT_SSH_PRIVATE_KEY 도 없어 SSH 조회는 '인증 실패'로 표시됩니다(TLS 포트 조회는 가능)." >&2
fi

# 단일 워커·다중 스레드: SQLite 와 해시 체인 감사 로그의 동시 쓰기 안전성을 위해 프로세스는 1개로 둔다.
exec gunicorn --workers 1 --threads 8 --timeout 600 --bind "0.0.0.0:${PORT}" \
  'certpilot_api.app:create_app()'
