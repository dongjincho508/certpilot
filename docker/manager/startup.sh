#!/bin/sh
# CertPilot 시작: gunicorn 으로 API+UI 를 포그라운드 실행한다.
set -e
PORT="${PORT:-${CERTPILOT_API_PORT:-8080}}"

if [ -z "$CERTPILOT_ADMIN_USER" ] || [ -z "$CERTPILOT_ADMIN_PASSWORD" ]; then
  echo "경고: CERTPILOT_ADMIN_USER / CERTPILOT_ADMIN_PASSWORD 가 없으면 최초 관리자가 만들어지지 않아 로그인할 수 없습니다." >&2
fi

# 단일 워커·다중 스레드: SQLite 와 해시 체인 감사 로그의 동시 쓰기 안전성을 위해 프로세스는 1개로 둔다.
exec gunicorn --workers 1 --threads 8 --timeout 600 --bind "0.0.0.0:${PORT}" \
  'certpilot_api.app:create_app()'
