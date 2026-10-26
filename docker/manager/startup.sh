#!/bin/bash
# CertPilot Manager - 컨테이너 시작 스크립트

set -e

echo "=== CertPilot Manager 시작 ==="

# 환경 변수 설정
export CERTPILOT_API_PORT=${CERTPILOT_API_PORT:-8080}
export CERTPILOT_DATA_DIR=${CERTPILOT_DATA_DIR:-/data}
export CERTPILOT_LOG_DIR=${CERTPILOT_LOG_DIR:-/var/log/certpilot}

# Apache 설정 확인
if [ ! -f /etc/apache2/sites-available/000-default.conf ]; then
    echo "Apache 설정 파일이 없습니다."
    exit 1
fi

# Apache 시작
echo "[1/3] Apache 시작..."
service apache2 start || true

# Flask API 시작 (백그라운드)
echo "[2/3] CertPilot API 시작..."
cd /app/certpilot_api
nohup python -m app --port 8080 > /data/logs/certpilot-api.log 2>&1 &

API_PID=$!
echo "CertPilot API PID: $API_PID"

# 로그 디렉토리 생성
mkdir -p /data/logs
mkdir -p /data/certs

# 헬스체크 대기
echo "[3/3] 헬스체크 대기..."
for i in {1..10}; do
    if curl -f http://localhost:8080/health 2>/dev/null; then
        echo "✅ CertPilot API 정상 동작 확인"
        break
    fi
    echo "   대기 중... ($i/10)"
    sleep 3
done

echo "========================================"
echo "✅ CertPilot Manager 실행 시작"
echo "   웹 UI: http://localhost"
echo "   API: http://localhost:8080"
echo "========================================"

# 메인 프로세스 유지
wait $API_PID
