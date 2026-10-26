#!/bin/bash
# CertPilot Manager - 컨테이너 시작 스크립트 (Flask API 전용)

set -e

echo "=== CertPilot Manager 시작 ==="

# 환경 변수 설정
export CERTPILOT_API_PORT=${CERTPILOT_API_PORT:-8080}
export CERTPILOT_DATA_DIR=${CERTPILOT_DATA_DIR:-/data}
export CERTPILOT_LOG_DIR=${CERTPILOT_LOG_DIR:-/var/log/certpilot}

# Flask API 시작 (백그라운드)
echo "[1/2] CertPilot API 시작..."
cd /app/certpilot_api
export PYTHONPATH=/app/certpilot_core:/app/certpilot_cli:/app
nohup python certpilot_api/app.py > /data/logs/certpilot-api.log 2>&1 &

API_PID=$!
echo "CertPilot API PID: $API_PID"

# 로그 디렉토리 생성
mkdir -p /data/logs
mkdir -p /data/certs

# 헬스체크 대기
echo "[2/2] 헬스체크 대기..."
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
