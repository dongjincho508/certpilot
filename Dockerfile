# CertPilot - 단일 이미지 (Flask API + 정적 UI, gunicorn)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CERTPILOT_DATA_DIR=/data PORT=8080

WORKDIR /app

# curl: 헬스체크. openssh-client: 비밀 환경변수의 키를 ssh-agent 에 올리기 위한 ssh-agent/ssh-add (SSH 접속 자체는 paramiko).
RUN apt-get update && apt-get install -y --no-install-recommends curl openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY certpilot_core/ certpilot_core/
COPY certpilot_cli/ certpilot_cli/
COPY certpilot_api/ certpilot_api/
COPY frontend/ frontend/
COPY docker/manager/startup.sh /app/startup.sh

# 비루트 사용자로 실행. /data 는 DB·감사 로그 저장소(볼륨)
RUN useradd --system --uid 10001 certpilot && mkdir -p /data && chown certpilot /data \
    && chmod +x /app/startup.sh
USER certpilot
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=20s \
    CMD curl -fsS http://localhost:${PORT}/health || exit 1

CMD ["/app/startup.sh"]
