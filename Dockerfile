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

# 앱은 비루트 사용자(10001)로 실행한다. Render 디스크는 root 소유로 마운트되므로
# 컨테이너는 root 로 시작해 /data 소유권을 맞춘 뒤 startup.sh 가 권한을 내린다(setpriv).
RUN useradd --system --uid 10001 certpilot && mkdir -p /data && chown certpilot /data \
    && chmod +x /app/startup.sh
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=20s \
    CMD curl -fsS http://localhost:${PORT}/health || exit 1

CMD ["/app/startup.sh"]
