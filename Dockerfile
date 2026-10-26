# CertPilot Manager - Docker 이미지 빌드 설정

# 메인 이미지: Python 3.11-slim + Apache2 + Flask + Frontend
FROM python:3.11-slim

# 환경 변수
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV CERTPILOT_API_PORT=8080
ENV CERTPILOT_DATA_DIR=/data
ENV CERTPILOT_LOG_DIR=/var/log/certpilot

# 작업 디렉토리
WORKDIR /app

# 시스템 패키지 설치
# - apache2: 웹 서버 (리버스 프록시 포함)
# - curl: 헬스체크
# - libpq-dev, gcc: Python 패키지 빌드
# - openssh-client, sshpass: 원격 서버 SSH 연결
RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    curl \
    libpq-dev \
    gcc \
    openssh-client \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

# Apache 설정 복사
COPY apache2/sites-available/certpilot.conf /etc/apache2/sites-available/000-default.conf

# Apache 모듈 활성화 (프록시, 리라이트 등)
RUN a2enmod proxy proxy_http headers rewrite deflate

# Python 의존성 설치
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 프로젝트 파일 복사
COPY certpilot_core/ /app/certpilot_core/
COPY certpilot_cli/ /app/certpilot_cli/
COPY certpilot_api/ /app/certpilot_api/
COPY frontend/ /app/frontend/

# 시작 스크립트 복사
COPY docker/manager/startup.sh /app/docker/manager/startup.sh
RUN chmod +x /app/docker/manager/startup.sh

# 데이터와 로그 디렉토리 생성
RUN mkdir -p /data/certs /data/logs /data/config && \
    mkdir -p /var/log/certpilot && \
    chmod 755 /data /data/certs /data/logs /data/config && \
    chown -R www-data:www-data /var/log/certpilot

# 볼륨 설정
VOLUME ["/data/certs", "/data/logs", "/data/config"]

# 포트 노출 (Apache: 80, API: 8080)
EXPOSE 80 8080

# 헬스체크 (Apache 프록시 기준)
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=60s \
    CMD curl -f http://localhost:80/health || exit 1

# 진입점
CMD ["/app/docker/manager/startup.sh"]
