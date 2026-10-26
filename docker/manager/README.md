# CertPilot Manager - Docker 배포 구성

CertPilot Manager 서버를 Docker로 배포하기 위한 종합 구성입니다.
Apache2, Flask API, 프론트엔드, 데이터베이스, 인증서 저장소, 로그 저장소를 모두 포함합니다.

## 📁 파일 구성

| 파일 | 설명 |
|---|---|
| `Dockerfile` | 메인 컨테이너 빌드 설정 (Apache + Flask + Frontend) |
| `apache2/sites-available/certpilot.conf` | Apache 가상 호스트 설정 |
| `docker-compose.yml` | 전체 서비스 구성 (매니저, DB, 인증서 저장소, 로그) |
| `.env.example` | 환경 변수 템플릿 |
| `docker/manager/README.md` | 매니저 서버 배포 가이드 |
| `docker/manager/startup.sh` | 컨테이너 시작 스크립트 |

## 🚀 빠른 시작

```bash
# 1. 저장소 복제
git clone https://github.com/dongjincho508/certpilot.git
cd certpilot

# 2. 환경 변수 설정
cp docker/manager/.env.example docker/manager/.env
# .env 파일 수정 (필수 설정)

# 3. Docker 이미지 빌드
docker-compose -f docker-compose-manager.yml build

# 4. 컨테이너 실행
docker-compose -f docker-compose-manager.yml up -d

# 5. 상태 확인
docker-compose -f docker-compose-manager.yml ps

# 6. 로그 확인
docker-compose -f docker-compose-manager.yml logs -f
```

## 🔗 접속 정보

| 항목 | 값 | 설명 |
|---|---|---|
| 웹 UI | http://localhost:80 | Apache 프록시, 프론트엔드 |
| API | http://localhost:8080 | Flask REST API |
| 헬스 체크 | http://localhost:8080/health | API 상태 확인 |
| 포트 매핑 | 80:80 (HTTP) | Apache 웹 서버 |
| 포트 매핑 | 8080:8080 (API) | Flask API |

## 📊 서비스 구성

| 서비스 | 포트 | 설명 |
|---|---|---|
| Apache2 | 80, 443 | 웹 서버 (리버스 프록시) |
| CertPilot API | 8080 | Flask REST API |
| Frontend | 8080 | UI 정적 파일 (via Apache) |
| 인증서 저장소 | (컨테이너 내부) | /data/certs |
| 로그 저장소 | (컨테이너 내부) | /data/logs |

## 📁 볼륨 구성

| 볼륨 | 경로 | 설명 |
|---|---|---|
| `certpilot_certs` | /data/certs | 관리 대상 인증서 저장 |
| `certpilot_logs` | /data/logs | 감사 로그, 애플리케이션 로그 |
| `certpilot_config` | /data/config | 설정 파일, SSH 키 |

## 🔒 보안 설정

| 항목 | 설정 |
|---|---|
| HTTP | 포트 80 (HTTP) |
| HTTPS | 포트 443 (SSL/TLS) |
| SSL 인증서 | /data/config/ssl/ |
| Apache 설정 | /etc/apache2/sites-available/certpilot.conf |

## 📝 라이선스

MIT License

## 👤 작성자

CertPilot 프로젝트팀
