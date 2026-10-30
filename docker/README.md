# CertPilot MVP - Docker 배포 구성

CertPilot MVP를 Docker 컨테이너로 배포하기 위한 구성 파일입니다.

## 📁 파일 구성

| 파일 | 설명 |
|---|---|
| `Dockerfile` | Docker 이미지 빌드 설정 |
| `docker-compose.yml` | 컨테이너 실행 구성 |
| `.env.example` | 환경 변수 템플릿 |
| `docker/README.md` | Docker 사용 가이드 |

## 🚀 빠른 시작

```bash
# 1. 저장소 복제
git clone https://github.com/dongjincho508/certpilot.git
cd certpilot

# 2. 환경 변수 설정
cp docker/.env.example docker/.env
# .env 파일 수정 (필수 설정)

# 3. Docker 이미지 빌드
docker-compose build

# 4. 컨테이너 실행
docker-compose up -d

# 5. 상태 확인
docker-compose ps
```

## 🔗 접속 정보

| 항목 | 값 |
|---|---|
| API URL | http://localhost:8080 |
| 헬스 체크 | http://localhost:8080/health |
| 프론트엔드 | http://localhost:8080 |

## 📊 데이터 볼륨

| 볼륨 | 경로 | 설명 |
|---|---|---|
| `/data/certs` | 인증서 저장소 | 관리 대상 인증서 저장 |
| `/data/logs` | 로그 저장소 | 감사 로그 및 애플리케이션 로그 |
| `/data/config` | 설정 저장소 | 설정 파일 저장 |

## 🛠 환경 변수

`.env` 파일에서 설정:

| 변수 | 기본값 | 설명 |
|---|---|---|
| `CERTPILOT_API_PORT` | 8080 | API 포트 |
| `CERTPILOT_DATA_DIR` | /data | 데이터 디렉토리 |
| `CERTPILOT_LOG_DIR` | /var/log/certpilot | 로그 디렉토리 |

## 📋 명령어

```bash
# 컨테이너 시작
docker-compose up -d

# 컨테이너 중지
docker-compose down

# 컨테이너 재시작
docker-compose restart

# 로그 확인
docker-compose logs -f

# 컨테이너 접속
docker-compose exec api bash
```

## 🔒 보안 참고

- 운영 환경에서는 `CERTPILOT_API_PORT`를 외부에 노출하지 마세요
- `/data/certs` 볼륨에 민감한 인증서 키를 저장하지 마세요
- 보안 설정이 필요한 경우 `docker-compose.override.yml` 사용

## 📝 라이선스

MIT License

## 👤 작성자

CertPilot 프로젝트팀
