
# CertPilot MVP

**CertPilot MVP**는 기업/조직의 Linux/Unix, Windows, 네트워크 및 보안 장비에 설치된 SSL/TLS 인증서를 검사·관리하기 위한 MVP(Minimum Viable Product) 도구입니다.

## 🚀 프로젝트 개요

- **목적**: 기업/조직의 Linux/Unix, Windows, 네트워크 및 보안 장비에 설치된 SSL/TLS 인증서를 검사·관리
- **대상**: Linux/Unix, Windows, 네트워크 및 보안 장비
- **인증기관**: 공인 CA 및 사내 CA
- **연결 방식**: SSH, 전용 에이전트, 장비 API
- **관리 규모**: 100~1,000대
- **상태**: MVP 승인 완료 (PRD v0.3, Release Approval, Security/Architecture 승인)

## 📋 주요 기능

- **인증서 검사**: PEM, PKCS#12, JKS 형식의 인증서 파싱
- **SSH 통합**: 원격 Linux 서버의 인증서 조회
- **WORM 감사 로그**: SHA-256 해시 트리 무결성 검증
- **REST API**: 서버/인증서 관리 API
- **TOFU + 호스트 키 변경 감지**: SSH 보안
- **고정 읽기 전용 명령어 세트**: `cat`, `head`, `tail`, `grep`, `openssl x509`, `ls`, `find`, `sha256sum`

## 📁 프로젝트 구조

```
certpilot/
├── certpilot_core/          # 핵심 모듈
│   ├── cert_parser.py       # 인증서 파싱 (PEM/PKCS#12/JKS)
│   ├── ssh_integration.py   # SSH 통합
│   ├── audit_storage.py     # WORM 감사 로그 저장
│   ├── certificate_manager.py # 인증서 관리
│   └── server_manager.py    # 서버 관리
├── certpilot_cli/           # CLI 도구
│   └── cli.py
├── certpilot_api/           # REST API
│   └── app.py
├── designs/                 # 설계 문서
│   ├── README.md
│   ├── uiux.md
│   ├── api.md
│   ├── threat-model.md
│   ├── pki.md
│   ├── infra.md
│   ├── testing.md
│   ├── independent-review.md
│   ├── mvp-verification-plan.md
│   ├── test-env-build.md
│   └── mvp-test-execution.md
├── PRD_v0.3_draft.md        # 제품 요구사항 문서
├── OWNER_DECISIONS.md       # 소유자 결정 사항
├── RELEASE_APPROVAL.md      # 릴리스 승인 문서
└── DECISIONS.md             # 전체 의사결정 기록
```

## 🔧 설치 및 실행

### 요구사항
- Python 3.11+
- paramiko (SSH 통합)
- Flask (REST API, 선택 사항)

### 설치
```bash
pip install -r requirements.txt
```

### CLI 실행
```bash
certpilot --help
```

### REST API 실행
```bash
python -m certpilot_api.app
# http://localhost:5000/ 에서 API 확인
```

# 📖 Render 배포 가이드

CertPilot MVP를 Render에 배포하는 방법입니다.

## 배포 방법

### 방법 1: 블루프린트 사용 (권장)

이 저장소의 `render.yaml`을 사용하여 Render에 배포합니다.

1. Render 대시보드에서 **New +** → **GitHub** → `dongjincho508/certpilot` 선택
2. `render.yaml` 기반 자동 구성
3. **Deploy** 클릭

#### 설정 요약

| 항목 | 값 |
|---|---|
| **Type** | `web` |
| **Runtime** | `docker` |
| **Dockerfile** | `Dockerfile` |
| **포트** | `8080` |
| **환경 변수** | `CERTPILOT_API_PORT=8080` |

### 방법 2: 수동 배포

1. Render 대시보드 → **New +** → **Web Service**
2. **GitHub** → `dongjincho508/certpilot` 선택
3. **Build Command**: 없음 (Docker 사용)
4. **Start Command**: `docker/manager/startup.sh`

### 포트 설정

- Render는 **HTTPS**를 기본으로 제공합니다 (Let's Encrypt 자동 인증서)
- 서비스는 내부적으로 **포트 8080**에서 실행됩니다
- 외부 접속은 `https://<your-service>.onrender.com` 형태로 HTTPS를 통해 이루어집니다
- 내부 트래픽은 HTTPS 로드 밸런서에서 HTTPS로 암호화되어 전달됩니다

### 필수 환경 변수

| 변수 | 설명 | 기본값 |
|---|---|---|
| `CERTPILOT_API_PORT` | API 포트 | `8080` |
| `CERTPILOT_DATA_DIR` | 데이터 디렉토리 | `/data` |
| `CERTPILOT_LOG_DIR` | 로그 디렉토리 | `/var/log/certpilot` |
| `CERTPILOT_AUTH_MODE` | 인증 모드 | `disabled` |
| `CERTPILOT_SSH_KEY_DIR` | SSH 키 디렉토리 | `/data/config/keys` |
| `CERTPILOT_DB_URL` | 데이터베이스 URL | `sqlite:///data/certpilot.db` |

### 선택 환경 변수

| 변수 | 설명 | 기본값 |
|---|---|---|
| `CERTPILOT_ADMIN_USER` | 관리자 계정 (운영 시 필수) | - |
| `CERTPILOT_ADMIN_PASSWORD` | 관리자 비밀번호 (운영 시 필수) | - |
| `CERTPILOT_LOG_LEVEL` | 로그 레벨 | `info` |
| `CERTPILOT_LOG_FORMAT` | 로그 형식 | `json` |
| `CERTPILOT_LOG_RETENTION_DAYS` | 로그 보존 기간 (일) | `30` |

## 모니터링

- **로그**: Render 대시보드 → 서비스 → **Logs**
- **메트릭**: Render 대시보드 → 서비스 → **Metrics**
- **헬스체크**: `/health` 엔드포인트 (포트 8080)

## 참고 문서

- [Render Web Services](https://render.com/docs/web-services)
- [Render Blueprints](https://render.com/docs/blueprints)
- [Render Troubleshooting Deploys](https://render.com/docs/troubleshooting-deploys)

## 문서

|| 문서 | 설명 |
|---|---|---|
| [PRD v0.3](PRD_v0.3_draft.md) | 제품 요구사항 문서 |
| [UI/UX 설계](designs/uiux.md) | 관리자 화면 설계 |
| [API 문서](designs/api.md) | REST API 명세서 |
| [위협 모델](designs/threat-model.md) | 보안 위협 및 대응 |
| [테스트 계획](designs/testing.md) | 테스트 전략 및 절차 |
| [독립 검토](designs/independent-review.md) | 독립 검토 결과 |

## 🔒 보안 사항

- **운영 개인키**: 운영 개인키, 비밀번호, API 토큰은 절대 출력하거나 로그에 기록하지 마세요.
- **감사 로그**: WORM(Write Once Read Many) 저장, SHA-256 해시 트리 무결성 검증
- **SSH 보안**: 고정 읽기 전용 명령어 세트, TOFU + 호스트 키 변경 감지
- **인증**: 관리자 계정, 운영자 권한 분리 (RBAC)

## 📄 라이선스

MIT License

## 👤 작성자

- CertPilot 프로젝트팀
- 담당: 조동진 (owner)
