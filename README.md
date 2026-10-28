# CertPilot

Linux 서버에 설치된 SSL/TLS 인증서를 **SSH(디스크 파일)와 TLS 포트(실행 중 서비스)** 로 조회하고, 만료 위험을 한 화면에서 보여주는 MVP.

- 대상: Linux 서버(SSH, OpenSSH 7.0+). 형식: PEM(단일·번들), 키스토어(PKCS#12/JKS)는 존재만 표시
- 상태 8종: 정상 · 만료 임박(기본 30일) · 만료 · 체인 위험 · 유효 전 · 조회 실패 · 인증서 미발견 · 확인 필요
- 보안: ssh-agent 키 인증(패스워드 미지원), TOFU+호스트 키 변경 차단, 고정 읽기 전용 명령·경로 화이트리스트, RBAC(관리자/운영자), 해시 체인 감사 로그
- **현재 상태: MVP 핵심 구현 + 자동 테스트 완료 / 프로덕션 릴리스 보류** — 근거와 남은 일은 [TRACEABILITY](docs/TRACEABILITY.md), [OPEN_ITEMS](docs/OPEN_ITEMS.md)

## 빠른 시작

```bash
pip install -r requirements-dev.txt
scripts/check.sh                      # 문법 검사 + 전체 테스트
python scripts/dev_server.py 8080     # 샘플 데이터가 든 데모 (admin / Demo!Passw0rd-1234)
```

실제 실행(운영):
```bash
cp docker/.env.example .env           # CERTPILOT_ADMIN_USER / CERTPILOT_ADMIN_PASSWORD 설정
docker compose up --build             # http://localhost:8080
```
SSH 조회는 **ssh-agent 에 로드된 키**로 수행됩니다(컨테이너에서는 `SSH_AUTH_SOCK` 마운트 또는 비밀 환경변수 `CERTPILOT_SSH_PRIVATE_KEY` 를 시작 시 메모리 agent 에 로드). **Render 배포는 [docs/ops/render.md](docs/ops/render.md)**. 조회 계정은 인증서 읽기 권한만 가진 전용 계정을 쓰세요.

CLI(로컬 파일 점검·감사 로그 검증):
```bash
python -m certpilot_cli.cli check-file /path/server.pem --warn-days 30
python -m certpilot_cli.cli audit-verify /data/audit
```

## 구조

```
certpilot_core/  status · remote(명령 정책·SSH) · scanner · cert_parser · store · auth · audit_storage · service
certpilot_api/   Flask create_app() (인증·RBAC·REST)
certpilot_cli/   로컬 점검 CLI
frontend/        단일 페이지 UI — Bootstrap 5 + Bootswatch(Flatly/Darkly 라이트·다크), 외부 CDN 없음(vendor/ 포함)
tests/           pytest (단위·API·통합) / scripts/ 개발 서버·화면 스모크
docs/            PRD · 결정 기록 · ARCHITECTURE · TRACEABILITY · OPEN_ITEMS · design/ · history/ · archive/
```

## 문서
| 문서 | 설명 |
|---|---|
| [PRD](docs/PRD.md) | 요구사항(오너 승인 기준선) |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | 구현 구조·조회 흐름·설계 결정 |
| [TRACEABILITY](docs/TRACEABILITY.md) | 요구사항 → 코드 → 테스트, AC 상태 |
| [OPEN_ITEMS](docs/OPEN_ITEMS.md) | 미확정·이월 항목 |
| [ROADMAP](docs/ROADMAP.md) | 제품 방향·단계별 계획·오너 결정 사항(제안) |
| [설계 색인](docs/design/README.md) | API · 인프라 · PKI · UI · 위협 모델 · 테스트 |
| [결정 기록](docs/decisions.md) · [릴리스 상태](docs/release-approval.md) | |

## 환경 변수
`CERTPILOT_ADMIN_USER`/`CERTPILOT_ADMIN_PASSWORD`(최초 관리자) · `CERTPILOT_DATA_DIR`(기본 `./data`, DB·감사 로그) · `CERTPILOT_SECURE_COOKIE`(HTTPS 에서 1) · `CERTPILOT_IDLE_MINUTES`(기본 30) · `CERTPILOT_ADMIN_RESET_PASSWORD`(1 이면 관리자 비밀번호를 환경변수 값으로 복구, 복구 후 제거) · `CERTPILOT_SSH_PRIVATE_KEY_B64`/`CERTPILOT_SSH_PRIVATE_KEY`(조회용 개인키, 시작 시 agent 로드 후 삭제) · `PORT`

## 라이선스
MIT
