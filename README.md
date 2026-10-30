# CertPilot — 인증서 감시·발급·자동 배포

Rocky Linux **관리 서버 1대**에서 서버 50대 이하의 SSL/TLS 인증서를 **감시하고(Prometheus·ssl_exporter·Alertmanager·Grafana)**, **발급·반입하고(상용 인증서 수동 가져오기 / Let's Encrypt DNS-01)**, **에이전트 없이 자동 배포(SSH/API, 실패 시 자동 롤백)** 하는 도구 모음입니다.

> **🚀 처음이면 [원스톱 시작 가이드](docs/ops/quickstart.md)** — 설치 마법사 → 첫날 체크리스트 → 운영 주기표 → 증상별 조치. **📚 문서 목차는 [docs/README.md](docs/README.md)**, 상세 명령은 [설치·테스트 매뉴얼](docs/ops/vm-install-and-test.md), 시험은 [테스트 시나리오](docs/ops/test-scenarios.md), 상태와 미검증 범위는 [검증 보고서](docs/ops/verification-report.md).

## 한눈에

| | 기능 | 위치 |
|---|---|---|
| 🔭 | 만료 감시·알림(메일·메신저·티켓) | `monitoring/`, Grafana |
| 🔐 | 발급·반입(상용 CSR/import, 내장 ACME DNS-01, DNS 제공자 선택) | `certdeploy/` |
| 🚀 | 자동 배포(Apache·nginx·Tomcat·WebtoB·JEUS·IIS·웹방화벽), 롤백, 카나리, 승인 단계 | `certdeploy/` |
| 🔎 | 미등록 인증서 자동 탐색 | `certdeploy-discover` |
| 🛡 | 관리자 화면(설정·운영), 2단계 인증, 변조 방지 감사 로그 | `certpilot_api/`, `frontend/` |
| 💾 | 매일 암호화 백업·검증·외부 복사·복구 | `certdeploy backup-*` |

## 설치 (Rocky Linux 10, 한 번에)

```bash
sudo dnf -y install git && sudo git clone https://github.com/dongjincho508/certpilot.git /opt/cert-monitor/src
cd /opt/cert-monitor/src && sudo bash scripts/install-mgmt-server.sh      # 설치 마법사가 질문합니다(--dry-run 으로 계획만 확인 가능)
```
업데이트(설정·데이터 유지): `cd /opt/cert-monitor/src && sudo git pull --ff-only && sudo /opt/certdeploy/venv/bin/pip install -e . && sudo systemctl restart certdeploy-admin`

## 구조

```
certdeploy/      발급·배포·승인·백업·탐색·알림 (CLI: certdeploy, certdeploy-discover)
certpilot_api/   관리자 화면 백엔드(Flask: 인증·RBAC·2단계 인증·감사 로그·설정 API)
certpilot_core/  공용(인증·감사 로그·저장소·추적) 및 SSH 인벤토리 조회
certpilot_cli/   로컬 점검 CLI
frontend/        관리자 화면(Bootstrap, 외부 CDN 없음)
monitoring/      Prometheus·Alertmanager·Grafana·ssl_exporter(Docker Compose)
scripts/         설치 스크립트(install-mgmt-server.sh), Kickstart 예시, 점검 도구
tests/           pytest(단위·통합·설치 스크립트 실제 실행·브라우저 화면)
docs/            시작 가이드·설치 매뉴얼·시험·검증 보고서
```

## 개발·시험
```bash
pip install -r requirements-dev.txt
scripts/check.sh                      # 문법 검사 + 전체 테스트 (promtool/amtool 이 PATH 에 있으면 감시 설정 시험까지)
```

## 라이선스
MIT
