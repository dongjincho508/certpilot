# 테스트 전략 (구현 기준)

원칙: **별도 격리 VM/Docker 없이** 이 저장소만으로 개발 환경(Claude Code 클라우드 포함)에서 전부 검증한다. 운영 서버에는 접속하지 않는다.

| 계층 | 방법 | 위치 |
|---|---|---|
| 단위 | 순수 함수(상태 판정·정책·파서·인증)에 시각 주입. 인증서는 `cryptography` 로 fixture 즉석 생성 | `tests/test_status.py` `test_policy.py` `test_cert_parser.py` |
| 스캐너 | `SandboxExecutor`(로컬 디렉터리=원격 FS) + 가짜 TLS 프로브 + 주입 시계/sleep | `tests/test_scanner.py` |
| API | `create_app()` + Flask `test_client`, 실행기 주입, 시계 조작(잠금·유휴 만료) | `tests/test_api.py` |
| 통합(`-m integration`) | 프로세스 내 paramiko SSH 서버(TOFU·호스트 키 변경·인증 실패·DNS·거부), 실제 TLS 서버 핸드셰이크 | `tests/test_ssh_integration.py` `test_tls_probe.py` |
| 화면 | Playwright 스모크(로그인 실패/성공·현황·상세·감사 검증)+스크린샷 | `scripts/e2e_smoke.js` (대상: `scripts/dev_server.py`) |
| CLI | click `CliRunner` | `tests/test_cli.py` |

## 실행
```bash
scripts/check.sh                 # 문법 + 전체 pytest
pytest -m "not integration"      # 빠른 단위 검증
python scripts/dev_server.py 8080 &  node scripts/e2e_smoke.js http://127.0.0.1:8080 ./shots
```
CI: `.github/workflows/ci.yml` 가 push/PR 마다 `scripts/check.sh` 실행.

## 한계 (정직한 범위)
- 실제 OpenSSH/운영 인증서 대상 검증은 미수행(OPEN_ITEMS I-7). KPI(AC-9) 측정 없음.
- AC 별 근거와 상태는 [TRACEABILITY](../TRACEABILITY.md).
