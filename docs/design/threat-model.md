# 위협 모델 (SECURITY)

## 1. 신뢰 경계

- 관리 서버(내부) ↔ 대상 서버(SSH)
- 관리 화면 ↔ 관리 서버(HTTPS)
- 관리 서버 ↔ 테스트 환경(격리)

## 2. 위협과 대응 (구현 기준)

| 위협 | 영향 | 대응 | 구현·검증 |
|---|---|---|---|
| 호스트 키 변경(MITM) | 자격·정보 유출 | TOFU, 변경 시 조회 차단 + 보안 이벤트 | `ParamikoExecutor`, `test_ssh_integration::test_tofu…` |
| SSH 세션 가로채기/키 유출 | 계정 탈취 | ssh-agent 전용, 앱은 키·패스워드 미보관 | 패스워드 인자 없음 |
| 조회 계정 권한 초과·임의 명령 | 서버 변경 | 고정 읽기 전용 명령 + 경로 화이트리스트 + 전용 계정 | `CommandPolicy`, `test_policy.py` |
| 개인키 노출 | 키 유출 | 개인키 파일 미접근, PEM 에서 CERTIFICATE 블록만 보존, 키스토어 내용 파싱 제외 | `test_private_key_never_read_or_exposed` |
| 인증서 변조로 상태 오인 | 오탐/미탐 | 파일별 SHA-256 비교 → 확인 필요 + 감사 | `test_hash_change_detected_s4` |
| 감사 로그 조작 | 추적 무력화 | 해시 체인(탐지), 관리자 전용 열람 | `test_audit_storage`; 저장소 수준 WORM 은 O-1 |
| 관리 화면 무차별 대입 | 계정 탈취 | 비밀번호 정책, 5회 잠금, 유휴·동시 세션 제한 | `test_api::test_login_wrong_password_and_lockout` |
| 권한 상승(운영자→관리자) | 설정 변조 | 모든 엔드포인트 RBAC | `test_rbac_operator_cannot_manage` |
| 오류 메시지 정보 노출 | 내부정보 유출 | 분류·조치 방향만 노출, 원문은 감사 로그 | `test_failure_message_has_no_raw_detail` |
| CSV 수식 인젝션 | 운영자 PC 침해 | 수식 시작 문자 이스케이프 | `test_csv_export_and_injection_guard` |
| XSS/클릭재킹 | 세션 탈취 | UI 는 textContent 만 사용, CSP·X-Frame-Options | `test_security_headers` |
| 감사 로그 원문(`raw_error`) 평문 | 내부정보 노출(관리자 한정) | **미해결** — 원문 암호화 O-2 | OPEN_ITEMS |
| 패스워드 인증 | 인증 우회 | 미지원 | |

## 3. 독립 검토
현재까지의 검토는 단일 모델의 역할 분리이며 **독립된 사람·기관의 감사가 아니다**. Q-KEYSTORE·WORM·알고리즘 범위는 OPEN_ITEMS 의 O-1/O-4/O-5 로 독립 검토를 요청한다.
