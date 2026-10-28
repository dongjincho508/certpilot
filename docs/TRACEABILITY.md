# 요구사항 추적표 (PRD → 구현 → 테스트)

범례: ✅ 구현+자동 테스트 · 🔶 부분 구현 · ❌ 미구현 · ⏸ MVP 제외/이월
**"자동 테스트 통과"는 운영 환경 검증이 아니다.** SSH 는 프로세스 내 paramiko 서버로, 원격 파일시스템은 샌드박스로 검증했다. 실제 OpenSSH 서버·운영 인증서 대상 검증은 아직 수행하지 않았다.
실행: `scripts/check.sh` (전체) · `pytest -m integration` (SSH/TLS 통합) · `node scripts/e2e_smoke.js` (화면)

## MVP 완료 정의 (AC)

| AC | 요구 | 상태 | 근거 (코드 / 테스트) |
|---|---|---|---|
| AC-1 | 등록 서버 식별 정보 목록 | ✅ | `service.add_server/overview` / `test_api::test_server_crud_and_duplicate`, `test_server_validation` |
| AC-2 | SSH 성공·실패 구분 + 원인 유형 | ✅ | `remote.ParamikoExecutor`, `scanner._connect` / `test_scanner::test_retry_policy`, `test_ssh_integration::*` |
| AC-3 | 식별·발급자·주체·CN/SAN·유효기간 표시 | ✅ | `cert_parser._to_info`, `ScanResult.to_dict` / `test_api::test_scan_flow_and_ui_fields`, `test_cert_parser` |
| AC-4 | 잔여 일수 계산·상태 분류 | ✅ | `status.py` / `test_status.py` (경계 포함·T 변경·최악 집계) |
| AC-5 | 실패·미발견·확인 필요가 정상으로 표시되지 않음 | ✅ | `scanner.py` / `test_scanner::test_not_found…`, `test_corrupt…`, `test_permission_denied…`, `test_ports_scanned_even_if_ssh_fails` |
| AC-6 | 마지막 조회 시각·결과 | ✅ | `service.overview` / `test_api::test_scan_flow…` |
| AC-7 | 변경하지 않음 검증(SHA-256) | ✅ | `remote.CommandPolicy`(쓰기 명령 차단), `scanner._read_file` 해시 비교 / `test_policy.py`, `test_scanner::test_scan_never_modifies_remote`, `test_hash_change_detected_s4` |
| AC-8 | (이력 비교) | ⏸ | P1 이관 |
| AC-9 | KPI 3종(성공률·만료 누락 0·평균 ≤10분) | ❌ | 측정 도구 없음. 감사 로그에 조회 결과가 남아 있어 집계 리포트만 추가하면 됨 |
| AC-10 | 감사 로그 무결성(WORM)·변조 시 알림 | 🔶 | 해시 체인 변조·삭제 탐지 ✅ (`test_audit_storage`, `test_api::test_audit_trail_and_integrity`). **주기 검증·알림·저장소 수준 WORM ❌** |

## 기능 요구 (PRD §3~§6)

| 요구 | 상태 | 비고 |
|---|---|---|
| §3.1.1 서버 등록(고유 서버명·기본 포트 22·계정·경로·T 기본 30) | ✅ | 그룹/메모 포함 |
| §3.1.1 연결 가능 = 인증 세션 수립 | ✅ | 등록 전 **연결 테스트**(`/servers/probe`)와 조회가 동일 기준(인증 세션 수립) 적용 |
| §3.1.2 ssh-agent 키 인증, 패스워드 미지원 | ✅ | `ParamikoExecutor` 에 패스워드 인자 없음 |
| §3.1.2 TOFU + 변경 시 차단·감사 | ✅ | `test_ssh_integration::test_tofu…`, `test_api::test_hostkey_changed…` |
| §3.1.2 고정 읽기 전용 명령·금지 명령 | ✅ | `test_policy.py` |
| §3.1.2 타임아웃 10s·재시도 2회+백오프 | ✅ | 백오프 1s→2s (설계 확정값) |
| §3.1.2 OpenSSH ≥ 7.0, 범위 밖은 '확인 필요' | ✅ | 알고리즘 범위는 OPEN_ITEMS |
| §3.1.3 실패 6종·조치 방향·미분류 없음 | ✅ | `remote.CAUSE_INFO` |
| §3.1.4 디스크 + 포트 기반 조회, 중복 병합 | ✅ | DD-1, DD-2 |
| §3.1.4 PEM 번들·체인(리프/중간/루트) | ✅ | `test_bundle_leaf_and_chain_risk` |
| §3.1.4 PKCS#12/JKS | 🔶 | 서버 조회는 `UNKNOWN`+사유(B-4), 로컬 CLI 는 파싱 ✅ |
| §3.1.4 DER 제외·형식 판별 | ✅ | DER/깨진 파일 → `UNKNOWN` |
| §3.1.4 경로 화이트리스트·전체 탐색 금지·심볼릭 링크 | ✅ | `test_custom_path_and_whitelist`, `test_symlink…` |
| §3.1.4 웹 설정 경로 추출(후보 제시) | ✅ | 정규식 기반(nginx/apache 기본 지시어만). 등록 화면의 **연결 테스트·경로 탐지**(`POST /servers/probe`)에서 선택해 추가 — `test_check_connection_*`, `test_probe_*` |
| §3.1.5 시간 기준 판정·UTC·T 설정 | ✅ | `status.py` |
| §3.1.6 위험 순 정렬·상태/그룹 필터·수동 갱신 | ✅ | `test_overview_sort_and_filter` |
| §5 서버 요약 = 최악 상태 | ✅ | `status.worst` |
| S-1 자격증명 저장·회전 | ⏸ | 앱이 키를 저장하지 않음(ssh-agent 전용). 장기 보관 키 저장소 결정 필요 → OPEN_ITEMS |
| S-2 전용 읽기 전용 계정 | 🔶 | 운영 절차 사항. 앱은 계정 형식만 검증 |
| S-3 경로 화이트리스트 | ✅ | |
| S-4 해시 비교 → 확인 필요 + 감사 | ✅ | DD-7 |
| S-5 감사 추적 | 🔶 | 누가·언제·무엇·결과 기록 ✅. 보존 1년·파기 증명서 ❌ |
| S-6 인증·RBAC·세션·비밀번호·잠금 | 🔶 | 2역할, 정책(12자·3종), 5회 잠금, 유휴 30분, 동시 3세션, 비밀번호 변경 ✅. **변경 주기 강제·유출 계정 차단 ❌** |
| S-7 마스킹·원문 암호화 | 🔶 | 화면은 메타데이터만 ✅. **감사 로그 원문 암호화·복호화 권한 분리 ❌** (`raw_error` 는 현재 평문, 관리자 전용) |
| S-8 원인 메시지 노출 수준 | ✅ | `test_failure_message_has_no_raw_detail` |
| §6.1 100대 규모·동시 20·큐잉 | 🔶 | 풀 20 ✅. 전체 조회는 동기 HTTP(타임아웃 600s) — 비동기 작업 큐 이월 |
| §6.1 보관 1년·파기 | ❌ | |
| CSV 내보내기(운영자) | ✅ | 인젝션 방어 포함 |
