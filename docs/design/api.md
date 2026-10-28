# REST API 설계 (구현 기준 v0.2.0)

인증: 로그인 시 HttpOnly 쿠키 `cp_session`(또는 `Authorization: Bearer <token>`). 오류 형식: `{"error":{"code","message"}}`. 시각은 UTC ISO 8601(`...Z`).

| 메서드 | 경로 | 설명 | 권한 |
|---|---|---|---|
| GET | /health | 헬스체크 | 공개 |
| POST | /auth/login | `{username,password}` → 쿠키 + `{username,role,token}` | 공개 |
| POST | /auth/logout | 세션 종료 | 공개 |
| GET | /auth/me | 현재 사용자 | 운영자+ |
| POST | /auth/password | `{old_password,new_password}` 본인 변경, 세션 전부 폐기 | 운영자+ |
| GET/POST | /users | 목록/추가 `{username,password,role}` | 관리자 |
| DELETE | /users/{name} | 삭제(자기 자신 불가) | 관리자 |
| POST | /users/{name}/unlock | 잠금 해제 | 관리자 |
| GET | /servers?status=&group= | 서버 현황(위험 순→서버명 정렬) | 운영자+ |
| POST | /servers | 등록 `{name,hostname,port=22,account,paths[],tls_ports[],warn_days=30,group,memo}` | 관리자 |
| POST | /servers/probe | **등록 전 연결 테스트·경로 탐지**(저장 안 함). 본문: `hostname, port, account, paths[], tls_ports[]` → `{connected, ssh_version, supported, cause/cause_label/action, hostkey_blocked, standard_paths[{path,files}], suggested_paths[{path,in_standard_root}], tls[]}` | 관리자 |
| DELETE | /servers/{id} | 삭제 | 관리자 |
| GET | /servers/{id}/certificates | 최신 조회 결과(인증서 목록·등록 후보 경로) | 운영자+ |
| POST | /servers/{id}/scan | 조회 실행 | 운영자+ |
| POST | /scan | 전체 조회(동시 20) | 운영자+ |
| POST | /servers/{id}/hostkey/reset | 호스트 키 재신뢰(보안 이벤트 기록) | 관리자 |
| GET | /export.csv | CSV 내보내기(인젝션 방어) | 운영자+ |
| GET | /audit-logs?limit= | 감사 로그(최신순) | 관리자 |
| GET | /audit-logs/verify | 해시 체인 무결성 검증 | 관리자 |

## 상태 코드
200/201 성공 · 401 미인증/자격 불일치 · 403 권한 없음 · 404 대상 없음 · 409 중복 · 422 입력 오류 · 423 계정 잠금.
조회 실패는 HTTP 오류가 아니라 **200 + `status: FETCH_FAIL`** 로 표현한다(서버별 결과이므로).

## 데이터 모델
- **servers**: id, name(고유), hostname, port, account, paths[], tls_ports[], warn_days, group, memo, created_at
- **scans**(서버당 최신 1건): scanned_at, status, result(JSON), file_hashes{path→sha256}
- **certificate(결과 내 항목)**: status, role(leaf/intermediate/root), sources[`file:/path`|`port:443`], subject, issuer, serial, san[], not_before, not_after, remaining_days, fingerprint_sha256, changed, cause/cause_label/action, note
- **users / sessions / hostkeys**: 인증·TOFU 저장
- **감사 로그**: JSONL, `id, timestamp, event_type, description, details, prev_hash, hash`
