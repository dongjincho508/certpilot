# API/데이터 모델 설계 (BACKEND)

## 1. REST API (JSON)

| 메서드 | 경로 | 설명 | 권한 |
|---|---|---|---|
| GET | /servers | 서버 목록 | 운영자+ |
| POST | /servers | 서버 등록 | 관리자 |
| GET | /servers/{id}/certificates | 서버별 인증서 조회 | 운영자+ |
| GET | /servers/{id}/certificates/{cert_id} | 인증서 상세 | 운영자+ |
| POST | /servers/verify | 수동 갱신 | 운영자+ |
| GET | /audit-logs | 감사 로그 목록 | 관리자 |
| GET | /audit-logs/{log_id} | 감사 로그 상세 | 관리자 |

*운영자+: 운영자 기본, 관리자는 전체 허용.*

## 2. 데이터 모델

### Server
| 필드 | 타입 | 비고 |
|---|---|---|
| server_id | string | 고유 식별자 |
| name | string | 서버명, 조직 내 고유 |
| hostname | string | 호스트명/IP |
| port | int | 기본 22 |
| account | string | 전용 읽기 전용 계정 |
| ssh_auth | string | 개인키 + ssh-agent |
| path_whitelist | array | 경로 화이트리스트 |
| warn_T | int | 기본 30일 |
| created_at | datetime | |

### Certificate
| 필드 | 타입 | 비고 |
|---|---|---|
| cert_id | string | |
| server_id | string | |
| fingerprint_sha256 | string | |
| issuer | string | |
| subject | string | |
| san | array | |
| not_before | datetime | |
| not_after | datetime | |
| status | string | 정상/만료 임박/만료/체인 위험/유효 전/조회 실패/인증서 미발견/확인 필요 |
| chain | array | 리프/중간CA/루트 |
| created_at | datetime | |
| updated_at | datetime | |

### AuditLog
| 필드 | 타입 | 비고 |
|---|---|---|
| log_id | string | |
| admin_id | string | |
| server_id | string | |
| cert_fingerprint | string | |
| result | string | 성공/실패/미발견/형식오류 |
| viewed_at | datetime | |
| stored | boolean | WORM 저장 여부 |

## 3. 상태 코드

- 200: 조회 성공
- 401: 인증 실패
- 403: 권한 거부
- 404: 서버 미발견
- 422: 형식 오류
- 503: 조회 실패
