# CertPilot 아키텍처 (구현 기준)

이 문서는 **현재 코드가 실제로 하는 일**을 기술한다. 요구사항의 원본은 [PRD](PRD.md), 결정의 원본은 [decisions.md](decisions.md).

## 1. 구성

```
 브라우저 ──HTTPS──▶ Flask API (certpilot_api) ──▶ CertPilotService (certpilot_core.service)
                         │ 인증/RBAC                   ├─ Scanner ──▶ RemoteExecutor ──SSH──▶ 대상 서버(Linux)
                         │                             │          └─▶ TlsProbe ──TLS──▶ 대상 서비스 포트
                         ▼                             ├─ Store (SQLite: 서버·최신 결과·호스트 키·사용자·세션)
                    정적 UI(frontend)                  └─ AuditLogWriter (해시 체인 JSONL)
```

| 모듈 | 책임 | 테스트 용이성을 위한 경계 |
|---|---|---|
| `status.py` | 8종 상태 판정·최악 우선 집계·잔여 일수 (순수 함수) | 현재 시각을 인자로 받음 |
| `remote.py` | `CommandPolicy`(고정 읽기 전용 명령 + 경로 화이트리스트), `RemoteExecutor` 인터페이스, `SandboxExecutor`(로컬 디렉터리를 원격 FS 로 사용), `ParamikoExecutor`(ssh-agent, TOFU) | 서비스는 인터페이스에만 의존 |
| `scanner.py` | 후보 경로 확인→파일 읽기→PEM 파싱→체인/리프 판정→TLS 포트 조회→지문 중복 병합→재시도/백오프 | 실행기·프로브·시계·sleep 주입 |
| `cert_parser.py` | `cryptography` 기반 PEM/DER/PKCS#12/JKS 파싱 (개인키 블록은 읽지 않음) | 순수 함수 |
| `store.py` | SQLite 영속화, 호스트 키 저장소(TOFU) | `:memory:` 지원 |
| `auth.py` | 관리자/운영자 RBAC, 비밀번호 정책, 계정 잠금, 유휴 세션, 동시 세션 제한 | 시계 주입 |
| `audit_storage.py` | SHA-256 해시 체인 추가 전용 로그, 변조·삭제 탐지, 스레드 안전 | 임시 디렉터리 |
| `service.py` | 서버 검증·등록, 조회 실행(동시 20), 감사 기록, 현황/CSV | |
| `certpilot_api/app.py` | `create_app()` 팩토리. 모든 엔드포인트 인증·권한 적용, 보안 헤더 | 의존성 주입 |

## 2. 조회 흐름

1. 관리자가 서버 등록(서버명 고유, 계정, 경로·TLS 포트·경고 기준 선택).
2. 조회 요청 → `Scanner.scan(target)`:
   1. **연결**: `PolicyExecutor(executor)` 로 감싼다. DNS/시간 초과만 2회 재시도(1s, 2s 백오프). 인증·호스트 키·권한은 즉시 실패.
   2. **버전**: OpenSSH 7.0 미만이면 조회하지 않고 `UNKNOWN`.
   3. **파일 조회**: 표준 후보 경로 + 서버별 예외 경로를 `ls -1 -p` 로 확인(깊이 2, 최대 200건). 확장자 `.crt .pem .cer .cert`(+ 키스토어 확장자)만, `privkey*`·`*.key` 는 열지 않음. `head -c 262144` 로 읽고 **CERTIFICATE 블록만 남기고 나머지는 즉시 버린다**.
   4. **상태 판정**: 번들에서 리프를 찾아 `classify()`(시간 기준, 경계 포함), 중간CA/루트는 문제 시 `CHAIN_RISK`.
   5. **웹 설정 추출**: nginx/apache 설정의 `ssl_certificate` 경로를 **등록 후보로만 제시**(스캔하지 않음).
   6. **포트 조회**: 등록된 TLS 포트마다 관리 서버가 직접 핸드셰이크(SNI=호스트명). SSH 실패와 무관하게 수행.
   7. **병합·집계**: 같은 (지문, 역할) 은 한 건으로 합치고 발견 위치를 모음. 서버 상태 = 최악 상태.
3. 결과 저장(서버당 최신 1건 + 파일별 SHA-256) → 감사 로그(원문 오류는 여기에만).

## 3. 보안 설계 요점

- **읽기 전용 강제**: 어떤 실행기든 `PolicyExecutor` 를 거친다. 허용 명령 `cat head tail grep ls find sha256sum openssl x509 -noout ...`, 셸 메타문자·`sudo`·`-exec`·쓰기 계열 전부 거부, 경로는 화이트리스트(`..` 이탈 차단).
- **인증**: SSH 는 ssh-agent 키만(패스워드 경로 없음). 호스트 키 TOFU, 변경 시 `HOSTKEY` 로 조회 차단 + `security_hostkey_changed` 감사 이벤트. 재신뢰는 관리자 명시 조작(`hostkey/reset`).
- **원문 비노출(S-8)**: API/UI 는 분류된 원인 6종과 조치 방향만. 원문은 감사 로그 `raw_error`.
- **세션**: 서버측 세션(토큰 해시 저장), HttpOnly·SameSite=Strict 쿠키, 유휴 30분, 동시 3세션, 5회 실패 시 15분 잠금.
- **CSV 인젝션 방지**, 보안 헤더(CSP·nosniff·frame deny), 비루트 컨테이너.

## 4. 설계 결정 (DD)

| ID | 결정 | 근거 |
|---|---|---|
| DD-1 | 포트 기반 조회는 **관리 서버가 직접 TLS 핸드셰이크**, 포트 목록은 **서버 등록 시 지정** | PRD 허용 명령에 `ss`/`openssl s_client` 가 없어 원격 열거 불가. 원격 명령 표면을 늘리지 않음 (권고 3 대응안) |
| DD-2 | 중복 제거 = **(SHA-256 지문, 역할)** 동일 시 병합, 발견 위치 목록 유지 | PRD §3.1.4 "중복 제거 규칙은 설계 과제" |
| DD-3 | 상태 판정 대상이 되는 리프 = 번들 안에서 다른 인증서의 발급자가 아닌 것 | Q-CHAIN |
| DD-4 | 키스토어(PKCS#12/JKS)는 서버 조회에서 **내용 파싱 제외, `UNKNOWN`+사유**. 로컬 CLI 에서만 파싱 | B-4 |
| DD-5 | 감사 로그 = **해시 체인 JSONL(변조 탐지)**. 저장소 수준 불변성(WORM)은 인프라 선택 필요 → OPEN_ITEMS | 권고 1 |
| DD-6 | 단일 프로세스(gunicorn 1 worker × 8 threads) | SQLite·감사 체인 직렬 쓰기, MVP 는 HA 비목표 |
| DD-7 | S-4 해시 대상 = 추출한 CERTIFICATE 블록 원문(개인키 변화는 무관). 이전과 다르면 `UNKNOWN`(확인 필요)+감사 기록 | Q-VERIFY |
