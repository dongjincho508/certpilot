# CertPilot MVP 설계 — 착수 문서

## 1. 배경

- PRD v0.3 (승인 완료, 2026-10-21)
- MVP 범위: Linux 서버 + SSH 기반 인증서 조회 및 만료 모니터링
- 관리 규모: 100대 (설계 1,000대)

## 2. 설계 원칙

1. **운영 서버 미사용**: MVP 검증은 별도 격리 테스트 환경에서 수행
2. **최소 권한**: 전용 읽기 전용 계정, sudo 불필요
3. **변경하지 않음**: 인증서·개인키를 변경하지 않음 (조회 중심)
4. **감사 로그 필수**: MVP 필수(P0), WORM, 보존 1년
5. **보안 우선**: 위협 모델 기반 설계, 독립 검토 필수

## 3. 역할별 설계 문서

### 3.1 UI/UX (DESIGN)

- **관리 화면**: 서버별 인증서 상태 목록, 상태별 필터/정렬, 수동 갱신
- **상태 정렬**: 위험 순 (만료 > 체인 위험 > 유효 전 > 만료 임박 > 인증서 미발견 > 확인 필요 > 조회 실패 > 정상)
- **서버 등록 화면**: 서버명·호스트명/IP·SSH 포트·계정·인증 방식·조회 경로·경고 기준
- **인증**: 관리자/운영자 2역할 RBAC
- **감사 로그 화면**: 관리자만 열람, WORM 검증

### 3.2 API/데이터 모델 (BACKEND)

- **REST API** (JSON 응답)
  - `GET /servers` — 서버 목록
  - `POST /servers` — 서버 등록
  - `GET /servers/{id}/certificates` — 서버별 인증서 조회
  - `GET /servers/{id}/certificates/{cert_id}` — 인증서 상세
  - `POST /servers/verify` — 수동 갱신
  - `GET /audit-logs` — 감사 로그 목록 (관리자)
- **데이터 모델**
  - Server (server_id, name, hostname, port, account, ssh_auth, path_whitelist, warn_T, created_at)
  - Certificate (cert_id, server_id, fingerprint_sha256, issuer, subject, san, not_before, not_after, status, chain, created_at, updated_at)
  - AuditLog (log_id, admin_id, server_id, cert_fingerprint, result, viewed_at, stored)

### 3.3 보안 요구사항 (SECURITY)

- **SSH**: 개인키 + ssh-agent, 패스워드 미지원
- **호스트 키**: TOFU + 변경 탐지 시 조회 차단
- **계정**: 전용 읽기 전용 계정, sudo 불필요
- **암호화 저장소**: 자격증명은 별도 암호화 저장소에 보관 + 3개월 회전
- **감사 로그**: WORM, 보존 1년, 관리자만 열람
- **위협 모델**: SSH 세션 가로채기, 인증서 변조, 권한 상승, 감사 로그 조작

### 3.4 PKI 설계 (PKI_ENGINE)

- **인증서 파싱**: PEM, PKCS#12, JKS 지원
- **키스토어 정책**: 인증서만 추출, 개인키는 열거·읽기 안 함
- **발급·갱신**: MVP 제외 (후속 단계)
- **상태 머신**: 정상 → 만료 임박 → 만료 (독립)
- **단일 조회 세션**: 인증 성공까지 세션 수립 기준

### 3.5 인프라 연동 (INFRA_CONNECTOR)

- **SSH**: OpenSSH 7.0 이상, 기본 포트 22, 비표준 포트 등록 시 필수
- **Windows**: 후속 단계 (MVP 제외)
- **네트워크/보안 장비**: 후속 단계 (MVP 제외)
- **경로 화이트리스트**: 허용된 디렉터리·패턴 안에서만 조회

### 3.6 테스트 전략 (QA_SRE)

- **격리 테스트 환경**: 신규 VM/컨테이너 기반
- **인증서 세트**: 유효/임박/만료/미발견/확인 필요 각 1건 이상
- **KPI**: 조회 성공률 ≥99%, 만료 누락 0, 평균 완료 ≤10분
- **테스트 범위**: 정상/실패/상태별 샘플

### 3.7 독립 검토 (INDEPENDENT_REVIEWER)

- PRD v0.3 정정 사항 (B-1~B-6, H-1~H-10, Q-AUDIT/관리 화면·인증) 검토
- 보안 설계 확인
- 인스턴트 착수: 독립 검토 문서 작성

## 4. 후속 단계

- MVP 완료 정의 (AC-1 ~ AC-10) 검증
- 릴리스 게이트: 결정 잔여 0, AC 전항 통과, 역할 검토 + 용어집 동기화
- 보안·아키텍처 항목: 독립 검토 후 오너 승인
