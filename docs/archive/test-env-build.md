> ⚠️ **보관용(폐기)**: 이 문서는 현재 구현과 맞지 않는 계획·주장을 담고 있어 더 이상 기준 문서가 아니다. 현재 기준은 [ARCHITECTURE](../ARCHITECTURE.md) · [TRACEABILITY](../TRACEABILITY.md) · [OPEN_ITEMS](../OPEN_ITEMS.md) 이다.

# 격리 테스트 환경 구축 절차

**대상**: CertPilot MVP 검증 (릴리스 승인 완료)
**작성일**: 2026-10-21
**작성자**: QA_SRE (Owner 승인 후)

> 본 문서는 MVP 검증을 위한 격리 테스트 환경 구축 절차입니다.
> 운영 서버와 완전히 격리된 환경에서만 수행합니다.

---

## 1. 사전 준비

### 1.1 필요 자원

| 자원 | 사양 | 비고 |
|---|---|---|
| 테스트 서버 | 물리/가상 머신 1대 | 운영 서버와 네트워크 분리 |
| 가상화 | VMware/Proxmox/KVM/Local VM | 호스트별 상이 |
| OS | Linux (Ubuntu 20.04+ / CentOS 8+) | SSH 서버 설치 가능 |
| RAM | 4GB 이상 | 인증서 파싱/검색 용도 |
| 디스크 | 20GB 이상 | 인증서/로그 저장 |
| 네트워크 | 관리망 분리 (전용 VLAN 권장) | 운영망 접근 차단 |

### 1.2 준비물

- 테스트용 SSH 공개/개인키 (운영 인증서와 무관)
- 테스트 인증서 세트 생성용 도구 (OpenSSL, keytool)
- VM 프로비저닝 도구 (Vagrant, Ansible, Packer)

---

## 2. 테스트 서버 구축 절차

### 2.1 VM 생성

1. 하이퍼바이저에서 VM 1대 생성
   - CPU: 2 vCPU
   - RAM: 4GB
   - Disk: 20GB (SSD 권장)
   - OS: Ubuntu 20.04 LTS 또는 CentOS 8
2. 네트워크 구성
   - 관리망 분리 (전용 VLAN 또는 호스트 전용)
   - 관리 서버와의 통신만 허용, 외부 접근 차단
   - 포트 22(SSH), 80(HTTP) 외 모든 포트 차단

### 2.2 OS 설치 및 초기 설정

1. OS 설치 (최소 설치 + SSH 서버 + curl/wget)
2. 호스트명 설정 (예: `test-cert-server-01.certpilot.local`)
3. 타임존 및 NTP 설정 (UTC)
4. 방화벽 설정 (Firewalld/ufw)
   - SSH(22) 포트만 허용
   - 기타 포트 모두 차단
5. SSH 서버 설정 확인
   - `sshd -t` (설정 검증)
   - `systemctl enable --now sshd` (자동 시작)

### 2.3 테스트 계정 생성

1. 전용 테스트 계정 생성
   ```bash
   # 예: certpilot-test
   sudo useradd -m -s /bin/bash certpilot-test
   ```
2. sudo 권한 없음 (조회 전용)
   - `/etc/sudoers.d/certpilot-test`에 `certpilot-test ALL=(ALL) NOPASSWD: ALL` 설정은 하지 않음
   - 조회용 최소 권한만 부여 (또는 관리자 계정만 조회)
3. SSH 키 기반 인증 설정
   - 운영자 공개키를 `certpilot-test`의 `~/.ssh/authorized_keys`에 추가
   - 비밀번호 로그인 비활성화
4. 접속 테스트
   ```bash
   ssh -i <운영자 개인키> certpilot-test@<테스트 서버 IP>
   ```

---

## 3. 테스트 인증서 세트 준비

### 3.1 합성 인증서 생성

> 운영 인증서/기존 인증서를 테스트에 재사용하지 않는다.  
> 아래 절차를 따라 테스트용 인증서를 생성한다.

#### 3.1.1 테스트용 CA 생성 (선택, JKS/PKCS#12 검증 시 필요)

```bash
# 테스트용 CA 생성
mkdir -p /opt/certpilot/test/ca
cd /opt/certpilot/test/ca

# CA 개인키 생성
openssl genrsa -out ca.key 2048
# CA 인증서 생성
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=Test Certification Authority"
```

#### 3.1.2 테스트 인증서 생성 (PEM 형식)

```bash
# 테스트 서버용 인증서 생성
mkdir -p /opt/certpilot/test/certs

# 서버 개인키 생성
openssl genrsa -out test-server.key 2048

# 인증서 서명 요청(CSR) 생성
openssl req -new -key test-server.key -out test-server.csr \
  -subj "/CN=test-cert-server.local/O=CertPilot/C=KR"

# CA로 서명
openssl x509 -req -in test-server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out test-server.crt -days 365

# 검증용 인증서 (만료 임박, 만료 10일 전)
openssl x509 -req -in test-server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out test-server-expired.crt -days 355  # 10일 남김
# (실제로는 -days 355 로 생성 후 10일 남김)

# 만료 인증서 (이미 만료)
openssl x509 -req -in test-server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out test-server-expired.crt -days 300  # 60일 전 만료
```

#### 3.1.3 테스트 인증서 생성 (PKCS#12)

```bash
# PEM→PKCS#12 변환
openssl pkcs12 -export -out test-server.pfx \
  -inkey test-server.key -in test-server.crt \
  -certfile ca.crt -passout pass:testpass123

# JKS (keytool 필요)
keytool -importkeystore \
  -srckeystore test-server.pfx \
  -srcstoretype PKCS12 \
  -destkeystore test-server.jks \
  -srcstorepass testpass123 \
  -deststorepass testpass123
```

### 3.2 테스트 데이터 준비

| 상태 | 파일 | 내용 |
|---|---|---|
| 정상 | `test-server.crt` | 유효 (30일+) |
| 만료 임박 | `test-server-expired.crt` | 30일 남김 |
| 만료 | `test-server-expired-60.crt` | 60일 전 만료 |
| 미발견 | `nonexistent.crt` | 경로 존재하나 없음 |
| 확인 필요 | `corrupt.crt` | 깨진 파일 |
| 강제 실패 | `forbidden.txt` | 조회 금지 경로 테스트 |

---

## 4. 테스트 환경 검증

### 4.1 사전 점검 (Pre-flight Check)

```bash
# 1. SSH 접속
ssh -i <운영자 키> certpilot-test@<테스트 서버 IP> 'echo OK'

# 2. 테스트 인증서 존재 확인
ls -la /opt/certpilot/test/certs/

# 3. 방화벽 확인
ufw status | grep "22/tcp"

# 4. SSH 서버 실행 확인
systemctl is-active ssh
```

### 4.2 연결 검증

| 검증 항목 | 방법 | 성공 기준 |
|---|---|---|
| SSH 연결 | `ssh certpilot-test@<IP>` | 접속 성공 |
| TofU 초기 신뢰 | 첫 접속 시 호스트 키 수락 | 경고 없음 |
| 호스트 키 변경 | 두 번째 접속 시 변경 감지 | 조회 차단 확인 |
| SELinux/AppArmor | `sestatus`/`aa-status` | 조회 명령어만 허용 |

---

## 5. 보안·아키텍처 최종 승인 (완료 확인)

| 권고 | 반영 | 확인 |
|---|---|---|
| WORM 구현 (불변 저장소) | ✅ | PRD v0.3 §3.1.4 |
| SSH 허용 명령 | ✅ | PRD v0.3 §3.1.2 |
| 포트 기반 조회 | ✅ | PRD v0.3 §3.1.4 |
| MVP 검증 | ✅ | 절차 문서화 완료 |

---

## 6. 문서화

| 문서 | 경로 |
|---|---|
| 보안·아키텍처 최종 승인 | `plans/certpilot/OWNER_DECISIONS.md` §J |
| MVP 검증 절차 계획 | `designs/mvp-verification-plan.md` |
| 테스트 인증서 세트 | `/opt/certpilot/test/certs/` |

---

## 7. 주의사항

- **운영 서버 미사용**: MVP 검증은 격리 환경에서만 수행
- **운영 인증서 재사용 금지**: 테스트 인증서는 합성 생성
- **개인키 관리**: 테스트용 개인키는 디스크에 저장하지 않음
- **로그 관리**: 검증 과정에서 발생하는 로그는 모니터링 대상
- **환경 초기화**: MVP 검증 완료 후 테스트 환경은 초기화

---

## 8. 다음 단계

| 단계 | 내용 | 담당 |
|---|---|---|
| 1단계 | 격리 테스트 환경 구축 | QA_SRE |
| 2단계 | 테스트 인증서 세트 준비 | PKI_ENGINE |
| 3단계 | 테스트 실행 (AC-1~AC-10) | QA_SRE |
| 4단계 | 결과 검증 및 리포트 | QA_SRE |
| 5단계 | 보안·아키텍처 최종 승인 | OWNER + SECURITY |
| 6단계 | 프로덕션 전환 | OWNER + 팀 |

---

> 본 문서는 QA_SRE가 작성했으며, 각 단계는 OWNERS와 협의하여 진행합니다.
