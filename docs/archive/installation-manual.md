> ⚠️ **보관용(폐기)**: 이 문서는 현재 구현과 맞지 않는 계획·주장을 담고 있어 더 이상 기준 문서가 아니다. 현재 기준은 [ARCHITECTURE](../ARCHITECTURE.md) · [TRACEABILITY](../TRACEABILITY.md) · [OPEN_ITEMS](../OPEN_ITEMS.md) 이다.

# CertPilot MVP - 설치 엔지니어용 설치 매뉴얼

> **버전**: 1.0  
> **작성일**: 2026-10-23  
> **작성자**: CertPilot 프로젝트팀  
> **적용 버전**: CertPilot MVP 1.0  
> **대상**: 설치 엔지니어, 운영 엔지니어

---

## 📋 문서 개요

본 문서는 CertPilot MVP (Corporate SSL/TLS Certificate Inspection Tool) 를 설치 엔지니어가 실제 운영 환경에 설치하고 구성할 수 있도록 작성된 설치 매뉴얼입니다.

### 변경 로그

| 버전 | 날짜 | 변경 내용 | 작성자 |
|---|---|---|---|
| 1.0 | 2026-10-23 | 최초 작성 | CertPilot 프로젝트팀 |
| - | - | 변경 예정: 업데이트 주기 | - |

---

## 1. 개요

### 1.1 목적

CertPilot MVP 는 기업/조직의 Linux/Unix, Windows, 네트워크 및 보안 장비에 설치된 SSL/TLS 인증서를 검사하고 관리하기 위한 MVP(Minimum Viable Product) 도구입니다.

### 1.2 대상 시스템

- **운영체제**: Linux (Ubuntu 22.04 LTS 이상 권장), Windows 10/11
- **관리 대상**: Linux/Unix 서버, Windows 서버, 네트워크 장비
- **인증기관**: 공인 CA, 사내 CA
- **연결 방식**: SSH, 전용 에이전트, 장비 API
- **관리 규모**: 100~1,000대

### 1.3 설치 방식

- **권장 방식**: Linux 서버 수동 설치
- **대안 방식**: Docker 컨테이너 (운영 환경 권장)
- **지원 방식**: systemd 서비스 (Linux)

---

## 2. 시스템 요구사항

### 2.1 설치 서버 요구사항

| 항목 | 요구사항 | 비고 |
|---|---|---|
| **CPU** | 2코어 이상 | |
| **RAM** | 512MB 이상 | |
| **디스크** | 10GB 이상 (SSD 권장) | |
| **운영체제** | Ubuntu 22.04 LTS 이상 | Windows 10/11 지원 (제한적) |
| **가상화** | VirtualBox, Docker, WSL2 중 하나 | |
| **네트워크** | SSH 포트 (22) 오픈 | 관리 대상 서버 연결용 |
| **포트** | 8080 (API), 22 (SSH) | |

### 2.2 관리 대상 서버 요구사항

| 항목 | 요구사항 | 비고 |
|---|---|---|
| **운영체제** | Linux (Ubuntu, CentOS, RHEL, Debian) | |
| **권한** | SSH 접속 계정 (sudo 권한 불필요) | 읽기 전용 |
| **SSH** | SSH 서버 실행 중 | 포트 22 |
| **인증** | SSH 키 기반 (권장) | 또는 비밀번호 |

### 2.3 테스트 환경 요구사항

| 항목 | 요구사항 |
|---|---|
| **운영체제** | Ubuntu 20.04 이상 |
| **CPU** | 2코어 |
| **RAM** | 2GB |
| **디스크** | 20GB |
| **네트워크** | 호스트 전용 네트워크 (192.168.56.0/24) |

---

## 3. 설치 전 준비

### 3.1 사전 확인 사항

1. **운영체제 확인**
   ```bash
   uname -a
   cat /etc/os-release
   ```

2. **Python 버전 확인**
   ```bash
   python3 --version
   # Python 3.11 이상 필요
   ```

3. **권한 확인**
   ```bash
   whoami
   # 관리자 권한 필요 (sudo)
   ```

4. **필수 패키지 설치**
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip python3-venv git
   ```

5. **외부 서비스 접근 확인**
   ```bash
   # GitHub 저장소 접근 확인
   git clone https://github.com/dongjincho508/certpilot.git
   
   # PyPI 접근 확인 (필요 시)
   pip install flask
   ```

### 3.2 환경 변수 설정

```bash
# 설치 경로
export CERTPILOT_HOME=/opt/certpilot

# 데이터 디렉토리
export CERTPILOT_DATA_DIR=/var/lib/certpilot

# 로그 디렉토리
export CERTPILOT_LOG_DIR=/var/log/certpilot

# API 포트
export CERTPILOT_API_PORT=8080
```

---

## 4. 설치 절차

### 4.1 저장소 복제

```bash
# 홈 디렉토리로 이동
cd /opt

# 저장소 복제
git clone https://github.com/dongjincho508/certpilot.git certpilot

# 또는 기존 저장소 사용
cd certpilot
```

### 4.2 가상환경 생성 (권장)

```bash
# 가상환경 생성
python3 -m venv venv

# 가상환경 활성화
source venv/bin/activate

# 패키지 설치
pip install --upgrade pip
pip install -r requirements.txt
```

### 4.3 인증서 저장 디렉토리 생성

```bash
# 인증서 데이터 디렉토리 생성
sudo mkdir -p /var/lib/certpilot/certs
sudo chmod 755 /var/lib/certpilot/certs

# 로그 디렉토리 생성
sudo mkdir -p /var/log/certpilot
sudo chmod 755 /var/log/certpilot

# 설정 파일 디렉토리 생성
sudo mkdir -p /etc/certpilot
sudo chmod 755 /etc/certpilot
```

### 4.4 의존성 패키지 설치

```bash
# Python 패키지 설치
pip install -r requirements.txt

# 필수 시스템 패키지 (Linux)
sudo apt install -y python3-paramiko
```

---

## 5. 구성 설정

### 5.1 기본 설정 파일 생성

```bash
# 설정 파일 템플릿 복사
cp /opt/certpilot/certpilot_api/config.yaml.example /etc/certpilot/config.yaml

# 또는 직접 생성
cat > /etc/certpilot/config.yaml << 'EOF'
server:
  host: 0.0.0.0
  port: 8080

auth:
  mode: disabled  # 운영 환경에서는 활성화 권장
  admin_user: admin

database:
  path: /var/lib/certpilot/certpilot.db
  pool_size: 5

audit:
  log_dir: /var/log/certpilot/audit
  retention_days: 365
  hash_tree: true  # SHA-256 해시 트리

servers:
  # Linux 서버 설정
  - hostname: prod-server-01
    ip_address: 192.168.1.100
    os_type: linux
    os_version: Ubuntu 22.04
    ssh_port: 22
    ssh_username: certpilot
    ssh_key_path: /etc/certpilot/keys/server-01.pem

# 테스트 환경 설정
test:
  enabled: true
  certs_dir: /tmp/certpilot-test/certs
EOF
```

### 5.2 키 관리

```bash
# 테스트 키 생성 (테스트 환경)
cd /etc/certpilot/keys
ssh-keygen -t ed25519 -f server-01.pem -N ""

# 운영용 키는 안전한 위치에 저장 (접근 권한 600)
sudo chmod 600 /etc/certpilot/keys/server-01.pem
```

### 5.3 환경 변수 설정

```bash
# ~/.bashrc 에 추가
export CERTPILOT_HOME=/opt/certpilot
export CERTPILOT_DATA_DIR=/var/lib/certpilot
export CERTPILOT_LOG_DIR=/var/log/certpilot
export CERTPILOT_API_PORT=8080

# 적용
source ~/.bashrc
```

---

## 6. 실행 방법

### 6.1 개발 모드 실행

```bash
# 가상환경 활성화
source venv/bin/activate

# 프로젝트 디렉토리로 이동
cd /opt/certpilot

# API 서버 실행
python -m certpilot_api.app --host 0.0.0.0 --port 8080

# CLI 도구 실행
python -m certpilot_cli.cli --help
```

### 6.2 systemd 서비스 설치

```bash
# 서비스 파일 복사
sudo cp /opt/certpilot/certpilot_api/certpilot.service /etc/systemd/system/

# 서비스 활성화 및 시작
sudo systemctl daemon-reload
sudo systemctl enable certpilot
sudo systemctl start certpilot

# 상태 확인
sudo systemctl status certpilot

# 로그 확인
sudo journalctl -u certpilot -f
```

### 6.3 Docker 실행

```bash
# Docker 이미지 빌드
docker build -t certpilot-mvp .

# 컨테이너 실행
docker run -d --name certpilot \
  -p 8080:8080 \
  -v /etc/certpilot:/etc/certpilot \
  -v /var/lib/certpilot:/var/lib/certpilot \
  -v /var/log/certpilot:/var/log/certpilot \
  certpilot-mvp

# 로그 확인
docker logs -f certpilot
```

---

## 7. 테스트 환경 구축

### 7.1 격리된 테스트 환경 구성

```bash
# 테스트 디렉토리 생성
mkdir -p /tmp/certpilot-test
cd /tmp/certpilot-test

# 테스트 인증서 생성
# (별도 스크립트: make_expired_certs.py 사용)
python3 make_expired_certs.py
```

### 7.2 테스트 환경 파일

| 파일 | 설명 |
|---|---|
| `ca.crt` | 테스트 CA 인증서 |
| `ca.key` | 테스트 CA 키 |
| `test-server.crt` | 유효 인증서 (30일) |
| `test-server-expired-30.crt` | 만료 임박 (30일 전) |
| `test-server-expired-60.crt` | 만료 (60일 전) |
| `corrupt.crt` | 손상된 인증서 |
| `missing/test.crt` | 없는 인증서 경로 |

### 7.3 테스트 데이터 디렉토리 구조

```bash
/tmp/certpilot-test/
├── certs/
│   ├── ca.crt
│   ├── ca.key
│   ├── test-server.crt
│   ├── test-server-expired-30.crt
│   ├── test-server-expired-60.crt
│   ├── corrupt.crt
│   └── missing/
│       └── test.crt
└── make_expired_certs.py
```

---

## 8. MVP 검증 테스트

### 8.1 테스트 실행

```bash
# 테스트 러너 실행
python /tmp/certpilot-test/mvp_test_runner.py
```

### 8.2 테스트 결과 예시

```
=== MVP 테스트 결과 ===
총 테스트: 10개
통과: 10개
실패: 0개
통과율: 100%

[✅ PASS] AC-1: 정상 인증서 정보 조회
[✅ PASS] AC-2: 만료 임박 인증서 테스트
[✅ PASS] AC-3: 만료 인증서 테스트
[✅ PASS] AC-4: 깨진 인증서 파일 테스트
[✅ PASS] AC-5: 없는 인증서 파일 테스트
[✅ PASS] AC-6: 만료 임박/만료 분류 테스트
[✅ PASS] AC-7: 다중 인증서 조회 테스트
[✅ PASS] AC-8: 인증서 체인 검증 테스트
[✅ PASS] AC-9: 오류 처리 테스트
[✅ PASS] AC-10: 감사 로그 테스트
```

### 8.3 결과 확인

```
테스트 결과가 저장되었습니다: /tmp/certpilot-test/test-results.json
```

---

## 9. 문제 해결

### 9.1 일반적인 문제

| 증상 | 원인 | 해결 방법 |
|---|---|---|
| **포트 8080 사용 중** | 다른 서비스가 포트를 사용 중 | `sudo netstat -tlnp | grep 8080` 후 다른 포트로 변경 |
| **SSH 연결 실패** | SSH 서버 미실행 또는 권한 부족 | `sudo systemctl status ssh` 확인 |
| **권한 오류** | 디렉토리 권한 부족 | `chmod 755` 또는 `chmod 700` 적용 |
| **인증서 파싱 실패** | 인증서 형식 오류 | `openssl x509 -in cert.crt -noout -text` 확인 |
| **Python 모듈 없음** | 의존성 패키지 미설치 | `pip install -r requirements.txt` |

### 9.2 로그 확인

```bash
# 서비스 로그
sudo journalctl -u certpilot -f

# 로그 파일
tail -f /var/log/certpilot/certpilot.log
tail -f /var/log/certpilot/error.log

# 감사 로그
ls -la /var/log/certpilot/audit/
```

### 9.3 복구 절차

```bash
# 서비스 중지
sudo systemctl stop certpilot

# 데이터베이스 백업
cp /var/lib/certpilot/certpilot.db /backup/certpilot-$(date +%F).db

# 서비스 재시작
sudo systemctl start certpilot

# 서비스 상태 확인
sudo systemctl status certpilot
```

---

## 10. 운영 및 유지보수

### 10.1 백업

```bash
# 데이터베이스 백업
sqlite3 /var/lib/certpilot/certpilot.db ".backup '/backup/certpilot-$(date +%F).db'"

# 로그 백업
tar czf /backup/certpilot-$(date +%F).tar.gz /var/log/certpilot

# 전체 백업
tar czf /backup/certpilot-full-$(date +%F).tar.gz \
  -C /var/lib/certpilot ./certpilot.db \
  -C /var/log/certpilot . \
  -C /etc/certpilot .
```

### 10.2 복구

```bash
# 서비스 중지
sudo systemctl stop certpilot

# 백업 복원
cp /backup/certpilot-20261023.db /var/lib/certpilot/certpilot.db

# 서비스 재시작
sudo systemctl start certpilot
```

### 10.3 업데이트

```bash
# 저장소 업데이트
cd /opt/certpilot
git pull origin main

# 의존성 업데이트
pip install -r requirements.txt

# 서비스 재시작
sudo systemctl restart certpilot
```

### 10.4 모니터링

```bash
# 서비스 상태
systemctl status certpilot

# 로그 모니터링
tail -f /var/log/certpilot/certpilot.log

# 리소스 사용량
top -p $(pgrep -f certpilot)
```

---

## 11. 보안 지침

### 11.1 보안 권장 사항

1. **운영 환경**: 인증 모드 활성화 (admin_user, password)
2. **키 관리**: SSH 키는 600 권한으로 저장
3. **감사 로그**: WORM 저장, 365일 보존
4. **접근 제어**: 관리자 계정 분리
5. **네트워크**: 운영 서버에서는 8080 포트를 외부에 노출하지 않기

### 11.2 보안 체크리스트

- [ ] 운영 환경 인증 활성화
- [ ] SSH 키 권한 600 설정
- [ ] 감사 로그 WORM 설정
- [ ] 백업 암호화
- [ ] 방화벽 설정 (8080 포트 제한)

---

## 11. 마이그레이션

### 11.1 이전 버전 데이터 마이그레이션

```bash
# 기존 데이터 백업
cp /var/lib/certpilot/certpilot.db /backup/certpilot-old.db

# 새 버전 설치
cd /opt/certpilot
git pull

# 데이터베이스 마이그레이션 (필요시)
python -m certpilot_api.migrate

# 서비스 재시작
sudo systemctl restart certpilot
```

---

## 12. 연락처

| 항목 | 내용 |
|---|---|
| **프로젝트** | CertPilot MVP |
| **담당자** | 조동진 |
| **이메일** | [REDACTED] |
| **GitHub** | https://github.com/dongjincho508/certpilot |

---

## 13. 부록

### 13.1 명령어 참조

```bash
# CLI 도움말
certpilot --help

# API 헬스 체크
curl http://localhost:8080/health

# 데이터베이스 백업
sqlite3 /var/lib/certpilot/certpilot.db ".backup '/backup/certpilot.db'"

# 서비스 상태 확인
systemctl status certpilot
```

### 13.2 유용한 명령어

```bash
# SSH 연결 테스트
ssh -i /etc/certpilot/keys/server-01.pem certpilot@192.168.1.100

# 포트 확인
ss -tlnp | grep 8080

# 서비스 재시작
systemctl restart certpilot

# 로그 순환 재설정
systemctl reload certpilot
```

---

## 14. 프론트엔드 설치 (UI/UX)

### 14.1 프론트엔드 구성 파일

| 파일 | 설명 |
|---|---|
| `frontend/templates/index.html` | 관리자 대시보드 메인 화면 |
| `frontend/css/style.css` | 그라디언트 스타일 CSS |
| `frontend/js/app.js` | API 연동 및 UI 로직 |

### 14.2 프론트엔드 특징

| 항목 | 설명 |
|---|---|
| **디자인** | 그라디언트 기반 현대식 UI |
| **반응형** | 모바일/데스크톱 대응 |
| **기능** | 대시보드, 서버 목록, 인증서 조회, 감사 로그, 서버 등록 |

### 14.3 프론트엔드 실행 방법

```bash
# 1. 가상환경 활성화
source venv/bin/activate

# 2. API 서버 실행 (port 8080)
python -m certpilot_api.app

# 3. 브라우저에서 접속
# http://localhost:8080
```

### 14.4 프론트엔드 파일 구조

```bash
frontend/
├── templates/
│   └── index.html           # 관리자 대시보드 화면
├── css/
│   └── style.css            # 그라디언트 스타일
└── js/
    └── app.js               # API 연동 및 UI 로직
```

### 14.5 프론트엔드 기능

| 기능 | 설명 |
|---|---|
| 대시보드 | 인증서 상태 요약 (정상/만료 임박/만료/기타) |
| 서버 목록 | 서버별 인증서 현황 테이블 |
| 서버 등록 | SSH 인증으로 서버 등록 |
| 감사 로그 | WORM 감사 로그 조회 |

---

## 15. 설치 엔지니어 체크리스트

### 설치 전 확인 사항
- [ ] 운영체제 확인 (Ubuntu 22.04 LTS 이상)
- [ ] Python 3.11 이상 설치
- [ ] 관리자 권한 확인 (sudo)
- [ ] 필수 패키지 설치 (python3, python3-pip, python3-venv, git)

### 설치 실행
- [ ] 저장소 복제 (git clone)
- [ ] 가상환경 생성 (python3 -m venv venv)
- [ ] 가상환경 활성화 (source venv/bin/activate)
- [ ] 패키지 설치 (pip install -r requirements.txt)
- [ ] 인증서 저장소 생성 (/var/lib/certpilot/certs)
- [ ] 로그 저장소 생성 (/var/log/certpilot)
- [ ] 설정 파일 생성 (/etc/certpilot/config.yaml)

### 설치 검증
- [ ] API 서버 실행 (http://localhost:8080/health)
- [ ] 프론트엔드 접속 (http://localhost:8080)
- [ ] 서버 목록 조회
- [ ] 인증서 조회
- [ ] 감사 로그 조회

---

## 16. 업데이트 이력

| 날짜 | 버전 | 변경 내용 | 작성자 |
|---|---|---|---|
| 2026-10-23 | 1.0 | 최초 작성 | CertPilot 프로젝트팀 |
| - | - | 프론트엔드 설치 매뉴얼 추가 | CertPilot 프로젝트팀 |

## 14. 업데이트 이력

| 날짜 | 버전 | 변경 내용 | 작성자 |
|---|---|---|---|
| 2026-10-23 | 1.0 | 최초 작성 | CertPilot 프로젝트팀 |

---

## 15. 승인 확인

| 확인 항목 | 확인자 | 서명 |
|---|---|---|
| 문서 완결성 | | |
| 설치 절차 검증 | | |
| 보안 검토 | | |

---

## 부록 A: 문제 해결 체크리스트

| 단계 | 확인 사항 | 결과 |
|---|---|---|
| 1 | Python 버전 확인 | |
| 2 | 권한 확인 (sudo) | |
| 3 | 필수 패키지 설치 | |
| 4 | 포트 확인 (8080) | |
| 5 | SSH 연결 테스트 | |
| 6 | 인증서 파일 존재 확인 | |
| 7 | 서비스 상태 확인 | |
| 8 | 로그 확인 | |

---

## 부록 B: 참고 문서

- [PRD v0.3](PRD_v0.3_draft.md)
- [설치 매뉴얼](installation-manual.md)
- [테스트 실행 방법](mvp_test_execution.md)
- [설치 환경 구축](test-env-build.md)

---

> **마지막 업데이트**: 2026-10-23  
> **작성자**: CertPilot 프로젝트팀  
> **승인**: 조동진 (owner)
