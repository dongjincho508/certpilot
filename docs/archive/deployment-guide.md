> ⚠️ **보관용(폐기)**: 이 문서는 현재 구현과 맞지 않는 계획·주장을 담고 있어 더 이상 기준 문서가 아니다. 현재 기준은 [ARCHITECTURE](../ARCHITECTURE.md) · [TRACEABILITY](../TRACEABILITY.md) · [OPEN_ITEMS](../OPEN_ITEMS.md) 이다.

# CI/CD 및 배포 가이드

CertPilot MVP의 CI/CD 파이프라인과 배포 절차에 대한 가이드입니다.

## 📋 목차

1. [CI/CD 파이프라인](#1-cicd-파이프라인)
2. [테스트 환경 구축](#2-테스트-환경-구축)
3. [배포 절차](#3-배포-절차)
4. [모니터링 및 유지보수](#4-모니터링-및-유지보수)

---

## 1. CI/CD 파이프라인

### 파이프라인 개요

```
push / PR → lint → test → security → build → deploy
  ↓
모든 job 통과 시 파이프라인 성공
                  ↓
main 브랜치 push 시 PyPI 배포 + 테스트 서버 배포
```

### GitHub Actions 구성

**파일**: `.github/workflows/cicd.yml`

### 필요 설정

| 설정 | 위치 | 내용 |
|---|---|---|
| `PYPI_API_TOKEN` | `Settings > Secrets and variables > Actions` | PyPI API 토큰 |
| GitHub PAT | `Settings > Developer settings > Personal access tokens` | 쓰기 권한 토큰 |

### Jobs 설명

#### lint
- 코드 품질 검사
- 도구: flake8, black, isort

#### test
- 유닛 테스트 실행
- 도구: pytest, pytest-cov

#### security
- 보안 검사
- 도구: bandit

#### build
- 패키지 빌드
- 도구: python -m build

#### deploy
- PyPI 배포
- 테스트 서버 SSH 배포

---

## 2. 테스트 환경 구축

### 2.1 VirtualBox 설치

```bash
# 설치 파일 다운로드
cd /tmp
curl -O https://download.virtualbox.org/virtualbox/7.2.22/VirtualBox-7.2.22-162550-Win.exe

# 관리자 권한으로 설치
# - 네트워크 기능 선택 해제 (VM과 호스트 간 네트워크 충돌 방지)
# - 기본 설치 경로: C:\Program Files\Oracle\VirtualBox
```

### 2.2 Ubuntu 22.04 VM 생성

```bash
# Ubuntu ISO 다운로드
curl -O https://cdimage.ubuntu.com/releases/22.04/release/ubuntu-22.04.5-live-server-amd64.iso
sha256sum ubuntu-22.04.5-live-server-amd64.iso

# VirtualBox에서 새 VM 생성
# - 이름: certpilot-test
# - 유형: Linux, Ubuntu (64-bit)
# - 메모리: 4096MB
# - CPU: 2개
# - 디스크: 20GB (VMDK, 동적 할당)
```

### 2.3 VM 네트워크 설정

```bash
# VM 내부 네트워크 설정
ip addr show
# eth0: NAT (인터넷)
# eth1: 호스트 전용 (192.168.56.x)

# 호스트 전용 네트워크 추가 (VirtualBox GUI)
# 1. File > Host Network Manager
# 2. Create
# 3. IPv4 Address: 192.168.56.1
# 4. IPv4 Network Mask: 255.255.255.0
```

### 2.4 게스트 확장 설치

```bash
sudo apt update
sudo apt install -y virtualbox-guest-utils virtualbox-guest-dkms
```

### 2.5 테스트 계정 생성

```bash
# 테스트 사용자 생성
sudo adduser certpilot
sudo usermod -aG sudo certpilot

# SSH 키 생성
sudo su - certpilot
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
chmod 600 ~/.ssh/id_ed25519
chmod 700 ~/.ssh

# SSH 설정
sudo nano /etc/ssh/sshd_config
# PasswordAuthentication no
# PubkeyAuthentication yes
# PermitRootLogin no

sudo systemctl restart sshd
```

### 2.6 테스트 인증서 복사

```bash
# 호스트에서 VM으로 복사
scp ca.crt ca.key test-server.crt test-server.key certpilot@192.168.1.100:/home/certpilot/certs/

# VM에서 권한 설정
sudo mkdir -p /opt/certpilot/certs
sudo chown certpilot:certpilot /opt/certpilot/certs
chmod 600 /home/certpilot/certs/ca.key /home/certpilot/certs/test-server.key
chmod 644 /home/certpilot/certs/ca.crt /home/certpilot/certs/test-server.crt
```

### 2.7 테스트 환경 구성 스크립트

```bash
# setup-test-server.sh
#!/bin/bash
# CertPilot 테스트 서버 설정 스크립트

set -e

echo "=== CertPilot 테스트 서버 설정 ==="

# 1. apt 업데이트
echo "[1/5] apt 업데이트..."
sudo apt update

# 2. SSH 설정
echo "[2/5] SSH 설정..."
sudo systemctl restart sshd

# 3. 인증서 디렉토리 생성
echo "[3/5] 인증서 디렉토리 생성..."
sudo mkdir -p /opt/certpilot/certs

# 4. MVP 테스트 러너 설치 (선택사항)
echo "[4/5] MVP 테스트 러너 설치..."
sudo apt install -y python3 python3-pip
pip3 install --user pytest pytest-cov

# 5. 완료
echo "[5/5] 완료!"
echo "테스트 서버가 준비되었습니다."
```

### 2.8 실행

```bash
chmod +x setup-test-server.sh
sudo ./setup-test-server.sh
```

---

## 3. 배포 절차

### 3.1 개발 환경 배포

```bash
# 1. 패키지 설치
pip install -r requirements.txt

# 2. CLI 설치
pip install -e .

# 3. API 실행
python -m certpilot_api.app --port 5000
```

### 3.2 운영 환경 배포

```bash
# 1. 프로젝트 복제
git clone <repository-url>
cd certpilot

# 2. 가상 환경 생성
python3 -m venv venv
source venv/bin/activate

# 3. 패키지 설치
pip install -r requirements.txt

# 4. systemd 서비스 설치
sudo cp certpilot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable certpilot
sudo systemctl start certpilot

# 5. 상태 확인
sudo systemctl status certpilot
```

### 3.3 Docker 배포

```bash
# 1. 이미지 빌드
docker build -t certpilot-mvp .

# 2. 컨테이너 실행
docker run -d --name certpilot \
  -p 5000:5000 \
  -v /etc/certpilot:/etc/certpilot \
  -v /var/log/certpilot:/var/log/certpilot \
  certpilot-mvp
```

---

## 4. 모니터링 및 유지보수

### 4.1 로그 확인

```bash
# CLI 로그
tail -f /var/log/certpilot/certpilot.log

# 시스템 로그
journalctl -u certpilot -f

# 감사 로그
cat /var/log/certpilot/audit/*.log
```

### 4.2 상태 확인

```bash
# 서비스 상태
systemctl status certpilot

# 리소스 사용량
top -p $(pgrep -f certpilot)

# 디스크 사용량
du -sh /var/log/certpilot
```

### 4.3 백업

```bash
# 데이터베이스 백업
cp /var/lib/certpilot/certpilot.db /backup/certpilot-$(date +%F).db

# 로그 백업
tar czf /backup/certpilot-$(date +%F).tar.gz /var/log/certpilot
```

### 4.4 복구

```bash
# 데이터베이스 복구
cp /backup/certpilot-2026-10-22.db /var/lib/certpilot/certpilot.db

# 서비스 재시작
systemctl restart certpilot
```

---

## 5. 문제 해결

### 5.1 SSH 연결 실패

```bash
# SSH 디버깅
ssh -vvv certpilot@192.168.1.100

# 권한 확인
ls -la ~/.ssh/
chmod 600 ~/.ssh/id_ed25519
```

### 5.2 인증서 파싱 오류

```bash
# 인증서 확인
openssl x509 -in /etc/ssl/certs/cert.pem -noout -subject -dates

# 로그 확인
tail -f /var/log/certpilot/certpilot.log
```

### 5.3 서비스 시작 실패

```bash
# 서비스 상태
systemctl status certpilot

# 로그 확인
journalctl -u certpilot -n 50

# 수동 실행
certpilot --config /etc/certpilot/config.yaml --debug
```

---

## 6. 참고 문서

| 문서 | 설명 |
|---|---|
| [PRD v0.3](PRD_v0.3_draft.md) | 제품 요구사항 문서 |
| [테스트 계획](designs/testing.md) | 테스트 전략 및 절차 |
| [테스트 환경 구축](designs/test-env-build.md) | 테스트 환경 구축 절차 |
| [테스트 실행](designs/mvp-test-execution.md) | MVP 테스트 실행 절차 |
| [보안](designs/threat-model.md) | 보안 위협 및 대응 |

---

## 7. 연락처

- **프로젝트**: CertPilot MVP
- **담당자**: 조동진
- **이메일**: [REDACTED]
- **GitHub**: [dongjincho508/certpilot](https://github.com/dongjincho508/certpilot)

---

> **마지막 업데이트**: 2026-10-23
> **작성자**: CertPilot 프로젝트팀
