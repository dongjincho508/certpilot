# 감시 서버 구축 가이드 — Rocky Linux 10.x (설치부터 배포·운영까지)

대상: [monitoring/](../../monitoring/README.md) 스택(ssl_exporter · Prometheus · Alertmanager · Grafana)을 교내 VM 1대에 올린다.
검증 범위: Docker 공식 저장소의 Rocky/RHEL 10 경로와 사용 이미지 4종(태그)이 **실재함을 확인**했다. 이 가이드의 OS 명령 자체는 Rocky 10 에서 **직접 실행해 보지 못했다**(RHEL 계열 표준 절차). 막히면 해당 단계의 출력을 알려 달라.

## 0. 준비물 (설치 전에 전산실과 정리)

| 항목 | 내용 |
|---|---|
| VM 사양 | 2 vCPU / 4GB RAM / 디스크 40GB 이상(대상 50대 이하 기준, 추정치) |
| **CPU 모델(중요)** | Rocky 10 은 **x86-64-v3(AVX2 등) CPU 를 요구**한다. VMware/KVM 에서 "호환 CPU 모델(구형)"로 만든 VM 은 부팅·설치가 안 될 수 있으니 호스트 CPU 통과(host-passthrough) 또는 v3 이상 모델로 생성 |
| 네트워크 | 고정 IP, 호스트명(예: `monitor.univ.example`), 내부 DNS 등록 |
| 방화벽 요청(VM 기준) | **나가는**: 감시 대상 서버들의 TLS 포트(443, 8443 …), 메일 릴레이(SMTP 25/587), NTP, DNS, (설치 중) `download.docker.com`·`registry-1.docker.io`·`hub.docker.com`·`github.com`·Rocky 미러 / **들어오는**: 관리자 PC → 443(HTTPS), 22(SSH) |
| 메일 | 교내 SMTP 릴레이 주소·포트·인증 여부, 발신 주소, 알림 수신 주소 |
| 감시 대상 목록 | `호스트명:포트`, 그룹, 서비스, OS, 담당(CSV 로 정리) |
| 인터넷이 막혀 있다면 | 교내 프록시 주소(3·4단계의 프록시 설정 참고) 또는 이미지 반입(5-5) |

## 1. Rocky Linux 10 설치
1. Rocky 10 ISO(Minimal 또는 DVD) 로 부팅 → 언어 한국어/영어, 키보드, 시간대 `Asia/Seoul`
2. 소프트웨어 선택: **최소 설치(Minimal Install)** (GUI 불필요)
3. 파티션: LVM 권장. `/` 20GB 이상, **`/var` 20GB 이상**(Docker 이미지·볼륨이 `/var/lib/docker` 에 쌓임)
4. 네트워크: 고정 IP·게이트웨이·DNS(교내 DNS)·호스트명 설정
5. 계정: root 는 비밀번호 로그인 SSH 비활성 전제로 설정하고, **일반 관리자 계정(wheel 그룹)** 을 만든다
6. 설치 완료 후 재부팅 → 관리자 계정으로 SSH 접속

## 2. 초기 설정
```bash
sudo dnf -y update
```
```bash
sudo hostnamectl set-hostname monitor.univ.example
```
```bash
sudo timedatectl set-timezone Asia/Seoul
```
**시각 동기화(필수)**: 만료 계산은 서버 시각을 쓰므로 틀어지면 알림이 틀린다.
```bash
sudo systemctl enable --now chronyd
```
```bash
chronyc tracking
```
(`System time` 오차가 1초 이내여야 한다. 교내 NTP 가 있으면 `/etc/chrony.conf` 의 `pool` 을 교내 NTP 로 교체)

**SELinux 는 enforcing 을 유지한다**(끄지 않는다). 확인:
```bash
getenforce
```
**방화벽(firewalld)**: 기본 활성. 지금은 SSH 만 허용 상태 확인:
```bash
sudo firewall-cmd --list-all
```
**SSH 보안**(`/etc/ssh/sshd_config.d/10-hardening.conf` 신규 작성)
```
PermitRootLogin no
PasswordAuthentication no     # 키 등록 후에만 적용
```
```bash
sudo systemctl reload sshd
```
**보안 업데이트 자동화(선택)**
```bash
sudo dnf -y install dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer
```
교내 프록시가 필요하면 `/etc/dnf/dnf.conf` 에 `proxy=http://프록시:포트` 추가.

## 3. Docker 설치 (Docker 공식 저장소)
Docker 공식 저장소에 CentOS/RHEL **10** 경로가 있음을 확인했다(`.../linux/centos/10/x86_64/stable`). Rocky 는 CentOS 저장소 파일을 쓴다.
```bash
sudo dnf -y install dnf-plugins-core
```
```bash
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
```
```bash
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
```bash
sudo systemctl enable --now docker
```
확인:
```bash
sudo docker run --rm hello-world
```
```bash
docker compose version
```
- 관리자 계정으로 `sudo` 없이 쓰려면 `sudo usermod -aG docker <계정>` 후 재로그인. 단, **docker 그룹은 root 와 동급 권한**이므로 필요한 관리자에게만 부여한다.
- 로그 용량 제한: `/etc/docker/daemon.json`
  ```json
  { "log-driver": "json-file", "log-opts": { "max-size": "20m", "max-file": "5" } }
  ```
  적용: `sudo systemctl restart docker`
- 교내 프록시가 필요하면 `/etc/systemd/system/docker.service.d/proxy.conf` 에 `[Service]` + `Environment="HTTPS_PROXY=http://프록시:포트"` `Environment="NO_PROXY=localhost,127.0.0.1"` → `sudo systemctl daemon-reload && sudo systemctl restart docker`

(대안) Docker 대신 **Podman**(AppStream 기본 제공)을 쓸 수도 있으나, 이 스택은 Docker Compose 기준으로 검증했다. Podman 을 쓰면 `podman compose` 제공자 설치와 동작 확인이 추가로 필요하다.

## 4. 코드 배치
```bash
sudo dnf -y install git
```
```bash
sudo mkdir -p /opt/cert-monitor && sudo chown $USER /opt/cert-monitor
```
```bash
git clone https://github.com/dongjincho508/certpilot.git /opt/cert-monitor/src
```
```bash
cd /opt/cert-monitor/src/monitoring
```
(GitHub 접속이 막혀 있으면 PC 에서 저장소를 압축해 `scp` 로 올려 `/opt/cert-monitor/src` 에 풀어도 된다. 이후 업데이트는 `git pull`.)

## 5. 설정
### 5-1. 환경 변수 (.env)
```bash
cp .env.example .env && chmod 600 .env
```
`.env` 편집: `GRAFANA_ADMIN_PASSWORD`(12자 이상, 필수), `GRAFANA_ROOT_URL=https://monitor.univ.example`, `GRAFANA_BIND=127.0.0.1`(HTTPS 역프록시를 둘 것이므로 그대로)

### 5-2. 메일·웹훅 비밀 값
```bash
cp -r alertmanager/secrets.example alertmanager/secrets && chmod 700 alertmanager/secrets && chmod 600 alertmanager/secrets/*
```
- `alertmanager/secrets/smtp_password`: SMTP 비밀번호 한 줄(인증 없는 내부 릴레이면 `alertmanager.yml` 의 `smtp_auth_username`/`smtp_auth_password_file` 두 줄을 삭제)
- `alertmanager/secrets/webhook_url`: 팀 메신저 웹훅 URL 한 줄. **웹훅을 쓰지 않으면** `alertmanager.yml` 의 `ops-critical` 에서 `webhook_configs` 블록을 삭제(빈 값/예시 URL 이면 critical 알림 전송이 실패로 기록됨)
- `alertmanager/alertmanager.yml` 의 `TODO` 3곳 수정: `smtp_smarthost`, `smtp_from`, 수신자 `to`(받는 사람 여러 명이면 쉼표)

### 5-3. 감시 대상 등록
```bash
cp prometheus/targets/servers.yml.example prometheus/targets/servers.yml
```
`servers.yml` 을 실제 서버로 수정한다(예시 항목 삭제). 서버가 많으면 CSV 로 변환:
```bash
python3 scripts/csv_to_targets.py /path/servers.csv -o prometheus/targets/servers.yml
```
(`pyyaml` 필요: `sudo dnf -y install python3-pyyaml`). 호스트명:포트 형식, 포트 여러 개를 쓰는 서버는 줄을 나눈다.
처음에는 **3~5대만** 넣어 시험하고 나중에 늘린다.

### 5-4. 기동 전 설정 검증 (공식 이미지의 도구로)
```bash
docker run --rm -v "$PWD/prometheus:/etc/prometheus:ro,z" --entrypoint promtool prom/prometheus:v3.5.0 check config /etc/prometheus/prometheus.yml
```
```bash
docker run --rm -v "$PWD/prometheus:/etc/prometheus:ro,z" --entrypoint promtool prom/prometheus:v3.5.0 test rules /etc/prometheus/tests/cert-expiry.test.yml
```
```bash
docker run --rm -v "$PWD/alertmanager:/etc/alertmanager:ro,z" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /etc/alertmanager/alertmanager.yml
```
세 명령 모두 `SUCCESS` 여야 한다. 실패하면 메시지의 파일·줄 번호를 수정한다.

### 5-5. 이미지 반입(인터넷이 막힌 경우)
인터넷이 되는 PC 에서 `docker pull` 후 저장, VM 에서 적재:
```bash
docker save ribbybibby/ssl-exporter:2.4.3 prom/prometheus:v3.5.0 prom/alertmanager:v0.28.1 grafana/grafana-oss:11.6.0 | gzip > cert-monitor-images.tar.gz
```
```bash
gunzip -c cert-monitor-images.tar.gz | docker load
```

## 6. 기동과 확인
```bash
docker compose up -d
```
```bash
docker compose ps
```
4개 서비스가 `running` 이어야 한다. 이상하면 `docker compose logs <서비스>`.

**Prometheus 확인**(서버 내부에서)
```bash
curl -s http://127.0.0.1:9090/-/ready
```
```bash
curl -s http://127.0.0.1:9090/api/v1/targets | python3 -c "import sys,json; [print(t['labels'].get('instance'), t['health']) for t in json.load(sys.stdin)['data']['activeTargets'] if t['labels'].get('job')=='ssl-endpoints']"
```
대상이 `up` 이면 수집 성공. 인증서 목록:
```bash
python3 scripts/cert_inventory.py list
```

**알림 경로 시험**(메일이 오는지)
```bash
docker compose exec alertmanager amtool --alertmanager.url=http://localhost:9093 alert add TestAlert severity=warning instance=test:443 -a summary="테스트 알림" -a description="메일 경로 시험"
```
수 분 내 수신 메일을 확인한다(안 오면 `docker compose logs alertmanager`, SMTP 릴레이 허용 IP·인증 설정 확인).

## 7. HTTPS 역프록시 (nginx) — 교내 접속용
Grafana 는 `127.0.0.1:3000` 으로만 열려 있다. 호스트의 nginx 로 HTTPS 를 제공한다. (Docker 로 게시한 포트는 firewalld 규칙을 우회할 수 있으므로 Grafana 를 직접 0.0.0.0 으로 열지 않는다.)
```bash
sudo dnf -y install nginx
```
```bash
sudo cp /opt/cert-monitor/src/monitoring/nginx/grafana.conf.example /etc/nginx/conf.d/grafana.conf
```
- 파일의 `TODO`(호스트명, 인증서 경로) 수정. 인증서는 처음엔 사내 CA/자체 서명(`openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/pki/tls/private/monitor.key -out /etc/pki/tls/certs/monitor.crt -days 365 -subj "/CN=monitor.univ.example"`)으로 시작하고, 이후 정식 인증서로 교체.
```bash
sudo setsebool -P httpd_can_network_connect on
```
```bash
sudo nginx -t && sudo systemctl enable --now nginx
```
```bash
sudo firewall-cmd --permanent --add-service=https && sudo firewall-cmd --reload
```
브라우저에서 `https://monitor.univ.example` → Grafana 로그인(`.env` 의 관리자 계정) → **인증서 › 인증서 현황** 대시보드 확인.
- 이 감시 서버 자신의 HTTPS 주소도 `servers.yml` 에 등록해 만료를 감시한다.

## 8. 운영
| 항목 | 방법 |
|---|---|
| 재부팅 후 자동 기동 | `systemctl enable docker` + compose 의 `restart: unless-stopped` 로 자동 복구. 재부팅 후 `docker compose ps` 확인 |
| 대상 추가·변경 | `servers.yml` 수정(1분 내 자동 반영) |
| 규칙·설정 변경 | 수정 후 5-4 검증 → `curl -X POST http://127.0.0.1:9090/-/reload` (알림 설정은 `docker compose restart alertmanager`) |
| 업그레이드 | `git pull` → 이미지 태그 변경 시 `docker compose pull && docker compose up -d` |
| 백업 | 핵심 상태는 Prometheus 이력(`prometheus-data`). 점검 시간대에 `docker compose stop prometheus` 후 볼륨 tar 백업 → `docker compose start prometheus`. 설정은 Git 이 곧 백업(`.env`·`secrets/` 는 Git 에 없으므로 별도 안전 보관) |
| 디스크 점검 | `docker system df`, `df -h /var` (이력 400일 보관 설정) |
| 로그 | `docker compose logs -f --tail=100 <서비스>` |
| 계정 | Grafana 사용자는 관리자 화면에서 추가, 교내 계정 연동은 Grafana LDAP/OIDC 설정 |

## 9. 장애 대응 (Rocky 특화 포함)
| 증상 | 원인·조치 |
|---|---|
| 컨테이너가 설정 파일을 못 읽음(`permission denied`) | SELinux 라벨. compose 의 `:ro,z` 확인. `sudo ausearch -m avc -ts recent` 로 거부 기록 확인. **SELinux 를 끄지 말 것** |
| 설치/부팅이 `x86-64-v3` 오류로 실패 | VM CPU 모델 문제(0단계). 호스트 CPU 통과로 재생성 |
| 이미지 `pull` 실패 | 프록시(3단계) 또는 이미지 반입(5-5) |
| 대상이 모두 `down`/조회 실패 | VM→대상 포트 방화벽, 대상 호스트명 해석(VM 의 DNS), `docker compose exec ssl-exporter` 는 셸이 없으므로 VM 에서 `openssl s_client -connect 호스트:포트` 로 직접 시험 |
| 컨테이너에서 호스트명이 해석 안 됨 | `docker-compose.yml` 의 `ssl-exporter` 에 `dns: [교내DNS IP]` 추가 |
| nginx 502 | `setsebool -P httpd_can_network_connect on` 확인, Grafana 컨테이너 상태 |
| 알림 시각·만료 계산이 어긋남 | `chronyc tracking` 으로 시각 동기화 확인 |
| 메일 미수신 | SMTP 릴레이의 허용 IP 에 VM 등록, `smtp_require_tls`/인증 설정 |

## 10. 완료 기준 체크리스트
- [ ] `getenforce` = Enforcing, `chronyc tracking` 정상, 방화벽은 SSH·HTTPS 만 허용
- [ ] `docker compose ps` 4개 서비스 실행, 재부팅 후에도 자동 복구
- [ ] 5-4 검증 3종 `SUCCESS`
- [ ] 등록한 모든 대상이 Prometheus 에서 `up`, 대시보드에 인증서가 보임
- [ ] 테스트 알림 메일 수신, (사용 시) 웹훅 수신
- [ ] 감시 서버 자신의 HTTPS 인증서도 감시 대상에 등록
- [ ] `.env`·`secrets/` 백업 위치 지정, Prometheus 볼륨 백업 절차 시험
- [ ] 담당자 2인 이상이 접속·재기동·복구 방법을 숙지

## 11. 다음 단계
감시가 안정되면 [교체 체크리스트](cert-rotation-checklist.md)로 현재 인증서의 설치 위치를 확정하고, 발급·갱신 자동화는 별도 VM 에서 [갱신 자동화 설계](acme-automation.md)대로 진행한다(개인키를 다루므로 감시 VM 과 분리).
