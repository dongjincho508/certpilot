# 관리 서버 설치·테스트 매뉴얼 (Rocky Linux 10.x, 명령어 상세)

**관리 서버 1대**(Rocky Linux 10.x)에 *감시 스택*(Prometheus·ssl_exporter·Alertmanager·Grafana·Pushgateway)과 *발급·배포 도구*(`certdeploy`)를 함께 구성한다. 인증서는 상용 CA 와일드카드를 **수동으로 추가**(`csr`→`import`)하고 배포는 자동화한다(DNS 연동 불필요). lego+Infoblox 자동 발급은 선택(7-3).
각 명령은 위에서 아래로 순서대로 실행한다. 시험 절차는 [테스트 시나리오](test-scenarios.md), 문제 수집은 [디버깅 가이드](debugging.md).

> ⚠️ **현재 RapidSSL 와일드카드는 2026-11-12 08:59(KST) 만료**다. 이 시스템의 시험 완료를 기다리지 말고, 만료 전 교체는 기존 절차([교체 체크리스트](cert-rotation-checklist.md))로 진행한다. 교체본으로 8~9단계를 처음 실사용해도 된다(실패하면 자동 롤백).
> 이 문서의 OS 명령은 RHEL 계열 표준 절차이며 Rocky 10 에서 직접 실행해 보지는 못했다. 막히면 **그 단계의 명령과 출력**을 알려 달라.

## 구성
```
 관리자 PC ──HTTPS 443──▶ [관리 서버 Rocky 10]
                           ├ nginx(443) ─▶ Grafana(127.0.0.1:3000)
                           ├ Docker: Prometheus(9090) · Alertmanager(9093) · Pushgateway(9091) · ssl_exporter · Grafana  (모두 127.0.0.1 바인딩)
                           └ certdeploy(계정 certdeploy, 개인키 보관) ──SSH 22──▶ 대상 서버들(deploy 계정)
 감시: 관리 서버 ──TLS 접속──▶ 대상 서버들의 443/8443 …
```
개인키는 관리 서버의 `certdeploy` 계정만 접근한다. 관리자 계정(`certadmin`)은 개인키를 읽을 수 없게 둔다(권한 700/600).

## 0. 준비물 (설치 전)
- [ ] VM: 4 vCPU / 8 GB / 디스크 100 GB 이상(`/var` 40 GB 이상). **CPU 는 x86-64-v3 지원**(VM 설정에서 호스트 CPU 통과) — 아니면 Rocky 10 이 설치·부팅되지 않는다
- [ ] 고정 IP, 호스트명(예: `mgmt.univ.example`), 내부 DNS 등록
- [ ] 방화벽 요청(관리 서버 기준) — 나가는: 대상 서버 TLS 포트(443, 8443 …)와 SSH 22, SMTP 25/587, NTP, DNS, (설치 중) `download.docker.com`·`registry-1.docker.io`·`github.com`·Rocky 미러 / 들어오는: 관리자 PC → 22, 443
- [ ] 대상 서버 목록(호스트·포트·OS·웹서버 종류), 각 서버에 `deploy` 계정을 만들 수 있는지
- [ ] SMTP 릴레이(주소·포트·인증), 알림 수신 주소, (선택) Teams 웹훅 URL
- [ ] 상용 인증서 주문 계정(RapidSSL 등) 접근 권한
- 인터넷이 막혀 있으면: 교내 프록시 주소(2·3단계에 설정 위치 표시), 또는 이미지 반입([rocky-linux-deploy.md](rocky-linux-deploy.md) 5-5)

## 1. Rocky Linux 10 설치
1. Rocky 10 ISO(Minimal) 부팅 → 시간대 `Asia/Seoul`, 소프트웨어 선택 **최소 설치**
2. 파티션(LVM): `/` 30 GB 이상, **`/var` 40 GB 이상**(Docker 이미지·Prometheus 이력)
3. 고정 IP·게이트웨이·교내 DNS·호스트명 설정
4. root SSH 비밀번호 로그인은 쓰지 않고, **일반 관리자 계정(wheel)** 을 만든 뒤 재부팅 → 그 계정으로 SSH 접속

## 2. 초기 설정
```bash
sudo dnf -y update
```
```bash
sudo hostnamectl set-hostname mgmt.univ.example
```
```bash
sudo timedatectl set-timezone Asia/Seoul
```
**시각 동기화(필수)** — 만료 계산·알림이 서버 시각에 의존한다. 교내 NTP 가 있으면 `/etc/chrony.conf` 의 `pool` 줄을 교내 NTP 로 바꾼다.
```bash
sudo systemctl enable --now chronyd
```
```bash
chronyc tracking
```
(`System time` 오차 1초 이내)
**SELinux 는 enforcing 유지**(끄지 않는다), 방화벽은 기본 활성:
```bash
getenforce
```
```bash
sudo firewall-cmd --state && sudo firewall-cmd --list-all
```
**관리자 계정 SSH 키 등록**(PC 에서 `ssh-keygen -t ed25519` 로 만든 공개키):
```bash
sudo useradd -m -G wheel certadmin && sudo passwd certadmin
```
```bash
sudo -u certadmin mkdir -p -m 700 /home/certadmin/.ssh && echo '<PC 공개키 한 줄>' | sudo -u certadmin tee -a /home/certadmin/.ssh/authorized_keys >/dev/null && sudo chmod 600 /home/certadmin/.ssh/authorized_keys && sudo restorecon -R /home/certadmin/.ssh
```
**새 터미널에서 키로 접속되는지 확인한 뒤** 비밀번호 로그인을 끈다:
```bash
printf 'PermitRootLogin no\nPasswordAuthentication no\n' | sudo tee /etc/ssh/sshd_config.d/10-hardening.conf && sudo sshd -t && sudo systemctl reload sshd
```
보안 업데이트 자동화(선택):
```bash
sudo dnf -y install dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer
```
교내 프록시가 필요하면 `/etc/dnf/dnf.conf` 의 `[main]` 에 `proxy=http://프록시:포트` 를 추가한다.

## 3. Docker 설치 (Docker 공식 저장소)
Docker 저장소에 CentOS/RHEL **10** 경로가 있음을 확인했다. Rocky 는 CentOS 용 저장소 파일을 쓴다.
```bash
sudo dnf -y install dnf-plugins-core && sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
```
```bash
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin && sudo systemctl enable --now docker
```
```bash
sudo docker run --rm hello-world && docker compose version
```
로그 용량 제한(디스크 보호):
```bash
printf '{ "log-driver": "json-file", "log-opts": { "max-size": "20m", "max-file": "5" } }\n' | sudo tee /etc/docker/daemon.json && sudo systemctl restart docker
```
프록시가 필요하면 `/etc/systemd/system/docker.service.d/proxy.conf` 에 `[Service]`, `Environment="HTTPS_PROXY=http://프록시:포트"`, `Environment="NO_PROXY=localhost,127.0.0.1"` 를 쓰고 `sudo systemctl daemon-reload && sudo systemctl restart docker`.
`docker` 그룹은 root 와 동급이므로 필요한 관리자에게만: `sudo usermod -aG docker certadmin` 후 재로그인.

## 4. 소스 배치
```bash
sudo dnf -y install git python3 python3-pip python3-pyyaml openssl
```
```bash
sudo mkdir -p /opt/cert-monitor && sudo chown certadmin: /opt/cert-monitor && git clone https://github.com/dongjincho508/certpilot.git /opt/cert-monitor/src
```
(GitHub 접속이 막혀 있으면 PC 에서 압축해 `scp` 로 올려 `/opt/cert-monitor/src` 에 푼다. 이후 갱신은 `git pull`.)

## 5. 감시 스택 설정·기동
```bash
cd /opt/cert-monitor/src/monitoring && cp .env.example .env && chmod 600 .env
```
`.env` 편집(`vi .env`): `GRAFANA_ADMIN_PASSWORD`(12자 이상, **필수** — 비어 있으면 기동 거부), `GRAFANA_ROOT_URL=https://mgmt.univ.example`. `GRAFANA_BIND`·`PUSHGATEWAY_BIND` 는 `127.0.0.1` 그대로(같은 서버의 certdeploy 가 쓰고, 외부는 nginx 가 담당).

**알림 비밀 값**
```bash
cp -r alertmanager/secrets.example alertmanager/secrets && chmod 700 alertmanager/secrets && chmod 600 alertmanager/secrets/*
```
- `alertmanager/secrets/smtp_password`: SMTP 비밀번호 한 줄(인증 없는 릴레이면 `alertmanager.yml` 의 `smtp_auth_username`/`smtp_auth_password_file` 삭제)
- `alertmanager/secrets/webhook_url`: Teams 웹훅 URL 한 줄(미사용이면 `alertmanager.yml` 의 `ops-critical` 에서 `webhook_configs` 삭제)
- `alertmanager/alertmanager.yml` 의 `TODO` 3곳: `smtp_smarthost`, `smtp_from`, 수신자 `to`

**감시 대상 등록**(처음엔 3~5대로 시작)
```bash
cp prometheus/targets/servers.yml.example prometheus/targets/servers.yml
```
`servers.yml` 을 실제 서버로 수정하거나 CSV 로 생성: `host,port,group,service,os,owner` 열
```bash
python3 scripts/csv_to_targets.py /home/certadmin/servers.csv -o prometheus/targets/servers.yml
```
**기동 전 설정 검증**(공식 이미지의 도구 — 모두 `SUCCESS`)
```bash
docker run --rm -v "$PWD/prometheus:/etc/prometheus:ro,z" --entrypoint promtool prom/prometheus:v3.5.0 check config /etc/prometheus/prometheus.yml
```
```bash
docker run --rm -v "$PWD/prometheus:/etc/prometheus:ro,z" --entrypoint promtool prom/prometheus:v3.5.0 test rules /etc/prometheus/tests/cert-expiry.test.yml
```
```bash
docker run --rm -v "$PWD/alertmanager:/etc/alertmanager:ro,z" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /etc/alertmanager/alertmanager.yml
```
**기동·확인**
```bash
docker compose config -q && docker compose up -d && docker compose ps
```
5개 서비스(`ssl-exporter`, `prometheus`, `pushgateway`, `alertmanager`, `grafana`)가 `running` 이어야 한다. 이상하면 `docker compose logs --tail=100 <서비스>`.
```bash
curl -s http://127.0.0.1:9090/-/ready && curl -s http://127.0.0.1:9093/-/ready && curl -s http://127.0.0.1:9091/-/ready
```
```bash
python3 scripts/cert_inventory.py list
```
**알림 경로 시험**(수 분 내 메일 수신)
```bash
docker compose exec alertmanager amtool --alertmanager.url=http://localhost:9093 alert add TestAlert severity=warning instance=test:443 -a summary="테스트 알림" -a description="메일 경로 시험"
```

## 6. HTTPS 역프록시 (nginx) — 교내 접속용
Docker 로 게시한 포트는 firewalld 를 우회할 수 있으므로 Grafana 는 `127.0.0.1` 로만 열고 호스트 nginx 가 HTTPS 를 제공한다.
```bash
sudo dnf -y install nginx && sudo cp /opt/cert-monitor/src/monitoring/nginx/grafana.conf.example /etc/nginx/conf.d/grafana.conf
```
`/etc/nginx/conf.d/grafana.conf` 의 `TODO`(서버명, 인증서 경로) 수정. 처음에는 임시 자체 서명 인증서로 시작하고 8~9단계 이후 정식 인증서로 교체한다:
```bash
sudo openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/pki/tls/private/mgmt.key -out /etc/pki/tls/certs/mgmt.crt -days 365 -subj "/CN=mgmt.univ.example" && sudo chmod 600 /etc/pki/tls/private/mgmt.key
```
```bash
sudo setsebool -P httpd_can_network_connect on && sudo nginx -t && sudo systemctl enable --now nginx
```
```bash
sudo firewall-cmd --permanent --add-service=https && sudo firewall-cmd --reload
```
브라우저로 `https://mgmt.univ.example` → Grafana 로그인 → 「인증서 현황」 대시보드 확인. 이 관리 서버 자신의 HTTPS 주소도 `servers.yml` 에 넣어 만료를 감시한다.

## 7. certdeploy 설치 (같은 서버)
### 7-1. 계정·디렉터리·설치
```bash
sudo useradd --system --create-home --home-dir /var/lib/certdeploy --shell /sbin/nologin certdeploy
```
```bash
sudo install -d -m 700 -o certdeploy -g certdeploy /var/lib/certdeploy/.ssh /var/lib/certdeploy/managed && sudo install -d -m 750 -o root -g certdeploy /etc/certdeploy
```
```bash
sudo python3 -m venv /opt/certdeploy/venv && sudo /opt/certdeploy/venv/bin/pip install /opt/cert-monitor/src
```
```bash
sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml --version
```
JKS(Tomcat/JEUS)가 필요하면: `sudo dnf -y install java-17-openjdk-headless` (keytool).

### 7-2. 설정 파일(수동 인증서 + 자동 배포)
```bash
sudo cp /opt/cert-monitor/src/certdeploy/certdeploy.manual.example.yml /etc/certdeploy/certdeploy.yml && sudo chgrp certdeploy /etc/certdeploy/certdeploy.yml && sudo chmod 640 /etc/certdeploy/certdeploy.yml && sudoedit /etc/certdeploy/certdeploy.yml
```
대상(`targets`)의 호스트·경로·재로드 명령을 실제 값으로 수정한다(처음에는 시험용 1대만). 키스토어 비밀번호는 환경변수 파일에:
```bash
echo 'TOMCAT_KS_PASS=<비밀번호>' | sudo tee /etc/certdeploy/env >/dev/null && sudo chown certdeploy:certdeploy /etc/certdeploy/env && sudo chmod 600 /etc/certdeploy/env
```
편의 변수(이후 명령에서 사용 — 새 터미널마다 다시 지정):
```bash
CD="sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml"
```

### 7-3. (선택) lego 자동 발급을 쓸 때만
```bash
LEGO_VER=X.Y.Z   # https://github.com/go-acme/lego/releases 에서 확인한 최신 버전 번호로 바꾼다
```
```bash
cd /tmp && curl -fLO https://github.com/go-acme/lego/releases/download/v${LEGO_VER}/lego_v${LEGO_VER}_linux_amd64.tar.gz && curl -fLO https://github.com/go-acme/lego/releases/download/v${LEGO_VER}/lego_v${LEGO_VER}_checksums.txt
```
```bash
sha256sum -c --ignore-missing lego_v${LEGO_VER}_checksums.txt && sudo tar -xzf lego_v${LEGO_VER}_linux_amd64.tar.gz -C /usr/local/bin lego && lego --version
```
```bash
lego dnshelp -c infoblox
```
출력된 환경변수 이름을 `/etc/lego/lego.env`(권한 600)에 쓰고 설정 파일에 `lego:` 블록을 추가한다([certdeploy.md](certdeploy.md), [acme-automation.md](acme-automation.md)). 이 경로는 반드시 `issue --staging --no-deploy` 로 먼저 시험한다.

### 7-4. 배포용 SSH 키 생성
```bash
sudo -u certdeploy ssh-keygen -t ed25519 -N "" -f /var/lib/certdeploy/.ssh/id_ed25519 && sudo cat /var/lib/certdeploy/.ssh/id_ed25519.pub
```
출력된 **공개키**를 8단계에서 각 대상 서버의 `deploy` 계정에 등록한다. 호스트 키는 **미리 등록**(certdeploy 는 known_hosts 에 없거나 바뀐 서버를 거부한다). 지문은 서버 관리자와 대조한다.
```bash
sudo -u certdeploy sh -c 'ssh-keyscan -t ed25519 www1.univ.example >> /var/lib/certdeploy/.ssh/known_hosts'
```
```bash
sudo -u certdeploy ssh-keygen -lf /var/lib/certdeploy/.ssh/known_hosts
```

## 8. 대상 서버 준비 (서버마다, 대상 서버에서 실행)
`deploy` 계정은 **인증서 전용 디렉터리만 쓰고, 재로드 명령만 sudo** 로 실행한다(전체 root 권한 `sudo: true` 는 비권장).
**Apache / Nginx (Rocky 계열 대상)**
```bash
sudo useradd -m -s /bin/bash deploy && sudo -u deploy mkdir -p -m 700 /home/deploy/.ssh && echo '<7-4 에서 출력한 공개키>' | sudo -u deploy tee -a /home/deploy/.ssh/authorized_keys >/dev/null && sudo chmod 600 /home/deploy/.ssh/authorized_keys && sudo restorecon -R /home/deploy/.ssh
```
```bash
sudo install -d -m 750 -o deploy -g apache /etc/ssl/univ
```
```bash
echo 'deploy ALL=(root) NOPASSWD: /usr/bin/systemctl reload httpd, /usr/sbin/apachectl configtest' | sudo tee /etc/sudoers.d/certdeploy && sudo chmod 440 /etc/sudoers.d/certdeploy && sudo visudo -c
```
```bash
sudo semanage fcontext -a -t cert_t '/etc/ssl/univ(/.*)?' && sudo restorecon -Rv /etc/ssl/univ
```
Apache 설정은 먼저 **수동으로** `SSLCertificateFile /etc/ssl/univ/fullchain.pem`, `SSLCertificateKeyFile /etc/ssl/univ/privkey.pem` 을 가리키게 바꾸고(처음 한 번 현재 인증서를 그 경로에 복사) `apachectl configtest` 통과를 확인한다.
**Ubuntu/Debian 대상**: 서비스 이름이 `apache2` 이므로 sudoers·`reload_cmd` 의 `httpd` 를 `apache2` 로 바꾼다.
**Tomcat / WebtoB·JEUS / Node.js**: 키스토어 경로·형식·재로드(재기동) 명령은 **제품 문서와 현재 설정으로 확인**해 `targets` 에 반영한다(`reload_cmd` 는 sudoers 에 해당 명령만 허용).
**IIS(Windows)**: 관리 서버에서 만든 PFX 를 옮겨 [deploy-iis.ps1](../../certdeploy/deploy-iis.ps1)(초안·미검증)로 바인딩을 교체한다. 자동화는 SSH 가 가능한 구성이 필요하므로 별도 협의.

## 9. 인증서 준비(수동)와 첫 배포
```bash
$CD validate
```
```bash
$CD preflight
```
`preflight` 는 접속·쓰기 권한·명령·sudo·여유 공간·현재 TLS 를 **변경 없이** 점검한다. 전부 통과해야 한다.
**CSR 생성 → CA 제출**
```bash
$CD csr --domains '*.univ.example,univ.example' --country KR --org '대학명'
```
출력된 CSR 을 RapidSSL 주문 화면에 붙여 넣는다(개인키는 `/var/lib/certdeploy/pending/…/key.pem`, 0600 — 외부로 보내지 않는다).
**CA 가 준 파일 검증·설치**(`/tmp` 에 올린 뒤)
```bash
$CD import --file /tmp/server.cer --file /tmp/intermediates.p7b --dry-run
```
이상 없으면 설치만, 또는 설치+배포:
```bash
$CD import --file /tmp/server.cer --file /tmp/intermediates.p7b
```
```bash
$CD plan
```
```bash
$CD deploy --target web-canary
```
```bash
$CD check
```
서빙 확인(외부 독립 확인): `echo | openssl s_client -connect www1.univ.example:443 -servername www1.univ.example 2>/dev/null | openssl x509 -noout -serial -enddate -subject`
canary 확인 후 나머지 대상을 `targets` 에 추가하고 `$CD preflight` → `$CD deploy`. 지표 연동 점검:
```bash
$CD diagnose --prometheus http://127.0.0.1:9090 --alertmanager http://127.0.0.1:9093 --pushgateway http://127.0.0.1:9091
```
임시 파일 정리: `sudo shred -u /tmp/server.cer /tmp/intermediates.p7b`(인증서라 비밀은 아니지만 정리 습관).

## 10. 운영 설정
**재부팅 후 자동 기동 확인**: Docker 는 `enable` 했고 컨테이너는 `restart: unless-stopped`.
```bash
sudo reboot
```
재접속 후:
```bash
docker compose -f /opt/cert-monitor/src/monitoring/docker-compose.yml ps && systemctl is-active docker nginx chronyd firewalld
```
**백업**(개인키 포함 → 암호화, 안전한 곳에 보관)
```bash
export BACKUP_PW='<12자 이상 비밀번호>' && $CD backup --out /home/certadmin/certdeploy-$(date +%F).cdbk --passphrase-env BACKUP_PW
```
감시 이력 백업(점검 시간대):
```bash
mkdir -p /opt/cert-monitor/backup && cd /opt/cert-monitor/src/monitoring && docker compose stop prometheus && docker run --rm -v cert-monitor_prometheus-data:/data:ro -v /opt/cert-monitor/backup:/backup:z alpine tar czf /backup/prometheus-$(date +%F).tgz -C /data . && docker compose start prometheus
```
`.env`·`alertmanager/secrets/` 는 암호화한 별도 저장소에 보관. lego 자동 발급을 쓸 때만 갱신 타이머 설치:
```bash
sudo cp /opt/cert-monitor/src/certdeploy/systemd/certdeploy-renew.* /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now certdeploy-renew.timer
```
수동 인증서 운영은 타이머가 필요 없다. 만료 임박은 감시 스택 알림(60/30/14/7일)이 알려 주고, 갱신 때 9단계를 반복한다.
**업그레이드**: `cd /opt/cert-monitor/src && git pull` → 감시는 `docker compose pull && docker compose up -d`, certdeploy 는 `sudo /opt/certdeploy/venv/bin/pip install --upgrade /opt/cert-monitor/src`.

## 11. 시험·버그 수집
시험은 [테스트 시나리오](test-scenarios.md) T-01~T-13 순서로 수행하고 결과표를 채운다. 문제가 생기면:
```bash
$CD diagnose --out /tmp/diag.json
```
감시 쪽은 `docker compose ps` 와 `docker compose logs --tail=100 <서비스>`. 전달 형식: **시험 ID · 실행한 명령 · 기대 결과 · 실제 결과 · diag.json**(비밀값 마스킹됨, 호스트명 노출이 곤란하면 가려서). 수정 후 같은 시험을 재실행하고 회귀 방지 테스트를 추가한다.

## 12. 장애 대응(Rocky 특화)
| 증상 | 원인·조치 |
|---|---|
| 컨테이너가 설정 파일을 못 읽음(`permission denied`) | SELinux 라벨 — compose 의 `:ro,z` 확인, `sudo ausearch -m avc -ts recent`. **SELinux 를 끄지 말 것** |
| 설치/부팅이 `x86-64-v3` 오류 | VM CPU 모델(0단계) — 호스트 CPU 통과로 재생성 |
| 이미지 pull 실패 | 프록시(3단계) 또는 이미지 반입 |
| 모든 대상이 down | 관리 서버→대상 포트 방화벽, DNS 해석, `openssl s_client -connect 호스트:포트` 직접 시험 |
| nginx 502 | `getsebool httpd_can_network_connect` = on, Grafana 컨테이너 상태 |
| certdeploy 가 대상 접속 거부 | `known_hosts` 미등록/변경(7-4), `deploy` 공개키 미등록, 대상 방화벽 22 |
| `import` 가 "일치하는 서버 인증서가 없습니다" | CSR 과 인증서의 키 불일치 — 대기 키(`pending/…/key.pem`)가 없거나 다른 CSR 로 주문함 |
| 알림 시각·만료 계산 어긋남 | `chronyc tracking` |
| 메일 미수신 | SMTP 릴레이 허용 IP·인증·TLS 설정 |

## 13. 완료 기준 체크리스트
- [ ] `getenforce` Enforcing · `chronyc tracking` 정상 · 방화벽은 SSH·HTTPS 만 허용
- [ ] 5개 컨테이너 실행, 재부팅 후 자동 복구, nginx HTTPS 로 Grafana 접속
- [ ] 등록 대상 전부 Prometheus `up`, 대시보드에 인증서 표시, 테스트 알림 수신
- [ ] T-01~T-13 합격 · 결과표 보관
- [ ] 개인키 권한 600, `certdeploy` 계정 외 접근 불가, 백업본 암호화 보관·복원 시험 완료
- [ ] 알림 수신자·야간/휴일 담당 확정, 갱신 달력(약 200일 주기, 단축 예정) 등록
- [ ] 담당자 2인 이상이 접속·재기동·롤백(`rollback --target`)·복구 방법 숙지
