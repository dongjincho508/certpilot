# certdeploy — 인증서 발급·자동 배포 도구

`certdeploy/` 패키지. **ACME 발급은 lego 가 수행**하고, certdeploy 는 ① lego 호출 ② 발급 결과 검증 ③ 서비스별 형식 변환·원자적 교체
④ 점검 → 재로드 → **TLS 로 새 인증서 반영 확인** ⑤ 실패 시 **자동 롤백**과 알림을 담당한다.
감시([monitoring/](../../monitoring/README.md))와는 별개 서버에서 돌리며, 감시 스택이 배포 결과를 독립 검증한다.

## 1. 한눈에 보기
```
 타이머(하루 2회) → certdeploy renew
   ├─ lego renew --days 30 (DNS-01, Infoblox)        ※ 만료 30일 이내일 때만 실제 갱신
   ├─ 인증서·키 검증: 키 일치 / 유효기간 / 체인 순서 / 대상 호스트명이 SAN 에 포함되는지
   └─ 대상별(canary → order 순, 한 대씩)
        ① 현재 서빙 중인 일련번호 확인 → 이미 최신이면 건너뜀(멱등)
        ② 파일 백업 → 임시 파일에 쓰기(umask 077) → 권한·소유자 → 원자적 mv
        ③ 점검(apachectl configtest 등) → 재로드 → TLS 접속으로 새 일련번호 확인(재시도)
        ④ 실패 시: 모든 파일을 백업으로 복원 → 이전 설정으로 재로드 → 상태 기록 → Alertmanager 알림 → 이후 대상 중단
```

| 유형 | 파일 | 기본 점검 / 재로드 |
|---|---|---|
| `apache` | `cert_path`(서버+중간 CA), `key_path`, 선택 `chain_path` | `apachectl configtest` / `systemctl reload httpd\|apache2` |
| `nginx` | 위와 동일 | `nginx -t` / `systemctl reload nginx` |
| `nodejs` | 위와 동일 | 없음 / **`reload_cmd` 필수** |
| `tomcat` | `format: pkcs12\|jks\|pem` (키스토어는 `keystore_path`+`password_env`) | 없음 / **`reload_cmd` 필수** |
| `generic` | `files:` 목록(content: cert/fullchain/chain/key/pkcs12/jks) — **WebtoB·JEUS 등** | `check_cmd`·`reload_cmd` 직접 지정 |

IIS(Windows)는 자동 배포 대상이 아니다. [`deploy-iis.ps1`](../../certdeploy/deploy-iis.ps1) 초안을 수동/별도 자동화로 사용한다.

## 2. 검증 현황 (정직한 범위)
| 항목 | 상태 |
|---|---|
| 인증서 검증·PEM/PKCS#12/JKS 변환 | ✅ 자동 테스트. **실제 JDK `keytool` 로 PKCS#12(현대·구형)·JKS 를 열어 확인** |
| 원자적 교체·백업·롤백·권한(키 600)·멱등·canary·실패 중단 | ✅ 자동 테스트(로컬 셸) |
| SSH 경유 배포 | ✅ 프로세스 내 SSH 서버(실제 셸 실행)로 끝까지 시험, 호스트 키 불일치·미등록 거부, **개인키가 원격 명령행에 노출되지 않음** 확인 |
| TLS 반영 확인 / 재로드 실패 시 롤백 | ✅ 실제 TLS 서버로 시험(재로드되지 않는 서비스 시나리오 포함) |
| Alertmanager 알림 | ✅ **실제 Alertmanager** 에 발생·해소 전송 후 웹훅 전달 확인 |
| lego 호출 | ⚠ **명령 구성·실패 처리만 가짜 lego 로 시험.** 실제 lego 바이너리와 Infoblox 는 이 저장소 개발 환경에서 실행하지 못했다. 옵션·환경변수 이름·산출 파일명은 설치한 lego 로 확인(`lego --help`, `lego dnshelp -c infoblox`) |
| 실제 Apache/Tomcat/WebtoB/JEUS 서버 | ❌ 미시험(해당 제품의 재로드 동작은 제품 문서로 확인, 아래 3-4) |
| Windows/IIS | ❌ 자동화 안 함 |

## 3. 설치 (Rocky Linux 10, 발급 전용 서버)
감시 VM 과 **분리된 서버**에 설치한다(개인키를 보관하므로 접근 계정 최소화).

### 3-1. 계정·디렉터리
```bash
sudo useradd --system --create-home --home-dir /var/lib/certdeploy --shell /sbin/nologin certdeploy
```
```bash
sudo install -d -m 700 -o certdeploy -g certdeploy /var/lib/lego /var/lib/certdeploy/.ssh && sudo install -d -m 750 -o root -g certdeploy /etc/certdeploy /etc/lego
```
### 3-2. certdeploy 설치
```bash
sudo dnf -y install python3 python3-pip git
```
```bash
sudo python3 -m venv /opt/certdeploy/venv && sudo /opt/certdeploy/venv/bin/pip install /path/to/certpilot   # 저장소 경로
```
(또는 `git clone` 한 뒤 `pip install .`) 확인: `/opt/certdeploy/venv/bin/certdeploy --version`
JKS 가 필요하면 `sudo dnf -y install java-17-openjdk-headless`(keytool).

### 3-3. lego 설치
lego 공식 릴리스(https://github.com/go-acme/lego/releases)에서 Linux amd64 바이너리를 받아 **체크섬을 확인**한 뒤 `/usr/local/bin/lego` 에 설치한다.
```bash
lego --version
```
```bash
lego dnshelp -c infoblox
```
(위 출력의 환경변수 이름을 `/etc/lego/lego.env` 에 사용한다. Infoblox 위임 영역 준비는 [갱신 자동화 설계](acme-automation.md) 3절.)
```bash
sudo install -m 600 -o certdeploy -g certdeploy /dev/null /etc/lego/lego.env && sudoedit /etc/lego/lego.env
```

### 3-4. 배포용 SSH 키와 대상 서버 권한 (최소 권한)
발급 서버에서 배포 전용 키를 만들고 공개키를 **각 대상 서버의 `deploy` 계정**에 등록한다.
```bash
sudo -u certdeploy ssh-keygen -t ed25519 -N "" -f /var/lib/certdeploy/.ssh/id_ed25519
```
호스트 키는 **미리 등록**한다(certdeploy 는 known_hosts 에 없는 서버·키가 바뀐 서버를 거부한다).
```bash
sudo -u certdeploy sh -c 'ssh-keyscan -t ed25519 www1.univ.example >> /var/lib/certdeploy/.ssh/known_hosts'
```
(스캔한 지문은 서버 관리자와 **대조 확인**한 뒤 사용한다.)

대상 서버 쪽은 `deploy` 계정이 **인증서 전용 디렉터리만 쓰고, 재로드 명령만 sudo 로 실행**하도록 구성한다(전체 root 권한을 주는 설정의 `sudo: true` 는 비권장).
```bash
sudo install -d -m 750 -o deploy -g apache /etc/ssl/univ
```
```bash
echo 'deploy ALL=(root) NOPASSWD: /usr/bin/systemctl reload httpd, /usr/sbin/apachectl configtest' | sudo tee /etc/sudoers.d/certdeploy && sudo chmod 440 /etc/sudoers.d/certdeploy && sudo visudo -c
```
SELinux(Rocky 대상 서버): 전용 디렉터리에 인증서 유형 라벨을 한 번 지정한다.
```bash
sudo semanage fcontext -a -t cert_t '/etc/ssl/univ(/.*)?' && sudo restorecon -Rv /etc/ssl/univ
```
Apache 설정은 `SSLCertificateFile /etc/ssl/univ/fullchain.pem`, `SSLCertificateKeyFile /etc/ssl/univ/privkey.pem` 를 가리키게 **먼저 수동으로 바꿔 둔다**.
**제품별 재로드 방식은 제품 문서로 확인**: Tomcat(버전별 SSL 재로드 가능 여부), WebtoB·JEUS(인증서 형식·재기동 명령), Node.js(재시작 방식).

### 3-5. 설정
```bash
sudo cp certdeploy/certdeploy.example.yml /etc/certdeploy/certdeploy.yml && sudo chgrp certdeploy /etc/certdeploy/certdeploy.yml && sudo chmod 640 /etc/certdeploy/certdeploy.yml && sudoedit /etc/certdeploy/certdeploy.yml
```
키스토어 비밀번호는 환경변수 파일에(설정 파일에 쓰지 않는다):
```bash
echo 'TOMCAT_KS_PASS=...' | sudo tee /etc/certdeploy/env >/dev/null && sudo chown certdeploy:certdeploy /etc/certdeploy/env && sudo chmod 600 /etc/certdeploy/env
```

## 4. 첫 실행 절차 (반드시 이 순서)
1. **스테이징 발급**(운영 인증서와 무관): `sudo -u certdeploy env $(cat /etc/certdeploy/env) certdeploy -c /etc/certdeploy/certdeploy.yml issue --staging --no-deploy`
   - 스테이징 인증서는 브라우저에서 신뢰되지 않으므로 **배포하지 않는다**. 발급·DNS 연동이 되는지만 확인.
2. 설정·인증서 검증: `certdeploy -c ... validate` → 키 일치, 유효기간, **대상 호스트명이 SAN 에 포함**, 환경변수 설정 여부
3. 계획 확인: `certdeploy -c ... plan` → 어떤 파일을 어디에 쓰고 어떤 명령을 실행하는지(키 내용은 출력되지 않음)
4. 운영 발급: `lego` 설정에서 `server` 를 제거(운영 CA)하고 `issue --no-deploy`
5. **canary 만** 배포: `certdeploy -c ... deploy --dry-run` → `deploy --target web-canary` → 감시 대시보드·`openssl s_client` 로 확인
6. 나머지 대상 배포: `deploy` (실패하면 그 대상에서 중단·롤백된다)
7. 타이머 활성화
   ```bash
   sudo cp certdeploy/systemd/certdeploy-renew.* /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now certdeploy-renew.timer
   ```
   ```bash
   systemctl list-timers certdeploy-renew.timer
   ```

## 5. 명령 요약
| 명령 | 설명 |
|---|---|
| `validate` | 설정·인증서·환경변수 점검(종료 코드 1: 문제 있음) |
| `plan [--target N]` | 배포 계획 출력(변경 없음) |
| `deploy [--dry-run] [--force] [--target N] [--continue-on-error]` | 현재 인증서를 배포. 기본: 한 대씩, 실패 시 중단 |
| `status` | 대상별 마지막 배포 기록과 **현재 서빙 중인 인증서** 대조 |
| `rollback --target N` | 마지막 배포 이전 파일로 되돌리고 재로드 |
| `issue [--staging] [--no-deploy]` / `renew` | lego 발급·갱신 후 배포(타이머가 `renew` 를 호출) |
종료 코드: 0 성공 · 1 배포/점검 문제 · 2 설정·인증서 오류 · 3 다른 작업 실행 중(동시 실행 방지 잠금)

## 6. 실패했을 때
| 상황 | 동작 |
|---|---|
| 설정 점검/재로드 실패, 새 인증서가 TLS 로 확인되지 않음 | 해당 서버의 모든 파일을 백업으로 복원하고 이전 설정으로 재로드, 상태 `rolled_back`, **Alertmanager `CertDeployFailed`(critical)**, 이후 대상 중단 |
| 롤백까지 실패 | 메시지에 "수동 조치 필요" 표시 + 알림. 서버의 `*.bak-<시각>` 파일로 직접 복원 |
| lego 실패(DNS·한도 초과 등) | 종료 코드 1, 알림(`target=lego`), 기존 인증서는 그대로 유지 |
| SSH 호스트 키 불일치 | 접속 거부(보안 이벤트일 수 있음) — known_hosts 를 확인 후 갱신 |
| 중간에 중단됐다 재실행 | 이미 새 인증서를 서빙하는 대상은 건너뛰므로 그대로 `deploy` 를 다시 실행하면 된다 |
성공하면 같은 대상의 `CertDeployFailed` 알림이 자동 해소된다. 감시 스택의 **갱신 지연 경보**(수명 75% 경과)가 이 도구 전체가 멈춘 경우를 독립적으로 잡는다.

## 7. 보안 설계 요점
- 개인키는 **stdin 으로만 전송**(명령행·로그·예외 메시지·상태 파일에 없음), 원격 임시 파일은 `umask 077`, 최종 권한 600
- 교체는 `mv` 원자적 이동 — 서비스가 중간 상태의 파일을 읽지 않음. 기존 파일은 소유자·권한 유지한 채 백업
- SSH 호스트 키 엄격 검증(미등록·불일치 거부), 상태 디렉터리 700, 상태 파일 600, 동시 실행 잠금
- 키스토어 비밀번호는 환경변수로만 받고 `keytool` 에도 `:env` 로 전달(프로세스 목록에 노출되지 않음)
- 발급 서버에는 개인키가 모이므로 전용 서버, 접근 계정 최소화, 백업은 암호화, 와일드카드 키를 다수 서버에 복사하는 범위를 줄이는 것을 검토

## 8. 알려진 한계
- IIS/Windows 자동 배포 없음, 로드밸런서·WAF·방화벽 장비 인증서는 해당 장비 방식으로 별도 교체
- 대상은 순차 배포(대수가 많으면 시간이 길어짐 — 50대 이하 기준 문제 없음)
- lego 옵션·산출 파일명 규칙(`*` → `_`)은 lego 버전에 따라 달라질 수 있어 첫 실행에서 확인 필요
- 롤백은 파일 복원 + 재로드까지이며, 애플리케이션 단의 세션·연결 영향은 제품 특성에 따른다
