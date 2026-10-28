# 인증서 자동 발급 가이드 (Let's Encrypt · DNS-01 · 내장 ACME)

`hnu.kr`, `hannam.ac.kr` 처럼 **DNS 를 직접 관리하는 도메인**의 인증서를 `certdeploy` 가 직접 발급·갱신하고 배포까지 이어 준다. lego 설치 없이 동작하는 내장 ACME 클라이언트(RFC 8555)다.

| DNS 방식 | 설정 | 동작 |
|---|---|---|
| **연동(자동)** | `dns.mode: infoblox` | Infoblox WAPI 로 `_acme-challenge` TXT 를 자동 등록 → 전파 확인 → 검증·발급 → TXT 자동 삭제 → 배포. 사람 개입 없음(갱신 타이머로 무인 운영) |
| **수동(연동 없음)** | `dns.mode: manual` | 1단계: 주문을 만들고 **등록할 TXT 를 안내**(화면·알림). 사람이 DNS 관리 화면에서 TXT 등록. 2단계: 같은 명령을 다시 실행하면 TXT 가 공개 DNS 에 보이는지 확인 후 검증·발급·배포 |

> **검증 범위**: 두 방식 모두 가짜 CA·가짜 Infoblox·로컬 DNS 서버로 전 과정을 시험했다(JWS 서명·nonce·키 인증·TXT 값 형식 포함, RFC 7638 지문 시험값 일치). **실제 Let's Encrypt 와 실제 Infoblox 장비로는 아직 실행하지 못했다** — 아래 "처음 실행" 순서대로 스테이징에서 먼저 확인한다. Infoblox WAPI 호출(`record:txt` 생성·조회·삭제)은 WAPI 문서 기준으로 작성했고 실제 장비·WAPI 버전에서 확인이 필요하다.

## 1. 준비
1. **발급 가능 조건 확인**(VM 에서)
```bash
dig NS hnu.kr +short
```
```bash
dig CAA hnu.kr +short
```
   - NS 가 인터넷에서 조회되는 권한 DNS(= TXT 를 등록할 곳)인지, CAA 가 있다면 `letsencrypt.org` 를 허용하는지 확인(`hannam.ac.kr` 도 동일). 권한 DNS 는 인터넷에서 53 포트 조회가 되어야 한다
2. **와일드카드 범위**: `*.hnu.kr` 은 `hnu.kr` 자체와 `a.b.hnu.kr` 같은 2단계 이하를 포함하지 않는다 → `domains` 에 루트를 함께 넣는다
3. `_acme-challenge.hnu.kr` 이름에 **CNAME 이 이미 있으면 안 된다**(TXT 와 공존 불가). CNAME 위임 방식은 아직 지원하지 않는다
4. (연동 모드) Infoblox 에 **TXT 레코드 생성·조회·삭제만 가능한 전용 계정**을 만들고, 공개 DNS 뷰 이름을 확인

## 2. 설정
```bash
sudo cp /opt/cert-monitor/src/certdeploy/certdeploy.acme.example.yml /etc/certdeploy/certdeploy.yml && sudo chgrp certdeploy /etc/certdeploy/certdeploy.yml && sudo chmod 640 /etc/certdeploy/certdeploy.yml && sudoedit /etc/certdeploy/certdeploy.yml
```
`domains`, `email`, `dns.mode`, `check_resolvers`(권장: 해당 영역 권한 DNS IP — 캐시에 가려지지 않게), 대상(`targets`)을 실제 값으로 수정한다. 예시 파일은 `hnu` 는 연동, `hannam` 은 수동 방식을 보여 준다.
Infoblox 계정은 환경변수 파일에(설정 파일에 쓰지 않는다):
```bash
printf 'INFOBLOX_USER=<계정>\nINFOBLOX_PASSWORD=<비밀번호>\n' | sudo tee /etc/certdeploy/env >/dev/null && sudo chown certdeploy:certdeploy /etc/certdeploy/env && sudo chmod 600 /etc/certdeploy/env
```
실행 래퍼(환경변수 파일을 읽어 certdeploy 실행)와 편의 변수:
```bash
sudo tee /usr/local/bin/cdrun >/dev/null <<'EOS'
#!/bin/bash
set -a; . /etc/certdeploy/env; set +a
exec /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml "$@"
EOS
sudo chmod 755 /usr/local/bin/cdrun
```
```bash
CD="sudo -u certdeploy /usr/local/bin/cdrun"
```
```bash
$CD validate
```

## 3. 처음 실행 (순서 고정)
**① 스테이징 발급**(시험용 CA — 운영 한도·운영 인증서와 무관, 운영 위치에 설치·배포하지 않음)
```bash
$CD --cert hnu issue --staging
```
- 연동: TXT 자동 등록→검증→삭제, `스테이징 발급 성공` 이 나오면 DNS 연동·권한·전파가 정상
- 수동: 종료 코드 **4** 와 함께 등록할 TXT 가 출력된다 → DNS 에 등록 → 같은 명령 재실행 → `스테이징 발급 성공`
- 실패 시: `$CD trace --errors` 의 `acme/*` 단계(어느 단계에서 왜 실패했는지)와 `$CD diagnose --out /tmp/diag.json` 번들을 전달
**② 운영 발급**(`--staging` 없이)
```bash
$CD --cert hnu issue --no-deploy
```
**③ canary 만 배포 → 확인 → 전체 배포**
```bash
$CD --cert hnu preflight
```
```bash
$CD --cert hnu deploy --target hnu-web-canary
```
```bash
$CD --cert hnu check
```
**④ 갱신 자동화**: 타이머가 매일 `renew` 를 실행한다(만료 `renew_days` 일 이내일 때만 실제 발급, 아니면 "갱신 불필요").
```bash
sudo cp /opt/cert-monitor/src/certdeploy/systemd/certdeploy-renew.* /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now certdeploy-renew.timer
```

## 4. 수동 방식 운영(타이머 사용 시)
갱신 시점이 되면 타이머가 `renew` 를 실행해 주문을 만들고 **알림(Alertmanager/메일/Teams)으로 등록할 TXT 를 알려 준다**(종료 코드 4 = 사람 조치 대기, 오류 아님). TXT 를 등록하면 다음 타이머 실행이 TXT 를 확인하고 발급·배포까지 자동으로 끝낸다. 급하면 `$CD renew` 를 바로 다시 실행한다.
- 안내를 다시 보려면 `$CD renew` 를 실행(주문을 새로 만들지 않고 같은 TXT 를 다시 보여 줌)
- 처음부터 다시: `$CD acme-reset` 후 `renew`
- 같은 이름(`_acme-challenge.hnu.kr`)에 **값이 둘**(루트·와일드카드) 필요하다. 둘 다 등록하고 기존 TXT 는 지우지 않는다. 발급 후 지워도 된다

## 5. 자주 나는 문제
| 증상 | 원인·조치 |
|---|---|
| `검증 실패: No TXT record found` | 공개 DNS 에 TXT 가 안 보임. `check_resolvers` 를 권한 DNS 로, 뷰(`view`)가 공개 뷰인지, TXT 이름 오타·CNAME 존재 여부 확인 |
| `TXT 가 DNS 에 전파되지 않았습니다` | `propagation_timeout` 을 늘리거나 Infoblox 반영 지연 확인 |
| `Infoblox ... HTTP 401/403` | 계정·권한·WAPI 버전(`wapi_version`)·`ca_file`(사설 인증서) 확인 |
| CAA 로 거부(`CAA record ... prevents issuance`) | CAA 에 `0 issue "letsencrypt.org"` 추가 |
| 속도 제한(rate limit) | 스테이징으로 시험, 실패 후 `lego_backoff_minutes` 동안 자동 대기. 급하면 `--ignore-backoff` |
| 종료 코드 4 | 수동 방식에서 TXT 등록 대기 중(정상) |

## 6. 보안
- 계정 키(`state_dir/acme/account-*.key`)와 대기 중 개인키는 0600, 발급 후 대기 키 삭제
- Infoblox 계정은 TXT 권한만, 환경변수 파일은 600. 트레이스·진단 번들에는 비밀번호·키가 마스킹됨
- 스테이징 발급분은 운영 위치에 설치·배포되지 않음
