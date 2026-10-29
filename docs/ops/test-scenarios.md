# 테스트 시나리오 (VM 시험용 상세 절차)

[VM 설치·테스트 매뉴얼](vm-install-and-test.md) 7절의 T-01~T-13 을 **그대로 따라 할 수 있게** 풀어 쓴 것이다. 각 시나리오는 *사전조건 → 절차 → 기대 결과 → 증거 → 실패 시* 순서다.
결과는 마지막 [결과 기록표](#결과-기록표)에 적고, 실패하면 매뉴얼 8절 방식으로 번들을 보낸다.

공통 준비(관리 서버, 한 번만). **인증서가 도메인별로 나뉘어 있으므로(`hnu`, `hannam`) 발급·배포 명령에는 `--cert hnu` 또는 `--cert hannam` 을 붙인다**(아래 예시는 `hnu`; `hannam` 도 같은 방식으로 반복). `validate`·`preflight`·`check`·`status` 처럼 전체를 대상으로 하는 명령은 생략 가능:
```bash
CD="sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml"
```
아래 `$CD` 는 위 변수다. 오류가 나면 같은 명령을 `certdeploy -c /etc/certdeploy/certdeploy.yml --debug <명령>` 형태(전역 옵션은 `-c` 뒤, 하위 명령 앞)로 다시 실행해 단계 출력을 확인한다.

---
## 감시 (감시 VM)
### T-01 감시 수집
- **사전조건**: 대상 CSV 로 만든 `prometheus/targets/*.yml` 반영, 컨테이너 기동
- **절차**: 브라우저로 Prometheus `/targets`, Grafana 「cert-overview」 확인
```bash
docker compose -f monitoring/docker-compose.yml ps
```
- **기대**: 5개 서비스 `Up`, `ssl-endpoints` 대상 UP, 대시보드에 만료일·남은 일수
- **증거**: `/targets` 화면 캡처, `docker compose ps` 출력
- **실패 시**: DOWN 대상의 `Last error` 전달(연결 거부=방화벽/포트, x509 오류=체인 문제 → T-04·T-09 참고)

### T-02 만료 알림과 해소
- **사전조건**: Alertmanager 메일/Teams 설정 완료
- **절차**: (a) 발송 경로 시험 — 테스트 알림 1건 전송, (b) 규칙 시험 — 시험용 대상(수일 남은 인증서)을 `ssl-endpoints` 에 임시 추가
```bash
curl -s -XPOST http://127.0.0.1:9093/api/v2/alerts -H 'Content-Type: application/json' -d '[{"labels":{"alertname":"TestAlert","severity":"warning"},"annotations":{"summary":"테스트 알림"}}]'
```
- **기대**: 수신함/Teams 에 알림 도착, 규칙 시험 시 임박 알림 발화(Prometheus `/alerts`), 대상 제거·교체 후 복구 알림
- **증거**: 수신 화면, `/alerts` 캡처
- **실패 시**: `docker compose logs --tail=100 alertmanager` 전달

---
## 발급·배포 (발급·배포 VM)
### T-02a 메일 알림 시험 (메일 우선)
```bash
$CD notify-test
```
- **기대**: `시험 알림을 보냈습니다: 메일(수신자…)` 출력, 수신함에 "WARNING certdeploy 알림 시험" 도착. 도착하지 않으면 `$CD trace --errors` 의 `notify/smtp` 이벤트(접속 거부·인증 실패·TLS 오류)와 SMTP 릴레이의 허용 IP 설정 확인

### T-03 사전 점검 (변경 없음)
- **절차**
```bash
$CD validate
```
```bash
$CD preflight
```
- **기대**: `validate` 종료 코드 0, `preflight` 가 모든 대상에서 접속·쓰기 권한·명령·sudo·여유 공간·현재 TLS 통과. 서버에는 아무 변경이 없다
- **확인**: `echo $?` = 0, 대상 서버의 인증서 파일 수정 시각이 그대로
- **실패 시**: 출력된 `[문제]` 줄과 `diagnose --out` 번들

### T-04 수동 가져오기 (CSR → CA → 검증)
- **사전조건**: 설정 파일에 `certificate.cert_file/key_file` 지정(`lego:` 없이)
- **절차**
```bash
$CD --cert hnu csr --domains '*.hnu.kr,hnu.kr' --country KR --org '대학명'
```
  출력된 CSR 을 CA 에 제출 → 받은 파일을 `/tmp` 에 올림 →
```bash
$CD --cert hnu import --file /tmp/server.cer --file /tmp/intermediates.p7b --dry-run
```
- **기대**: 서버 인증서 일련번호·유효기간·SAN 표시, `중간 CA 1개`(필요 시 "자체 서명 루트 제외" 안내), `--dry-run` 이라 설치 안 함. 개인키 내용은 어디에도 출력되지 않음
- **오류 확인(선택)**: 다른 키로 시도(`--key-file`)하면 "일치하는 서버 인증서가 없습니다", 만료 인증서면 "만료"로 종료 코드 2
- **증거**: 출력 전체(키 없음), `openssl verify` 결과
```bash
openssl verify -CAfile /path/to/root.pem -untrusted /var/lib/certdeploy/hnu/managed/wildcard.crt /var/lib/certdeploy/hnu/managed/wildcard.crt
```
- **실패 시**: 번들과 CA 가 보낸 파일 이름 목록(파일 자체는 인증서라 공유 가능, 키는 절대 보내지 않는다)

### T-05 단건(canary) 배포
- **절차**
```bash
$CD plan
```
```bash
$CD --cert hnu import --file /tmp/server.cer --file /tmp/intermediates.p7b
```
```bash
$CD --cert hnu deploy --target hnu-web-canary
```
- **기대**: `[hnu-web-canary] 배포 완료`, `요약: 배포 완료 1`, 종료 코드 0. 대상에는 백업 `*.bak-<시각>` 이 남음
- **확인**
```bash
echo | openssl s_client -connect www1.hnu.kr:443 -servername www1.hnu.kr 2>/dev/null | openssl x509 -noout -serial -enddate
```
```bash
$CD status
```
  서빙 일련번호가 새 인증서와 같고 `status` 의 서빙 열이 "최신"
- **증거**: deploy·status 출력, openssl 출력
- **실패 시**: `$CD trace --errors` 와 번들

### T-06 멱등성
- **절차**: T-05 직후 같은 명령 재실행
```bash
$CD --cert hnu deploy --target hnu-web-canary
```
- **기대**: `건너뜀 — 이미 새 인증서를 서빙 중`, 재로드 없음(서버 로그에 reload 기록 추가 없음), 종료 코드 0
- **실패 시**: 건너뛰지 않고 재배포했다면 `status` 출력과 번들(서빙 일련번호 확인 실패 여부)

### T-07 실패 → 자동 롤백
- **목적**: 배포 중 문제가 나도 서비스가 이전 인증서로 유지되는지
- **절차(안전한 주입)**: 시험 대상(운영 트래픽 없는 서버 권장)의 `check_cmd` 를 `"false"` 로 바꾸고 강제 재배포
```bash
$CD --cert hnu deploy --target hnu-web-test --force
```
- **기대**: `[web-test] 롤백됨 — 설정 점검 실패 … → 이전 파일로 롤백함`, 종료 코드 1, 알림(메일/Teams/Alertmanager) 수신, 해당 서버의 서빙 인증서는 **이전 것 그대로**, Pushgateway 지표 `certdeploy_run_ok 0`
- **복구**: `check_cmd` 를 원복하고 `$CD --cert hnu deploy --target hnu-web-test` → `배포 완료`, 해소 알림, `run_ok 1`
- **증거**: 출력, 알림 화면, Grafana certdeploy 패널
- **실패 시**: 롤백 문구에 "롤백도 실패 — 수동 조치 필요"가 보이면 즉시 중단하고 `.bak-` 파일로 수동 복구 후 번들 전달

### T-08 전체 배포 (순서·canary)
- **절차**
```bash
$CD preflight
```
```bash
$CD --cert hnu deploy
```
- **기대**: canary → order 순 한 대씩 `배포 완료`, 중간에 실패하면 이후 대상은 `실행 안 함`, 종료 코드 0, `$CD check` 가 `CERTDEPLOY OK`
- **확인**
```bash
$CD check
```
- **증거**: deploy 출력 전체, `check` 한 줄

### T-09 제품별 재로드
각 제품 1대씩 아래를 반복하고 표에 결과를 적는다.
| 제품 | 확인 포인트 |
|---|---|
| Apache | `configtest` 통과, `reload` 후 새 일련번호 서빙 |
| Nginx | `nginx -t` 통과 |
| Tomcat | 키스토어(PKCS12/JKS) 교체 후 **재로드 방식**(재시작 필요 여부) 확인 — `reload_cmd` 에 반영 |
| WebtoB/JEUS | `type: webtob`/`jeus` 자동 배포(T-26), 재기동 명령은 제품 문서로 확인 |
| IIS | `type: iis` 자동 배포(T-25) 또는 `deploy-iis.ps1` 수동 교체 후 서빙 일련번호 확인 |
| Node.js | 프로세스 재시작/리로드 방식 |
- **공통 확인**: `$CD status`, 외부에서 `openssl s_client` 일련번호
- **실패 시**: `$CD trace --errors` 의 `deploy/check_cmd`·`reload_cmd` 출력과 제품 로그 10줄

### T-10 감사 로그 무결성
```bash
$CD verify-audit
```
- **기대**: JSON 에 `"integrity_valid": true`, 종료 코드 0. (선택) 로그 파일 한 줄을 임의 수정 후 재실행하면 `false`·종료 코드 1 — **시험용 사본**에서만 수행

### T-11 백업·복원
```bash
export BACKUP_PW='12자-이상-비밀번호'
```
```bash
$CD backup --out /tmp/cd.cdbk --passphrase-env BACKUP_PW
```
```bash
$CD restore --in /tmp/cd.cdbk --dest /tmp/restore-test --passphrase-env BACKUP_PW
```
- **기대**: 복원 디렉터리에 설정·상태(·lego) 파일, 잘못된 비밀번호는 오류. 확인 후 `/tmp/restore-test` 와 백업 파일 삭제(개인키 포함)

### T-12 재부팅·타이머 (수동 인증서만 쓰면 건너뜀)
- **절차**: 타이머 활성 상태에서 VM 재부팅
```bash
systemctl list-timers certdeploy-renew.timer
```
- **기대**: 재부팅 후에도 타이머가 다음 실행 시각을 가짐, 잠금 파일 잔여로 인한 종료 코드 3 없음, `journalctl -u certdeploy-renew` 에 정상 기록

### T-13 감시 장애 시 배포 영향 없음
- **절차**: 감시 VM 의 Pushgateway 를 중지(`docker compose stop pushgateway`)한 상태에서 `$CD --cert hnu deploy --force --target hnu-web-test`
- **기대**: 배포는 정상 완료, 종료 코드 0. 지표 푸시 실패는 오류 이벤트로만 남음
```bash
$CD trace --errors
```
  `metrics/pushgateway` 오류가 보여야 한다. 시험 후 Pushgateway 재기동

---
## 자동 발급·호환성 (내장 ACME · DNS 제공자 · 웹방화벽)
> 아래는 [자동 발급 가이드](auto-issue.md)·[호환성 가이드](compatibility.md) 설정을 마친 뒤 수행한다. **반드시 스테이징(시험 CA)부터** 한다.

### T-14 내장 ACME 스테이징 발급 (DNS 연동 모드)
- **사전조건**: 설정에 `acme:` + `dns.mode`(infoblox 등), `/etc/certdeploy/env` 에 계정, `check_resolvers` 에 권한 DNS IP, `dig CAA` 확인 완료
- **절차**
```bash
$CD validate
```
```bash
$CD --cert hnu issue --staging
```
- **기대**: `스테이징 발급 성공(일련번호 …) — 운영 위치에는 설치하지 않았습니다`, 종료 코드 0. DNS 에 만들어진 `_acme-challenge` TXT 가 **발급 후 모두 삭제**되어 있고(DNS 관리 화면/`dig TXT _acme-challenge.hnu.kr` 로 확인), 운영 인증서 파일(`managed/…`)과 대상 서버는 바뀌지 않음
- **증거**: 출력, `$CD trace --debug` 의 `acme/*` 단계(register_account, new_order, dns_present, challenge, finalize, dns_cleanup)
- **실패 시**: 메시지의 단계(검증 실패 `No TXT record found` → 뷰·전파·CNAME 존재, `Infoblox … HTTP 401/403` → 계정·권한·WAPI 버전)와 `diagnose --out` 번들

### T-15 수동 TXT 두 단계 (DNS 연동 없음)
- **사전조건**: `dns.mode: manual`
- **절차**
```bash
$CD --cert hannam issue --staging
```
  종료 코드 **4** 와 등록할 TXT(이름·값, 같은 이름에 값 2개)가 출력되고 알림이 온다 → DNS 관리 화면에서 TXT 를 **모두** 등록 → 같은 명령 재실행
- **기대**: 일부만 등록한 상태에서는 `아직 보이지 않는 레코드` 와 함께 종료 코드 4 유지(주문은 같은 것 재사용), 모두 등록 후 `스테이징 발급 성공`, 종료 코드 0
- **정리**: 시험이 끝나면 등록했던 TXT 삭제. 처음부터 다시 하려면 `$CD acme-reset`
```bash
$CD acme-reset
```

### T-16 운영 발급 → canary 배포 → 갱신 판정
```bash
$CD --cert hnu issue --no-deploy
```
```bash
$CD --cert hnu deploy --target hnu-web-canary
```
```bash
$CD --cert hnu renew
```
- **기대**: 운영 발급 성공 → canary 배포 확인(T-05 와 동일 기준) → `renew` 는 `갱신 불필요: 만료까지 N일` (만료가 `renew_days` 이내가 아닐 때). 타이머 사용 시 `systemctl list-timers certdeploy-renew.timer`

### T-17 다른 DNS 제공자 선택 (사용 시)
- **대상**: `rfc2136`/`cloudflare`/`powerdns`/`webhook`/`exec` 중 실제로 쓸 것만
- **절차**: T-14 와 동일(`issue --staging`). `rfc2136` 은 서버의 update-policy 가 `_acme-challenge` TXT 만 허용하는지, TSIG 키 이름·알고리즘이 일치하는지 확인. `exec`/`webhook` 은 `present`/`cleanup` 을 **스크립트·중계 서비스에서 단독 실행**해 TXT 가 생겼다 지워지는지 먼저 확인
- **기대**: T-14 의 기대와 동일. 실패 시 `acme/dns_*` 이벤트와 `exec 훅 실패(…, 종료 코드 N)`·`DNS UPDATE 거부됨: NOTAUTH/NOTZONE`·`Cloudflare … HTTP 403` 같은 메시지로 원인 구분

### T-18 웹방화벽(HTTP API) 배포 — API 문서 확보 후
- **사전조건**: 제품 관리 API 문서로 `certdeploy.waf.example.yml` 을 실제 경로·필드로 바꿈, **시험용 가상 호스트/대기 장비**, [WAF 확인 질문 7가지](compatibility.md) 답 확보(특히 '적용' 이 다른 설정 변경까지 반영하는지)
```bash
$CD preflight
```
```bash
$CD plan
```
```bash
$CD deploy --target waf-main
```
- **기대**: `preflight` 가 API 관리 주소 도달·`rollback_steps` 설정을 확인(요청은 보내지 않음). `deploy` 가 로그인→업로드→적용→(wait)→TLS 일련번호 확인 후 `배포·확인 완료`. **의도적 실패 시험**: 적용 단계 URL 을 일부러 틀리게 하면 `rollback_steps` 가 실행되어 이전 인증서로 복귀(`롤백함`)하고 알림이 오며, 장비는 이전 인증서를 계속 서빙
```bash
$CD rollback --target waf-main
```
- **증거**: deploy 출력, 장비 관리 화면의 인증서 목록(이름·만료), 앞단 `openssl s_client` 일련번호
- **주의**: 운영 장비는 시험 장비에서 통과한 뒤에, 점검 시간대에, 담당자 입회로

### T-19 알림·감시 연동 종합
```bash
$CD diagnose --prometheus http://127.0.0.1:9090 --alertmanager http://127.0.0.1:9093 --pushgateway http://127.0.0.1:9091
```
- **기대**: 모든 점검 `OK`. 수신함/Teams 에서 (a) DNS TXT 등록 필요 알림(수동 모드), (b) 배포 실패 알림(T-07), (c) 해소 알림을 각각 1건 이상 확인. Grafana 「certdeploy」 패널에 대상별 상태·마지막 성공 경과·연속 발급 실패가 표시


### T-20 개인키 저장 방식: 평문 ↔ 암호 보호 (둘 다 시험)
- **절차**: 기본(평문)에서 `validate` 가 `평문(권한 600으로 보호)` 로 표시되는지 확인 → 암호 환경변수 준비(`/etc/certdeploy/env` 에 `CERTDEPLOY_KEY_PASSPHRASE`, 설정에 `key_password_env`) → 전환
```bash
$CD key-encrypt
```
  설정에 `key_encryption: passphrase` 를 켜고
```bash
$CD validate
```
```bash
$CD --cert hnu deploy --force --target hnu-web-canary
```
- **기대**: `key-encrypt` 후 키 파일이 `BEGIN ENCRYPTED PRIVATE KEY`(0600), 변환 전 파일은 `*.key.bak-<시각>`(0600)으로 남음(확인 후 `shred -u` 로 삭제), `validate` 가 `암호화됨(…)`, **대상 서버에 배포된 키 파일은 평문(0600)** 이고 서비스 정상. 암호 환경변수를 빼고 실행하면 `개인키 암호화가 켜져 있습니다 — 환경변수 … 를 설정하세요` 로 중단. 되돌리기: `$CD key-decrypt` 후 설정을 `none` 으로
- **재부팅 시험**: 암호 보호 상태에서 재부팅 → 타이머(`renew`)가 환경변수 파일의 암호로 정상 동작하는지(T-12 와 함께)

### T-21 수동 교체 대상(웹방화벽 옵션 C) — API 문서 확인 전에도 가능
- **사전조건**: `certdeploy.waf-manual.example.yml` 기반 설정, `WAF_PFX_PASSWORD` 설정, 메일 수신 가능
```bash
$CD deploy --target waf-main
```
- **기대**: `[waf-main] 수동 교체 대기 — 교체용 파일 …`, 종료 코드 **0**, `state_dir/handoff/waf-main/` 에 파일(디렉터리 0700, 개인키·PFX 0600)이 생기고 **메일로 '수동 교체 필요'** 도착. 담당자가 모니터랩 화면에서 PFX 업로드·적용 → WAF 앞단에서 새 일련번호가 서빙되면
```bash
$CD deploy --target waf-main
```
  `건너뜀 — 수동 교체 확인됨`, 교체용 파일 삭제, 해소 알림. 교체하지 않고 두면 다음 실행마다 같은 안내(3일 후 긴급 표시)와 감시 알림(1일 경고·3일 긴급), Grafana 「수동 교체 대기 장비」 패널에 대기 시간이 표시됨
- `verify` 를 두지 않은 경우: 교체 후 `$CD confirm --target waf-main`
```bash
$CD confirm --target waf-main
```

### T-22 관리자 화면(발급·배포 설정) — 메일 입력·시험 / 인증서별 개인키 보호 선택
- **사전조건**: 설치 매뉴얼 7-5 완료(`certdeploy-admin` 실행, nginx 8443), 인증서(`hnu`, `hannam`) 중 하나 이상이 이미 설치되어 있으면 키 변환까지 확인 가능
- **절차**: ① 브라우저로 `https://<관리 서버>:8443` 로그인(관리자) → 「발급·배포 설정」 ② **메일**: SMTP 입력 → [시험 메일 보내기] → 수신함 확인 → [저장] ③ **개인키 보호**: `hnu` 를 「사용」+암호(12자 이상)로 [적용] → `hannam` 은 「사용 안 함」 유지 ④ CLI 확인
```bash
$CD --cert hnu validate
```
```bash
$CD --cert hnu deploy --force --target hnu-web-canary
```
- **기대**: 시험 메일이 도착하고, 실패 시 화면에 원인(연결 거부·로그인 실패·TLS 오류…)이 표시됨. 저장 후 `validate` 출력에 `관리자 화면(settings.json) 적용: 메일 · 개인키 보호(hnu)`. `hnu` 키 파일이 암호화(`BEGIN ENCRYPTED PRIVATE KEY`)되고 같은 폴더에 평문 `.bak-` 사본이 **남지 않으며**, 배포는 환경변수 없이 성공(대상 서버의 키는 평문). `hannam` 키는 평문 그대로. 「사용 안 함」으로 되돌리면 평문으로 복원. 감사 로그에 `certdeploy_settings_update` 가 기록되지만 비밀번호·암호는 없음
- **권한 확인**: 운영자(operator) 계정으로 로그인하면 「발급·배포 설정」 탭이 보이지 않고, API 직접 호출은 403
- **증거**: 화면 캡처(비밀번호 가림), `validate` 출력, `ls -l /var/lib/certdeploy/hnu/managed/`
- **실패 시**: `journalctl -u certdeploy-admin -n 50`, 화면의 오류 메시지·요청 ID, `$CD diagnose --out`

### T-23 관리자 화면 2단계 인증(TOTP) — 등록·로그인·복구 코드·초기화
- **사전조건**: 관리자 화면 로그인 가능, 휴대폰에 인증 앱(Google/Microsoft Authenticator 등), 시험용 운영자 계정 1개
- **절차**: ① 우측 상단 계정 메뉴 → 「2단계 인증」 → 비밀번호 입력 → 「등록 시작」 → 앱에서 **키 직접 입력(시간 기반)** 으로 표시된 설정 키 입력 → 앱의 6자리 코드 입력 → 「켜기」 → **복구 코드 10개 표시(한 번뿐) 저장** ② 로그아웃 후 재로그인: 비밀번호 입력 시 코드 칸이 나타나고 앱 코드로 로그인됨 ③ 같은 코드를 30초 안에 다시 쓰면 거부됨(재사용 방지) ④ 복구 코드 1개로 로그인(같은 코드는 두 번 쓸 수 없음) ⑤ 관리자가 운영자 계정의 「2단계 인증 초기화」 → 그 계정 세션이 끊기고 다음 로그인은 비밀번호만으로 가능 ⑥ (선택) `CERTPILOT_REQUIRE_MFA=1` 로 서비스 재시작 → 미등록 계정은 로그인 후 등록 창만 열리고 다른 기능은 403
- **기대**: 위 동작대로. 틀린 코드 5회 시 계정 잠금(15분). 감사 로그에 `mfa_enable`·`mfa_disable`·`mfa_reset` 이 남고 설정 키·복구 코드는 없음. 서버 시간이 틀리면 코드가 계속 거부됨(`chronyc tracking` 확인)
- **증거**: 화면 캡처(설정 키·복구 코드 가림), 감사 로그 화면
- **실패 시**: 코드가 항상 틀림 → 서버·휴대폰 시간 차이(±30초 허용), `journalctl -u certdeploy-admin -n 50`. `/var/lib/certdeploy-admin/mfa.key` 를 잃으면 등록된 2단계 인증을 복호화할 수 없으므로 관리자가 계정별로 초기화해야 함

### T-24 배포 승인 단계 — 대기·승인·반려·긴급 우회
- **사전조건**: 설정 파일에 `approval: {required: true, approvers: 2}` (시험은 카나리 대상 1대만 있는 인증서로), 관리자 화면 관리자 계정 2개
- **절차**: ① `$CD --cert hnu deploy --dry-run` → "실제 배포 시에는 승인이 필요합니다" 출력, 요청은 생기지 않음 ② `$CD --cert hnu deploy --force` → 종료 코드 5, 대상 서버 인증서는 **바뀌지 않음**, 승인 요청 알림 도착 ③ 관리자 화면 「배포 승인」에서 관리자 A 승인(1/2) → 같은 계정으로 다시 승인 불가 → 관리자 B 승인(2/2) ④ `$CD --cert hnu deploy` → 배포 성공, 요청 상태 「배포 완료」 ⑤ 다른 인증서로 교체 후 요청이 새로 생기고 이전 승인은 효력 없음 ⑥ 반려 → `deploy` 가 계속 보류, `approval-request` 로 재요청 ⑦ `$CD --cert hnu deploy --emergency "시험"` → 승인 없이 배포, 감사 로그 `approval_bypass`
- **기대**: 위 동작대로. 감사 로그에 `approval_requested/approved/rejected/applied/bypass` 가 남고 Grafana·Prometheus 에 `certdeploy_approval_pending` 지표가 보임. 승인 대기 1일 초과 시 경고 알림(시험 시 규칙 임계를 낮춰 확인 가능)
- **증거**: `$CD approvals --all` 출력, 화면 캡처, 알림 메일
- **실패 시**: `$CD diagnose --out`, `/var/lib/certdeploy/.../approvals.json` 확인(승인자 이름·시각)

### T-25 Windows IIS 자동 배포 (SSH+PowerShell)
- **사전조건**: 설치 매뉴얼 8-1 완료(OpenSSH, 배포용 계정, 관리 모듈), 시험용 IIS 사이트 1개(https 바인딩 있음), 설정에 `type: iis`(`certdeploy.iis.example.yml` 참고), 인증서 SAN 이 사이트 호스트명 포함
- **절차**: ① `$CD preflight --target intra-iis` → 접속·바인딩·현재 지문 표시 ② `$CD plan --target intra-iis` ③ `$CD deploy --target intra-iis` → 배포 후 브라우저/`openssl s_client` 로 새 인증서(일련번호) 서빙 확인 ④ 같은 명령 재실행 → 「건너뜀」(멱등) ⑤ `$CD rollback --target intra-iis` → 바인딩이 이전 인증서로 복귀 ⑥ 실패 주입: 존재하지 않는 바인딩/사이트명으로 배포 → 변경 없이 실패 메시지, 두 바인딩 중 하나만 틀리게 설정해 일부만 바뀐 뒤 복구되는지 확인
- **기대**: 위 동작대로. PowerShell 창이 뜨지 않고, 명령 이력·로그에 PFX·비밀번호가 남지 않음(Windows `Get-WinEvent` PowerShell 로깅이 켜져 있으면 스크립트 블록 로그에 임시 비밀번호가 남을 수 있음 → 보안팀 확인). `Cert:\LocalMachine\My` 에 새 인증서가 추가됨(이전 인증서는 삭제하지 않음)
- **증거**: preflight/deploy 출력, 브라우저 인증서 정보, `certutil -store My` 출력
- **실패 시**: 출력의 `IIS 바인딩 실패: …` 메시지, Windows `C:\ProgramData\ssh\logs\sshd.log`, PowerShell 7 이면 `powershell: pwsh` 설정, `$CD diagnose --out`

### T-26 WebtoB / JEUS 자동 배포
- **사전조건**: 시험용 WebtoB·JEUS 인스턴스(운영과 분리 권장), 설정에 `type: webtob`/`jeus`(`certdeploy.webtob-jeus.example.yml` 참고), 현재 설정의 경로·실행 계정·재기동 명령 확인, 배포용 계정의 sudoers 제한 설정(8단계)
- **절차**: ① `$CD preflight --target sso-webtob` (접속·디렉터리 쓰기·현재 TLS) ② `$CD plan` 으로 파일·소유자·명령 확인 ③ `$CD deploy --target sso-webtob` → 서버에서 파일 권한·소유자(`ls -l`) 확인, 새 인증서 일련번호 서빙 확인 ④ 개인키 패스프레이즈를 쓰는 경우: 재기동이 입력 대기로 멈추지 않는지 확인 ⑤ 재기동 명령을 일부러 틀리게 설정해 실패 시 **이전 파일로 롤백**되고 서비스가 정상인지 확인 ⑥ JEUS: 키스토어 비밀번호가 JEUS 설정의 keypass 와 같은지, 별칭(alias)이 기존과 같은지 확인, 재기동 필요 여부 확인
- **기대**: 위 동작대로. 배포 직후 WebtoB/JEUS 가 새 파일을 읽어 정상 기동, 실패 시 이전 인증서로 복구
- **증거**: `ls -l` 결과, 서빙 일련번호, 재기동 로그(WebtoB `wsboot` 출력, JEUS 서버 로그)
- **실패 시**: 기동 로그의 SSL 오류(키 불일치·패스프레이즈·권한·별칭), `$CD diagnose --out`. 제품 버전별 차이는 해당 버전 매뉴얼로 확인

---
## 결과 기록표
| ID | 일시 | 수행자 | 합격(O/X) | 증거 파일/링크 | 비고(실패 시 번들 경로) |
|---|---|---|---|---|---|
| T-01 | | | | | |
| T-02 | | | | | |
| T-03 | | | | | |
| T-04 | | | | | |
| T-05 | | | | | |
| T-06 | | | | | |
| T-07 | | | | | |
| T-08 | | | | | |
| T-09 | | | | | |
| T-10 | | | | | |
| T-11 | | | | | |
| T-12 | | | | | |
| T-13 | | | | | |
| T-14 | | | | | |
| T-15 | | | | | |
| T-16 | | | | | |
| T-17 | | | | | |
| T-18 | | | | | |
| T-19 | | | | | |
| T-20 | | | | | |
| T-21 | | | | | |
| T-02a | | | | | |
| T-22 | | | | | |
| T-23 | | | | | |
| T-24 | | | | | |
| T-25 | | | | | |
| T-26 | | | | | |
