# 테스트 시나리오 (VM 시험용 상세 절차)

[VM 설치·테스트 매뉴얼](vm-install-and-test.md) 7절의 T-01~T-13 을 **그대로 따라 할 수 있게** 풀어 쓴 것이다. 각 시나리오는 *사전조건 → 절차 → 기대 결과 → 증거 → 실패 시* 순서다.
결과는 마지막 [결과 기록표](#결과-기록표)에 적고, 실패하면 매뉴얼 8절 방식으로 번들을 보낸다.

공통 준비(발급·배포 VM, 한 번만):
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
$CD csr --domains '*.univ.example,univ.example' --country KR --org '대학명'
```
  출력된 CSR 을 CA 에 제출 → 받은 파일을 `/tmp` 에 올림 →
```bash
$CD import --file /tmp/server.cer --file /tmp/intermediates.p7b --dry-run
```
- **기대**: 서버 인증서 일련번호·유효기간·SAN 표시, `중간 CA 1개`(필요 시 "자체 서명 루트 제외" 안내), `--dry-run` 이라 설치 안 함. 개인키 내용은 어디에도 출력되지 않음
- **오류 확인(선택)**: 다른 키로 시도(`--key-file`)하면 "일치하는 서버 인증서가 없습니다", 만료 인증서면 "만료"로 종료 코드 2
- **증거**: 출력 전체(키 없음), `openssl verify` 결과
```bash
openssl verify -CAfile /path/to/root.pem -untrusted /var/lib/certdeploy/managed/fullchain.pem /var/lib/certdeploy/managed/fullchain.pem
```
- **실패 시**: 번들과 CA 가 보낸 파일 이름 목록(파일 자체는 인증서라 공유 가능, 키는 절대 보내지 않는다)

### T-05 단건(canary) 배포
- **절차**
```bash
$CD plan
```
```bash
$CD import --file /tmp/server.cer --file /tmp/intermediates.p7b
```
```bash
$CD deploy --target web-canary
```
- **기대**: `[web-canary] 배포 완료`, `요약: 배포 완료 1`, 종료 코드 0. 대상에는 백업 `*.bak-<시각>` 이 남음
- **확인**
```bash
echo | openssl s_client -connect www1.univ.example:443 -servername www1.univ.example 2>/dev/null | openssl x509 -noout -serial -enddate
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
$CD deploy --target web-canary
```
- **기대**: `건너뜀 — 이미 새 인증서를 서빙 중`, 재로드 없음(서버 로그에 reload 기록 추가 없음), 종료 코드 0
- **실패 시**: 건너뛰지 않고 재배포했다면 `status` 출력과 번들(서빙 일련번호 확인 실패 여부)

### T-07 실패 → 자동 롤백
- **목적**: 배포 중 문제가 나도 서비스가 이전 인증서로 유지되는지
- **절차(안전한 주입)**: 시험 대상(운영 트래픽 없는 서버 권장)의 `check_cmd` 를 `"false"` 로 바꾸고 강제 재배포
```bash
$CD deploy --target web-test --force
```
- **기대**: `[web-test] 롤백됨 — 설정 점검 실패 … → 이전 파일로 롤백함`, 종료 코드 1, 알림(메일/Teams/Alertmanager) 수신, 해당 서버의 서빙 인증서는 **이전 것 그대로**, Pushgateway 지표 `certdeploy_run_ok 0`
- **복구**: `check_cmd` 를 원복하고 `$CD deploy --target web-test` → `배포 완료`, 해소 알림, `run_ok 1`
- **증거**: 출력, 알림 화면, Grafana certdeploy 패널
- **실패 시**: 롤백 문구에 "롤백도 실패 — 수동 조치 필요"가 보이면 즉시 중단하고 `.bak-` 파일로 수동 복구 후 번들 전달

### T-08 전체 배포 (순서·canary)
- **절차**
```bash
$CD preflight
```
```bash
$CD deploy
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
| WebtoB/JEUS | 인증서 형식, 재기동 명령 확인(제품 문서) |
| IIS | `deploy-iis.ps1` 로 가져오기·바인딩 교체 후 서빙 일련번호 확인 |
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
- **절차**: 감시 VM 의 Pushgateway 를 중지(`docker compose stop pushgateway`)한 상태에서 `$CD deploy --force --target web-test`
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
