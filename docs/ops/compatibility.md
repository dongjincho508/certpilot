# 호환성 가이드 — DNS 제공자 · 웹방화벽(WAF) · 어플라이언스

환경마다 DNS 업체와 장비가 달라도 **설정으로 선택**할 수 있게 만들었다. 이 문서는 무엇을 어떻게 고르는지, 어디까지 검증했는지 정리한다.

> **검증 범위**: 아래 모든 방식은 로컬 가짜 서버(가짜 CA·DNS API·WAF 관리 API)로 전 과정을 시험했다. **실제 업체 서비스·장비로는 실행하지 못했다.** 실제 장비의 API 경로·필드는 제품 문서와 장비로 확인해야 하며, 확인 전에는 반드시 시험 장비/스테이징에서 먼저 한다.

## 1. DNS 제공자 (인증서 자동 발급의 TXT 등록 방식)
`acme.dns.mode` 로 선택한다. 자세한 절차는 [자동 발급 가이드](auto-issue.md).

| mode | 대상 | 필수 설정 | 비고 |
|---|---|---|---|
| `manual` | **API 없는 모든 DNS** | — | 안내된 TXT 를 사람이 등록 → 재실행하면 발급. 가장 호환성이 높음 |
| `infoblox` | Infoblox | `host`, `user_env`, `password_env` (+`view`, `wapi_version`) | WAPI `record:txt` |
| `rfc2136` | **BIND, PowerDNS, Windows DNS, Infoblox DDNS 등 표준 동적 갱신 지원 서버** | `server`, `zone` (+`tsig_key_name`, `tsig_secret_env`, `tsig_algorithm`) | TSIG 권장. 서버 쪽 update-policy 로 `_acme-challenge` TXT 만 허용 |
| `cloudflare` | Cloudflare | `token_env` (+`zone`) | 토큰 권한: 해당 영역 DNS 편집만 |
| `powerdns` | PowerDNS Authoritative API | `api_url`, `api_key_env`, `zone` | |
| `webhook` | 사내 DNS 관리 시스템·자체 API | `url_env` (+`auth_header_env`) | `POST {action: present\|cleanup, fqdn, value}` 를 받는 작은 중계 서비스를 두면 어떤 시스템이든 연결 |
| `exec` | **그 밖의 모든 업체**(가비아, 후이즈, Route53, Azure, Google 등) | `cmd` (+`env_pass`, `timeout`) | `<cmd> present\|cleanup <fqdn> <value>` 호출(셸 미사용). 종료 코드 0 = 성공 |
| (lego 엔진) | **lego 가 지원하는 100여 개 업체** | `lego:` 블록의 `dns_provider` | `acme:` 대신 `lego:` 를 쓰면 lego 가 처리. `lego dnshelp -c <업체>` 로 변수 확인 |

설정 예
```yaml
acme:
  email: cert-admin@hnu.kr
  domains: ["hnu.kr", "*.hnu.kr"]
  dns:
    mode: rfc2136                       # 또는 cloudflare / powerdns / webhook / exec / infoblox / manual
    check_resolvers: ["203.0.113.53"]   # 전파 확인용(권한 DNS IP 권장)
    rfc2136:
      server: 203.0.113.53              # [:포트], TCP 53
      zone: hnu.kr
      tsig_key_name: acme-key.
      tsig_secret_env: ACME_TSIG_SECRET # base64 비밀은 /etc/certdeploy/env 에
```
`exec` 스크립트 예(Route53 — AWS CLI 가 설치·자격 증명된 경우의 구조 예시, 실제 값은 환경에 맞게):
```bash
#!/bin/bash
# $1=present|cleanup  $2=_acme-challenge.hnu.kr  $3=TXT 값
set -euo pipefail
ACTION=$([ "$1" = present ] && echo UPSERT || echo DELETE)
aws route53 change-resource-record-sets --hosted-zone-id "$ROUTE53_ZONE_ID" --change-batch \
  "{\"Changes\":[{\"Action\":\"$ACTION\",\"ResourceRecordSet\":{\"Name\":\"$2\",\"Type\":\"TXT\",\"TTL\":60,\"ResourceRecords\":[{\"Value\":\"\\\"$3\\\"\"}]}}]}"
```
※ 스크립트에는 `env_pass: [ROUTE53_ZONE_ID, AWS_PROFILE ...]` 로 **필요한 환경변수만** 허용한다(나머지 비밀은 전달되지 않음). 같은 이름에 TXT 값이 둘(루트·와일드카드)이므로 UPSERT 는 기존 값을 덮어쓰지 않도록 업체 API 의 "추가" 동작을 확인한다.

## 2. 웹방화벽(WAF)·로드밸런서·어플라이언스 배포
인증서는 **WAF 에도 올라가야** 사용자에게 보이는 인증서가 바뀐다. 장비가 인증서를 받는 방법에 따라 세 가지 중 고른다.

| 방식 | 대상 | 설정 | 비고 |
|---|---|---|---|
| **① HTTP API** | 관리용 REST API 가 있는 WAF·LB | `type: http_api` + `api.steps` | 로그인(세션 쿠키·토큰) → 업로드(JSON/폼/multipart/PFX) → 적용 → TLS 로 확인, 실패 시 이전 인증서로 롤백 |
| **② SSH(CLI)** | CLI 로 반영하는 장비(F5 tmsh 등) | `type: generic` + 파일 + `reload_cmd` | 기존 SSH 배포와 같은 방식(점검·롤백 포함) |
| **③ 수동 교체(`type: manual`)** | API/CLI 가 없거나 아직 확인 전인 장비(모니터랩 등) | `type: manual` + `manual:` | `certdeploy` 가 **교체용 파일(PEM/PFX) 준비 → 메일로 알림 → 미교체면 독촉(3일 지나면 긴급, 감시 알림 1일/3일) → WAF 앞단 서빙 인증서로 완료 자동 확인**(또는 `confirm`). 교체 담당자는 GUI 에서 파일만 올리면 된다. 예시: `certdeploy.waf-manual.example.yml` |

### ③ 수동 교체 상세 (`type: manual`)
- `deploy` 가 `state_dir/handoff/<대상>/`(0700)에 `fullchain.pem`·`cert.pem`·`chain.pem`·`privkey.pem`(0600)·`server.pfx`(0600, 비밀번호는 환경변수)·`INSTRUCTIONS.txt` 를 준비하고 메일(Alertmanager/SMTP)로 알린다. 상태는 **수동 교체 대기**(`manual_pending`)이며 **실패가 아니다**(종료 코드 0, `run_ok` 유지)
- 교체 후 다시 `certdeploy deploy`(또는 타이머)가 `verify` 로 서빙 일련번호를 확인하면 자동 완료 → 교체용 파일(개인키 사본) 삭제·알림 해소. `verify` 가 없으면 `certdeploy confirm --target <이름>`
- 감시: 지표 `certdeploy_target_manual_pending`/`..._since_timestamp_seconds`, 알림 `CertDeployManualReplacementPending`(1일 초과 경고)·`…Overdue`(3일 초과 긴급), Grafana 「수동 교체 대기 장비」 패널
- 주의: 교체용 파일에는 **개인키가 들어 있다** — 전달은 SSH/보안 경로로만, 완료되면 삭제됨. 이중화 장비는 양쪽을 각각 대상으로 등록

### ① HTTP API (`type: http_api`)
- **구조 예시**: [`certdeploy/certdeploy.waf.example.yml`](../../certdeploy/certdeploy.waf.example.yml) — 경로·필드명은 가상이며 제품 API 문서로 바꿔야 한다
- 자리표시자: `{cert_pem}` `{chain_pem}` `{fullchain_pem}` `{key_pem}` `{pfx_b64}` `{pfx_password}` `{serial}` `{not_after}` `{name}`, 이전 배포본 `{prev_*}`(rollback_steps), 환경변수 `{env:NAME}`, `vars`, 앞 단계 `extract` 값
- 본문: `json` / `form` / `body` / `multipart`(파일 업로드), 세션 쿠키는 단계 사이에 유지
- 성공 판정: `expect_status`(기본 2xx), `expect_body`(정규식), `expect_json`(`{"$.code": 0}` — **HTTP 200 인데 본문이 실패인 장비 대응**)
- 대기: 단계의 `wait: 초` — '적용' 뒤 장비가 반영될 시간을 두고 다음 단계·TLS 확인으로 넘어감(확인은 `options.verify_attempts/verify_interval` 로 재시도)
- 추출: `extract: {변수: "$.a.b[0]" | "header:Set-Cookie" | "regex:패턴"}`
- 안전장치: 요청 본문(개인키 포함)·계정은 로그·진단 번들에 남지 않음, `plan`/`preflight` 는 요청을 보내지 않음(관리 주소 도달성만), `rollback_steps` 가 없으면 `preflight` 가 경고, 직전 성공 배포본은 `state_dir/api-bundles/<대상>/` 에 0600 으로 보관, `rollback --target` 수동 롤백 지원(수동 롤백 때는 `extract` 하는 로그인 단계까지 다시 실행)
- 관리 화면이 사설 인증서면 `ca_file` 로 신뢰할 CA 를 지정(`verify_tls: false` 는 비권장)

### 제품 도입 시 확인할 것 (WAF 담당자에게)
1. **인증서 교체용 관리 API 가 있는가?** (문서·예제, 인증 방식: 계정/토큰/세션, CSRF 헤더 필요 여부)
2. 인증서·키를 어떤 형식으로 받는가? (PEM 텍스트, 파일 업로드, PFX+비밀번호)
3. **업로드 후 '적용' 단계가 따로 있는가?** (설정 반영/커밋, 서비스 재시작 영향)
4. 기존 인증서를 같은 이름으로 **덮어쓸 수 있는가**, 이전 것으로 되돌리는 방법
5. 이중화(HA) 구성이면 한 쪽에 올리면 동기화되는가, 양쪽에 모두 올려야 하는가(대상을 둘로 등록)
6. 도메인별·가상 호스트별로 인증서가 따로 걸려 있는가(여러 번 올려야 하는가)
7. 서비스 영향(세션 끊김) 허용 시간대

> **어떤 WAF 인가요?** 제품명·모델·버전(예: 국내 WAF 제품, F5, FortiWeb, 클라우드 WAF)과 관리 API 문서를 알려 주면 위 질문의 답을 채워 해당 제품용 설정 프로파일(검증 가능한 범위의 가짜 서버 시험 포함)을 만들 수 있다.

### 클라우드 WAF/로드밸런서 (구조 예시)
- AWS(ALB·CloudFront): `aws acm import-certificate` 를 `type: generic`(로컬) 의 `reload_cmd` 로 호출 — `files` 로 인증서·키를 파일로 만들고 CLI 가 읽게 한다. 자격 증명은 환경변수(`hook_env`)로 최소 전달
- Cloudflare 프록시: 엣지 인증서는 Cloudflare 가 관리(원본 서버 인증서만 이 시스템으로 배포)

## 3. WAF 와 인증서 발급의 관계
- 발급은 **DNS-01** 이라 WAF 가 HTTP 요청을 막아도 영향이 없다(HTTP-01 은 `/.well-known/acme-challenge` 를 WAF 가 막을 수 있어 쓰지 않는다)
- WAF 뒤 서버 인증서와 WAF 앞단 인증서가 **둘 다** 필요한 구조(SSL 종단 + 재암호화)면 대상을 각각 등록한다

## 4. 새 환경에 맞추기 (확장 방법)
| 필요 | 방법 |
|---|---|
| 지원 목록에 없는 DNS 업체 | `dns.mode: exec`(스크립트) 또는 `webhook`(중계 서비스), 또는 `lego:` 엔진 |
| 지원 목록에 없는 장비 | `http_api`(steps 로 기술) 또는 `generic`(SSH 명령) |
| 서로 다른 CA | 내장 ACME 는 `acme.directory` 로 ACME 지원 CA 지정(EAB 가 필요한 CA 는 아직 미지원) |

## 5. 알려진 한계
- 내장 ACME 의 `_acme-challenge` **CNAME 위임**, **EAB**(외부 계정 바인딩) 미지원 — 필요하면 추가 개발
- `http_api` 는 바이너리 본문(원시 octet-stream 업로드)과 클라이언트 인증서(mTLS) 인증은 아직 지원하지 않는다(PEM/PFX 를 JSON·폼·multipart 로 보내는 방식만)
- 실제 업체·장비 검증은 시험 환경에서 별도로 필요

## 6. 업로드와 '적용'이 따로 있는 장비(예: 모니터랩 웹방화벽) 주의점
- `steps` 를 **업로드 → 적용** 순서로 쓰고, 적용 뒤 `wait` 와 `verify`(WAF 앞단 VIP 에서 서빙 일련번호 확인)로 반영을 확인한다. 적용이 실패하거나 새 인증서가 안 보이면 `rollback_steps`(이전 인증서 업로드 → 적용)가 실행된다
- **'적용'이 인증서만 반영하는지, 대기 중인 다른 설정 변경까지 한꺼번에 반영하는지** 제품 문서로 확인한다. 후자라면 다른 담당자가 저장만 해 둔 변경이 인증서 배포 때 같이 운영에 적용될 수 있으므로, 배포 시간대에는 설정 변경을 잠그거나 먼저 정리한다
- 적용 시 **서비스 순단·세션 끊김**이 있는지, 이중화(HA)면 한쪽 적용이 상대에게 동기화되는지(아니면 대상을 둘로 등록) 확인한다
- 적용 단계가 GUI 에만 있고 API/CLI 가 없으면 자동화할 수 없다 → 수동 교체 + `check` 감시
