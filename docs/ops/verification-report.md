# 검증 보고서 (2026-10-28 기준)

무엇을 어떻게 검증했고, **무엇이 아직 검증되지 않았는지**를 구분해 기록한다. "자동 테스트 통과"는 *가짜 서버·로컬 환경에서의 동작*을 뜻하며 실제 장비·서비스에서의 동작을 보증하지 않는다.

## 1. 한눈에
| 구분 | 결과 |
|---|---|
| 자동 테스트 | **699개 통과·건너뜀 0 (promtool·amtool 포함)** (`scripts/check.sh`, promtool/amtool 포함 실행 기준) |
| 정적 보안 분석(bandit, 중간 이상) | 지적 **0건** (CI `security` 잡) |
| 의존성 취약점(pip-audit) | 알려진 취약점 **0건** |
| 실제 바이너리로 확인 | Prometheus 3.5.0 · Alertmanager 0.28.1 · ssl_exporter 2.4.3(설정 검증·규칙 단위 시험·실수집), OpenSSL(체인 검증), JDK keytool(JKS), systemd-analyze(유닛), docker compose config |
| **실제 장비·서비스로 확인** | **없음** — VM·실제 Let's Encrypt·Infoblox·웹서버·WAF·SMTP 검증은 [VM 시험](test-scenarios.md)에서 수행 |

## 2. 기능별 검증 현황
범례: ✅ 자동 테스트로 확인 · 🔶 실제 바이너리/도구로 부분 확인 · ⬜ 실제 환경 확인 필요(VM 시험 ID)

### 감시 스택 (`monitoring/`)
| 기능 | 검증 | 실제 환경 확인 |
|---|---|---|
| 수집 대상 파일(CSV→file_sd), 인벤토리 도구 | ✅ `test_monitoring.py` | — |
| 알림 규칙 9종+certdeploy 규칙 | ✅ promtool 규칙 단위 시험, PromQL 구문 | ⬜ T-02 (메일/Teams 수신) |
| Alertmanager 설정·라우팅·템플릿 | 🔶 amtool check-config, 실제 Alertmanager 로 페이로드 확인 | ⬜ T-02 |
| 대시보드 15패널 쿼리 | 🔶 **실제 Prometheus+ssl_exporter 로 모든 패널 쿼리 실행**(예상 화면 이미지) | ⬜ T-01 (Grafana 렌더링은 미확인) |
| docker compose(5서비스, localhost 바인딩, 비밀번호 필수) | 🔶 `docker compose config` 렌더링·검증 | ⬜ T-01 (실제 기동) |
| SELinux 라벨(`:ro,z`), nginx 역프록시 설정 | ✅ 정적 검사 | ⬜ 설치 5~6단계 |

### certdeploy — 인증서 준비
| 기능 | 검증 | 실제 환경 확인 |
|---|---|---|
| 수동 인증서: `csr` / `import`(PEM·DER·p7b·PFX, 체인 정렬, 루트 제외, 키 일치·만료·SAN 검증, 원자적 설치·백업) | ✅ `test_certdeploy_manual.py` 25개, 🔶 OpenSSL `verify` 교차 검증, 퍼징 | ⬜ T-04 (실제 CA 가 준 파일) |
| **내장 ACME(RFC 8555, DNS-01)**: 계정·주문·와일드카드+루트 TXT 2개·검증·발급·설치·TXT 정리·스테이징 격리·갱신 판정·속도제한 보호 | ✅ `test_certdeploy_acme.py` 30개 — **가짜 CA 가 JWS 서명·nonce·키 인증을 실제로 검증**, RFC 7638 지문 시험값 일치 | ⬜ **T-14~T-16 (실제 Let's Encrypt)** |
| DNS 제공자 `manual` 두 단계(TXT 안내→등록→재실행, 일부만 등록 시 대기) | ✅ 전 과정 | ⬜ T-15 |
| DNS 제공자 `infoblox`(WAPI) | ✅ 가짜 WAPI(인증·중복 방지·선택 삭제·오류) | ⬜ **T-14 (WAPI 경로·버전·뷰는 문서 기준, 실장비 미확인)** |
| DNS 제공자 `rfc2136`(TSIG), `cloudflare`, `powerdns`, `webhook`, `exec` | ✅ 제공자별 **발급 전 과정** + 오류(NOTAUTH/NOTZONE/401/403/종료 코드) | ⬜ T-17 (쓰는 것만) |
| lego 엔진(`lego:` 블록) | ✅ 가짜 lego 로 명령 구성·실패·백오프 | ⬜ lego 실행 자체 미확인(설치 7-3) |
| DNS 전파 확인(UDP/TCP TXT 조회, 255자 초과 조각, NXDOMAIN) | ✅ 실제 UDP 소켓 | ⬜ T-14 |

### certdeploy — 배포
| 기능 | 검증 | 실제 환경 확인 |
|---|---|---|
| 파일 배포(Apache/Nginx/Node.js/Tomcat/generic), 원자적 교체·백업·권한, 점검→재로드→서빙 일련번호 확인, 자동 롤백, canary/순서, 멱등성, 동시 실행 잠금 | ✅ `test_certdeploy_engine/features/ssh/cli.py`(SSH 는 프로세스 내 paramiko 서버) | ⬜ T-05~T-09 (실제 서버·제품별 재로드) |
| PKCS#12 / **JKS**(Tomcat·JEUS) 변환 | ✅ + 🔶 실제 keytool 로 확인 | ⬜ T-09 (제품이 읽는지) |
| strict TLS 검증(체인·호스트명·사설 CA), HTTP 헬스체크, soak, pre/post 훅(최소 환경) | ✅ | ⬜ T-05 |
| **웹방화벽/어플라이언스 `http_api`**: 로그인(쿠키·토큰)→업로드(JSON/폼/multipart/PFX)→적용(`wait`)→확인, 응답 본문 코드 판정, 실패 시 이전 배포본으로 롤백, 수동 롤백, 비밀 비노출, 설정 검증 | ✅ `test_certdeploy_waf.py` 24개 — 가짜 WAF 관리 API | ⬜ **T-18 (모니터랩 API 문서 확보 후; 현재 설정 예시는 가상 필드)** |
| IIS | 초안 스크립트만(`deploy-iis.ps1`), **미검증** | ⬜ 별도 협의 |
| 알림(Alertmanager·SMTP·Webhook[slack/teams/generic]), 지표(textfile·Pushgateway), 해시 체인 감사 로그, 보고서 | ✅ 가짜 수신기·실제 Alertmanager 페이로드 | ⬜ T-02, T-10, T-19 |
| 암호화 백업/복원(AES-256-GCM/scrypt), 키 파일 권한 점검 | ✅ | ⬜ T-11 |
| **수동 교체 대상 `type: manual`**(WAF 옵션 C): 교체용 파일(PEM/PFX) 준비·메일 안내·독촉 승격·서빙 확인으로 자동 완료·`confirm`·개인키 사본 삭제, 지표·알림 규칙(1일/3일)·Grafana 패널 | ✅ `test_certdeploy_options.py`(수동 교체 9개) + promtool 규칙 단위 시험 | ⬜ **T-21** (모니터랩 화면에서 실제 교체) |
| **개인키 저장 방식 선택**: `key_encryption: none/passphrase` — import·csr·내장 ACME(대기 키 포함) 저장본 암호화, 배포 때만 복호화, `key-encrypt`/`key-decrypt` 전환·백업, 설정↔실제 상태 불일치 점검 | ✅ `test_certdeploy_options.py`(암호화 8개) | ⬜ **T-20** (재부팅·타이머 환경에서 암호 공급) |
| 알림 시험 `notify-test`(메일 우선 설정), 전송 실패 진단 이벤트 | ✅ | ⬜ **T-02a** (실제 SMTP 수신) |
| **관리자 화면(발급·배포 설정)**: 메일 입력·저장·시험 메일(원인 분류), 인증서별 개인키 보호 사용/사용 안 함 선택·즉시 변환(평문 사본 검증 후 삭제)·암호 변경, 현황(만료·대상 상태), 관리자 전용·감사 기록(비밀 제외), 설정 화면 값이 CLI·타이머에 자동 적용 | ✅ `test_certdeploy_admin.py`(가짜 SMTP 서버로 실제 메일 전송·인증 실패·수신 거부 확인, 키 변환·롤백 안전) + 실제 브라우저 조작 확인 | ⬜ **T-22** (systemd·nginx 8443 구성, 실제 SMTP) |
| `check`(Nagios 형식 종료 코드), `schema`, `diagnose`, `trace`, `--debug` | ✅ `test_prevm_checks.py`, `test_debug_tools.py` | ⬜ T-19 |

### 보안 설계 (코드로 확인된 것)
- 개인키·계정은 로그·트레이스·진단 번들·알림에 남지 않음(마스킹 + 테스트로 부재 확인), 개인키 파일 0600/디렉터리 0700, 대기 키는 사용 후 삭제
- 훅/스크립트에는 최소 환경변수만 전달(허용 목록), 외부 호출은 http/https 만(`file://` 등 거부), SSH 는 호스트 키 사전 등록 필수(RejectPolicy)
- 스테이징 발급분은 운영 위치에 설치·배포되지 않음, 발급 실패 후 대기(속도 제한 보호), 모든 배포는 canary 순차·실패 시 중단
- 감사 로그 해시 체인(변조 탐지), 관리자 전용 진단 API

## 3. 이 환경에서 확인 불가능한 것 (VM 에서 처음 확인)
| 항목 | 이유 | 확인할 시험 | 실패 시 대응 |
|---|---|---|---|
| 실제 Let's Encrypt 발급 | 외부 접속 불가 | T-14~T-16 | 스테이징 로그의 `acme/*` 단계로 수정, `manual` 모드로 우회 |
| Infoblox WAPI 동작(경로·뷰·버전) | 장비 없음 | T-14 | 응답 본문이 오류 메시지에 포함됨 → 수정, 또는 `rfc2136`/`exec` 로 전환 |
| 실제 DNS 조건(CAA·CNAME·53 포트·권한 DNS) | 조회 불가 | [준비 체크리스트 2-C](pre-vm-checklist.md) | 요청 문구 ①~④ |
| 웹서버별 재로드(Apache/Tomcat/WebtoB/JEUS/IIS/Node.js) | 제품 없음 | T-09 | 제품 문서로 `reload_cmd` 조정 |
| 모니터랩 WAF 인증서 반영 | API 문서 없음 | T-18 | API/CLI 없으면 WAF 만 수동 교체 |
| Grafana 실제 화면, docker compose 실제 기동 | Docker 데몬·Grafana 실행 불가 | T-01 | `docker compose logs` |
| SMTP/Teams 발송 | 외부 접속 불가 | T-02, T-19 | Alertmanager 로그 |
| Rocky Linux 10 OS 명령 | OS 없음 | 설치 1~6단계 | 막힌 단계의 명령·출력 전달 |
| lego 실행 | 다운로드·실행 제한 | (lego 사용 시) 설치 7-3 | 내장 ACME 사용 |

## 4. 알려진 한계 (설계상 미지원)
- 내장 ACME: `_acme-challenge` **CNAME 위임**, **EAB**(외부 계정 바인딩) 미지원
- `http_api`: 원시 바이너리 업로드, 클라이언트 인증서(mTLS) 인증 미지원
- IIS 자동 배포 미구현(초안 스크립트만)
- 인증서 상태의 상세 웹 화면은 Grafana 대시보드가 담당하고, 관리자 화면은 설정(메일·개인키 보호)과 요약 현황만 제공한다(Render 의 CertPilot 앱은 사용하지 않음)
- 관리자 화면에서 저장하는 SMTP 비밀번호·개인키 암호는 `settings.json`(0600, certdeploy 계정)에 평문으로 저장된다(서버 침해 시 노출 — 파일 단독 유출은 디스크 암호화·접근 통제로 방어)
- 단일 관리 서버(고가용성 없음): 장애 시 백업([T-11](test-scenarios.md))으로 새 VM 에 복원

## 5. 테스트 구성 (파일별)
| 파일 | 개수 | 내용 |
|---|---|---|
| `tests/test_prevm_checks.py` | 246 | 문서 정합성(bash 문법·명령·링크·이미지 태그), 설정 예시↔스키마, systemd·compose, OpenSSL 교차 검증, 퍼징, check/export-targets, 보안 보강, 50대 성능 |
| `tests/test_certdeploy_features.py` | 50 | 멀티 인증서, 훅, soak, 백업, 알림 3종, 지표, 감사, scaffold 등 부가 기능 |
| `tests/test_api.py` | 39 | CertPilot API(보류 앱): 인증·권한·서버·조회 |
| `tests/test_certdeploy_engine.py` | 33 | 배포 엔진: 교체·롤백·canary·멱등·잠금 |
| `tests/test_certdeploy_acme.py` | 30 | 내장 ACME + DNS 제공자 7종(가짜 CA/WAPI/DNS/Cloudflare/PowerDNS/RFC2136/웹훅/exec) |
| `tests/test_monitoring.py` | 29 | 감시 설정: promtool/amtool, 규칙 단위 시험(수동 교체 알림 포함), 대시보드 15패널, 도구 |
| `tests/test_policy.py` | 28 | 원격 명령 정책(읽기 전용 화이트리스트) |
| `tests/test_certdeploy_cli.py` | 26 | certdeploy CLI·lego 래퍼·설정 검증 |
| `tests/test_certdeploy_manual.py` | 25 | 수동 인증서 csr/import |
| `tests/test_certdeploy_waf.py` | 24 | 웹방화벽 HTTP API 배포(옵션 A) |
| `tests/test_scanner.py` | 22 | CertPilot 조회기(보류 앱) |
| `tests/test_certdeploy_admin.py` | 23 | 관리자 화면: 메일·개인키 보호 저장/적용/변환, 시험 메일(가짜 SMTP), 웹 API 권한·감사·비밀 비노출 |
| `tests/test_certdeploy_options.py` | 21 | 개인키 암호 사용/미사용 옵션, 수동 교체 대상(옵션 C), 알림 시험 |
| `tests/test_debug_tools.py` | 19 | 진단 트레이스·진단 API·trace/diagnose·감시 점검 |
| `tests/test_certdeploy_bundle.py` | 18 | 번들 검증·PKCS12/JKS 변환 |
| `tests/test_sshkey.py` | 18 | SSH 키 정규화(보류 앱) |
| `tests/test_status.py` | 13 | 상태 판정(보류 앱) |
| `tests/test_audit_storage.py` | 8 | 감사 로그 해시 체인 |
| `tests/test_cert_parser.py` | 7 | 인증서 파서 |
| `tests/test_ssh_integration.py` | 6 | SSH 통합(보류 앱) |
| `tests/test_certdeploy_ssh.py` | 5 | SSH 전송(프로세스 내 서버) |
| `tests/test_cli.py` | 5 | certpilot-cli |
| `tests/test_tls_probe.py` | 3 | TLS 프로브 |
| `tests/test_install_scripts.py` | 31 | 자동 설치 스크립트(문법·shellcheck·dry-run 무변경·입력 검증·비밀 미출력)·Alertmanager 렌더링(amtool)·Kickstart(ksvalidator RHEL10). **실제 Rocky 10 실행은 미검증** |
| `tests/test_discover.py` | 25 | 자동 탐색(범위·가드, 인증서 해석, 분류, 실제 TLS 소켓 조회, 비교, CLI, 지표·알림 규칙). 실제 대역 스캔은 미검증 |
| `tests/test_mfa.py` | 19 | 2단계 인증(RFC 6238 시험 벡터, 등록·로그인·재사용 방지·복구 코드·잠금·해제·초기화·정책 강제·암호화 저장·DB 이전·화면 연결). 실제 인증 앱과의 연동·브라우저 화면은 미검증 |
| `tests/test_approval.py` | 34 | 배포 승인(정책 검증, 1·2인 승인, 요청자 제한, 반려·만료·대체, CLI 실제 배포 흐름, 긴급 우회, 감사, 관리자 화면 API, 알림 규칙). 실제 SSH 대상과의 조합은 미검증 |
| `tests/test_iis.py` | 32 | Windows IIS 배포(설정 검증·주입 방지, 스크립트 생성·비밀 비노출, 배포·멱등·부분 실패 복구·롤백·preflight, 가짜 Windows). **실제 PowerShell/Windows 실행은 미검증** |
| `tests/test_webtob_jeus.py` | 21 | WebtoB/JEUS 유형(설정 검증, 암호화 개인키 2형식, 소유자, PKCS12 키스토어, 재로드 실패 롤백, 비밀번호 누락 시 무변경). **실제 WebtoB/JEUS 제품과 재기동 명령은 미검증** |
| `tests/test_notify_channels.py` | 35 | 알림 확장(웹훅 5형식·심각도 필터·반복 억제, ServiceNow/Jira/일반 티켓 생성·중복 방지·해소·실패 재시도, YAML 검증, 관리자 화면 저장/마스킹/시험, 감사 로그 비밀 비노출). **실제 ServiceNow/Jira/Teams 는 미검증** |
| `tests/test_backup_auto.py` | 35 | 백업 자동화(설정 검증, 수집·SQLite 스냅샷·제외·누락 보고, 암호화·변조 검출, GFS 보관 정리, 폴더/SSH 외부 복사와 실패 격리, 지표·상태, CLI, 심층 검증, 복구 계획/적용, 악성 아카이브 거부, 관리자 화면). **실제 NAS·SSH 서버·새 VM 복구는 미검증** |
| `tests/test_pipeline_e2e.py` | 1 | 전 과정 시나리오(등록→발급→배포→지표→실패 주입→진단→복구) |

## 6. 재현 방법
```bash
bash scripts/check.sh                                   # 컴파일 + 전체 테스트(promtool/amtool 을 PATH 에 두면 감시 설정 시험까지 실행)
```
```bash
PIPELINE_VERBOSE=1 python -m pytest tests/test_pipeline_e2e.py -s -q    # 서버 등록→CSR→가져오기→배포→지표→실패 주입→진단→복구 타임라인
```
```bash
bandit -q -r certpilot_core certpilot_api certpilot_cli certdeploy monitoring/scripts -ll
```
