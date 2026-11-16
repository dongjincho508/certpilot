# 요구사항 추적표 — 기획부터 검증까지

요청받은 요구사항이 **어디에 구현되고, 어떻게 검증됐고, VM 에서 무엇으로 확인하는지**를 한 표로 묶었다. 재검토(2026-11-16)에서 빠진 연결을 찾아 보완했다(아래 「재검토 결과」).

표기: ✅ 자동 시험 · 🧪 **진짜 소프트웨어**로 확인(개발 환경) · ⬜ 실제 VM·장비에서 확인 필요 · 시험 ID 는 [테스트 시나리오](test-scenarios.md)

## 1. 기본 요구사항

| # | 요구사항 | 구현 | 검증 | VM 시험 |
|---|---|---|---|---|
| R1 | 서버 50대 이하의 인증서 만료 감시·알림 | `monitoring/`(Prometheus·ssl_exporter·Alertmanager·Grafana) | ✅ promtool 규칙 시험, 🧪 실제 Prometheus·Alertmanager·ssl_exporter | T-01, T-02 |
| R2 | 상용 와일드카드(RapidSSL) **수동 반입** 후 자동 배포 | `certdeploy csr/import/deploy` | ✅, 🧪 OpenSSL 체인 검증 | T-04~T-08 |
| R3 | 대상 서버에 **에이전트 없이** 배포 | SSH(OpenSSH)/API, 실패 시 자동 롤백 | ✅, 🧪 **실제 sshd+sudo·nginx·Apache·Tomcat 배포·롤백** | T-05, T-07, T-29 |
| R4 | Let's Encrypt **자체 발급** — DNS 연동과 수동 TXT 둘 다 | 내장 ACME(DNS-01) `issue/renew` | ✅ 가짜 CA 로 발급 전 과정 | T-14~T-16 |
| R5 | DNS 호환성(여러 DNS 중 선택) | infoblox·rfc2136·cloudflare·powerdns·webhook·exec·manual, **CNAME 위임** | ✅, 🧪 **실제 BIND 의 RFC 2136 TSIG·CNAME 위임** | T-14, T-17 |
| R6 | 웹방화벽(모니터랩: 업로드 후 「적용」 단계) | `http_api`(단계·대기·롤백) / `manual`(교체 파일·독촉·서빙 확인) | ✅ 가짜 WAF | T-18, T-21 |
| R7 | 관리자 화면에서 메일 입력, 인증서별 개인키 암호 사용/미사용 | 관리자 화면 「알림」·「인증서·승인」, `settings.json`(600) | ✅, 🧪 실제 브라우저 | T-20, T-22 |
| R8 | 디버깅이 쉬운 구조 | `trace`·`diagnose`·진단 탭·진단 번들(비밀 제외) | ✅ | T-19 |
| R9 | Rocky 상세 매뉴얼·시험 시나리오·사전 점검표 | `vm-install-and-test.md`, `test-scenarios.md`, `pre-vm-checklist.md`, `quickstart.md` | ✅ 문서 링크·번호 일치 시험 | 전체 |
| R10 | 원스톱 자동 설치(로키 설치 후 나머지) | `scripts/install-mgmt-server.sh`(마법사·재실행·요약), Kickstart 예시 | ✅, 🧪 **가짜 시스템 명령으로 끝까지 실제 실행(5 시나리오)** | **T-31** |
| R11 | 시험 중 수정 시 재설치 없이 반영 | `git pull` + `pip install -e` + 재시작(설정·데이터 유지) | 🧪 설치 시험의 재실행 시나리오 | **T-31** |

## 2. 상용 제품 비교 후 추가한 요구사항

| # | 요구사항 | 구현 | 검증 | VM 시험 |
|---|---|---|---|---|
| R12 | 미등록 인증서 자동 탐색 | `certdeploy-discover`(읽기 전용, 사설 대역만, 주간 타이머, 알림) | ✅ 실제 TLS 소켓 | **T-30** |
| R13 | AD/LDAP 없이 로그인 보안 강화 | 2단계 인증(TOTP)·복구 코드·정책 강제 | ✅, 🧪 설치 시험에서 등록 흐름 | T-23 |
| R14 | 배포 전 승인(1~3인) | `approval` 정책·승인 화면·긴급 우회 | ✅ | T-24 |
| R15 | IIS 자동 배포 | `type: iis`(SSH+PowerShell) | ✅ 가짜 Windows (PowerShell 실행은 미검증) | T-25 |
| R16 | WebtoB/JEUS 자동 배포 | `type: webtob`/`jeus`(암호화 키, 소유자, 키스토어) | ✅, 🧪 실제 Tomcat 이 JKS/PKCS12 를 읽음 | T-26 |
| R17 | 알림 확장(관리자 화면에서 설정) | 메일·메신저 5종·ServiceNow/Jira 티켓, 심각도·반복 억제 | ✅ 가짜 서버 | T-27 |
| R18 | 백업 자동화 | 매일 암호화 백업·검증·외부 복사·보관 정리·복구 | ✅, 🧪 설치 직후 실제 백업 실행 | T-28 |
| R19 | 사용자 기반 UX(표·아이콘·쉬운 설명) | 체크리스트·지금 할 일·운영 주기표·증상별 조치 | 🧪 실제 브라우저(데스크톱·모바일 폭) | T-22 |
| R20 | 상용 솔루션 수준의 UI 품질 | 사이드바 앱 셸·디자인 토큰·일관된 표/상태 표기·다크 모드 | 🧪 실제 브라우저 | T-22 |

## 3. 운영 결정

| 결정 | 내용 |
|---|---|
| Render 앱 | 사용하지 않음. 저장소에서는 **정리하지 않고 둔다**(2026-10-30 삭제 후 되돌림) |
| 인증서 만료 대응 | RapidSSL 와일드카드(2026-11-12 만료)는 이 시스템 시험과 별개로 기존 절차로 교체 |
| 디스크 암호화 | 전산실 VMware 암호화 여부 확인 후 결정 |
| 관리 서버 | 1대로 시작, 운영 전 분리 검토 |

## 4. 재검토 결과 (2026-11-16)

| 구분 | 발견 | 조치 |
|---|---|---|
| 기획 | 자동 탐색(R12)과 원스톱 설치·업데이트(R10·R11)에 대응하는 VM 시험 항목이 없음 | T-30, T-31 추가 |
| 시험 | 실제 sshd 시험의 임시 계정 이름이 고정이라 이전 실행 잔여 계정과 충돌 | 고유 이름·강제 정리로 수정 |
| 문서 | 검증 보고서 요약(시험 수·기능표)과 일부 문서의 시험 범위·IIS 설명이 오래됨 | 현재 상태로 갱신 |
| 보안 | 모든 관리 API 의 인증 적용, CSRF(JSON 전용 + SameSite=Strict 쿠키), 보안 헤더(CSP·X-Frame-Options) 재확인 | 이상 없음 |
| UI | 상단 메뉴 + 중첩 탭 구조로 기능이 늘수록 찾기 어려움 | 사이드바 정보 구조로 개편(R20) |

## 5. 아직 확인하지 못한 것 (VM·장비에서만 가능)
Rocky 10·SELinux 동작, 실제 Let's Encrypt·Infoblox, IIS 의 실제 PowerShell 실행, WebtoB·JEUS 제품, 모니터랩 웹방화벽, 실제 ServiceNow·Jira·Teams, Grafana 화면 렌더링. 자세한 범위는 [검증 보고서](verification-report.md).
