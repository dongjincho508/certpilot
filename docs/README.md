# 문서 안내

이 저장소는 **인증서 감시(Prometheus·ssl_exporter·Alertmanager·Grafana) + 인증서 발급·자동 배포(`certdeploy`)** 를 Rocky Linux 관리 서버 1대에서 운영하기 위한 코드와 문서다. 관리자 화면(설정·운영)은 `certpilot_api`/`frontend` 코드로 같은 서버에 설치된다.

## 지금 상태 (2026-10-28)
- 코드·자동 테스트 완료, **실제 VM·실제 장비 검증 전** → 무엇을 검증했고 무엇이 남았는지는 [검증 보고서](ops/verification-report.md)
- **RapidSSL 와일드카드 만료 2026-11-12 08:59(KST)** — 11/5 에 새 방식 사용 여부 결정([준비 체크리스트](ops/pre-vm-checklist.md))

## 🚀 처음이라면
**[원스톱 시작 가이드](ops/quickstart.md)** — 설치(마법사) → 첫날 체크리스트 → 화면 가이드 → 운영 주기표 → 증상별 조치를 한 문서에. 자세한 명령은 아래 표의 상세 매뉴얼.

| 내가 지금… | 바로 가기 |
|---|---|
| 🛠 서버를 새로 설치한다 | [원스톱 시작 가이드 4장](ops/quickstart.md) → [상세 매뉴얼](ops/vm-install-and-test.md) |
| 👀 매일 운영한다 | [운영 주기표](ops/quickstart.md) · 관리자 화면 「설정·운영 → 시작하기」 |
| 🧯 문제가 생겼다 | [증상별 조치](ops/quickstart.md) · [디버깅 가이드](ops/debugging.md) |
| ✅ 시험한다 | [테스트 시나리오 T-01~T-28](ops/test-scenarios.md) |
| 📋 결정·요청할 것을 정리한다 | [준비 체크리스트](ops/pre-vm-checklist.md) |

## 읽는 순서
| 단계 | 문서 | 내용 |
|---|---|---|
| ① 준비 | [VM 구성 전 준비 체크리스트](ops/pre-vm-checklist.md) | 결정할 것, 모을 정보, 요청할 것, 일정 |
| ② 설치 | [관리 서버 설치·테스트 매뉴얼](ops/vm-install-and-test.md) | Rocky 10.x 에서 감시 스택+certdeploy 설치(명령어 상세), 예상 화면. **자동 설치 스크립트**(`scripts/install-mgmt-server.sh`)·Kickstart 예시 포함 |
| ③ 시험 | [테스트 시나리오](ops/test-scenarios.md) | T-01~T-28 절차·기대 결과·증거·결과 기록표 |
| ④ 발급 | [자동 발급 가이드](ops/auto-issue.md) · [certdeploy](ops/certdeploy.md) | Let's Encrypt(DNS 연동/수동) 발급, 수동 와일드카드 가져오기, 명령 요약 |
| ⑤ 호환성 | [호환성 가이드](ops/compatibility.md) | DNS 제공자 선택, 웹방화벽·어플라이언스(HTTP API) 배포, 확장 방법 |
| ⑤-1 설정 화면 | [설치 매뉴얼 7-5](ops/vm-install-and-test.md) · [시작 가이드 6장](ops/quickstart.md) | 관리자 화면 「설정·운영」: 체크리스트, 알림(메일·웹훅·티켓), 승인, 백업, 개인키 보호 |
| ⑤-2 자동 탐색 | [설치 매뉴얼 10-1](ops/vm-install-and-test.md) | `certdeploy-discover`: 대역을 스캔해 미등록·위험 인증서 찾기(읽기 전용, 주 1회 타이머, 알림) |
| ⑥ 장애 | [디버깅 가이드](ops/debugging.md) | trace/diagnose, 버그 수집·전달 형식 |
| ⑦ 교체 | [인증서 교체 체크리스트](ops/cert-rotation-checklist.md) | 11/12 만료 대응(기존 방식) 일정·절차 |

## 참고
| 문서 | 내용 |
|---|---|
| [검증 보고서](ops/verification-report.md) | 기능별 검증 방법·결과, 미검증 항목과 VM 에서 확인할 방법 |
| [오늘 밤 할 일](ops/tonight-todo.md) | 2026-10-28 밤 작업(준비 체크리스트의 첫 단계) |
| [감시 서버 구축 가이드(Rocky 10)](ops/rocky-linux-deploy.md) | 감시 스택만 구축하는 상세 가이드(설치 매뉴얼의 5~6단계 원본) |
| [갱신 자동화 설계](ops/acme-automation.md) | lego + Infoblox 설계(내장 ACME 이전 설계 문서) |
| [monitoring/README](../monitoring/README.md) | 감시 스택 구성·규칙·대시보드·도구 |

## 설정 예시 파일 (`certdeploy/`)
| 파일 | 용도 |
|---|---|
| `certdeploy.manual.example.yml` | 상용 인증서(와일드카드)를 **수동으로 가져와** 자동 배포(`hnu`/`hannam` 도메인별 분리) |
| `certdeploy.acme.example.yml` | Let's Encrypt **자동 발급**(`hnu.kr`=Infoblox 연동, `hannam.ac.kr`=수동 TXT) + 배포 |
| `certdeploy.waf.example.yml` | 웹방화벽 옵션 A(HTTP API)·B(SSH CLI, F5 형) 구조 예시(가상 필드) |
| `certdeploy.waf-manual.example.yml` | 웹방화벽 옵션 C — **사람이 교체**(교체용 파일 준비·메일 안내·독촉·서빙 확인) |
| `certdeploy.example.yml` | lego 엔진 포함 전체 항목 설명 |
| `certdeploy schema` | 설정 JSON Schema 출력(편집기 자동완성) |
