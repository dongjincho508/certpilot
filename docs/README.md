# 문서 안내

이 저장소는 **인증서 감시(Prometheus·ssl_exporter·Alertmanager·Grafana) + 인증서 발급·자동 배포(`certdeploy`)** 를 Rocky Linux 관리 서버 1대에서 운영하기 위한 코드와 문서다. CertPilot 웹 앱(보류)의 문서는 맨 아래.

## 지금 상태 (2026-10-28)
- 코드·자동 테스트 완료, **실제 VM·실제 장비 검증 전** → 무엇을 검증했고 무엇이 남았는지는 [검증 보고서](ops/verification-report.md)
- **RapidSSL 와일드카드 만료 2026-11-12 08:59(KST)** — 11/5 에 새 방식 사용 여부 결정([준비 체크리스트](ops/pre-vm-checklist.md))

## 읽는 순서
| 단계 | 문서 | 내용 |
|---|---|---|
| ① 준비 | [VM 구성 전 준비 체크리스트](ops/pre-vm-checklist.md) | 결정할 것, 모을 정보, 요청할 것, 일정 |
| ② 설치 | [관리 서버 설치·테스트 매뉴얼](ops/vm-install-and-test.md) | Rocky 10.x 에서 감시 스택+certdeploy 설치(명령어 상세), 예상 화면 |
| ③ 시험 | [테스트 시나리오](ops/test-scenarios.md) | T-01~T-19 절차·기대 결과·증거·결과 기록표 |
| ④ 발급 | [자동 발급 가이드](ops/auto-issue.md) · [certdeploy](ops/certdeploy.md) | Let's Encrypt(DNS 연동/수동) 발급, 수동 와일드카드 가져오기, 명령 요약 |
| ⑤ 호환성 | [호환성 가이드](ops/compatibility.md) | DNS 제공자 선택, 웹방화벽·어플라이언스(HTTP API) 배포, 확장 방법 |
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
| [ROADMAP](ROADMAP.md) | 제품 방향 결정 기록 |

## 설정 예시 파일 (`certdeploy/`)
| 파일 | 용도 |
|---|---|
| `certdeploy.manual.example.yml` | 상용 인증서(와일드카드)를 **수동으로 가져와** 자동 배포 |
| `certdeploy.acme.example.yml` | Let's Encrypt **자동 발급**(`hnu.kr`=Infoblox 연동, `hannam.ac.kr`=수동 TXT) + 배포 |
| `certdeploy.waf.example.yml` | 웹방화벽(HTTP API)·F5 형 CLI 장비 배포 구조 예시(가상 필드) |
| `certdeploy.example.yml` | lego 엔진 포함 전체 항목 설명 |
| `certdeploy schema` | 설정 JSON Schema 출력(편집기 자동완성) |

## CertPilot 웹 앱 (보류) 문서
[PRD](PRD.md) · [ARCHITECTURE](ARCHITECTURE.md) · [TRACEABILITY](TRACEABILITY.md) · [OPEN_ITEMS](OPEN_ITEMS.md) · [decisions](decisions.md) · [release-approval](release-approval.md) · [Render 배포](ops/render.md) · [design/](design/) · [archive/](archive/) · [history/](history/)
Render 배포 구성은 사용하지 않기로 했으나 **정리하지 않고 그대로 둔다**(결정 2026-10-28).
