# 인증서 만료 감시 스택 (Prometheus · ssl_exporter · Alertmanager · Grafana)

서비스 중인 TLS 인증서(Apache, Tomcat, WebtoB/JEUS, IIS, Node.js …)의 **만료·교체·설치 위치**를 감시하고, 만료 전에 메일/웹훅으로 알린다.
검증된 오픈소스만 사용하며 직접 만든 서버 코드는 없다(설정·규칙·대시보드·보조 스크립트만 포함).

```
감시 대상 host:port ◀─TLS─ ssl_exporter ◀─ Prometheus ─▶ Alertmanager ─▶ 메일 / 웹훅(Teams·Slack·Mattermost)
                                              │
                                              └──────▶ Grafana (대시보드, 교체 체크리스트)
```

## 무엇을 감시하나 / 못 하나
| 항목 | 설명 |
|---|---|
| ✅ 서비스되는 인증서 | 포트로 접속해 **실제 서빙 중인 인증서**를 조회한다. OS·웹서버 종류와 무관(Windows/IIS 포함) |
| ✅ 교체 확인 | 일련번호·발급일 변화로 새 인증서 반영 여부 확인(이력 400일 보관) |
| ✅ 갱신 지연 | 인증서 수명의 75% 가 지났는데 교체되지 않으면 경보(자동 갱신 조용한 실패 탐지) |
| ❌ 디스크 파일 | 서비스되지 않는 인증서·갱신 파일은 보지 못한다(필요하면 각 서버에 `x509-certificate-exporter` 추가) |
| ❌ 발급·배포 | 하지 않는다. `renewal/` 의 lego 초안과 배포 훅을 사용 → [갱신 자동화](../docs/ops/acme-automation.md) |

## 설치 (교내 VM 1대, Docker 필요)
> **Rocky Linux 10 기준 전 과정(OS 설치·SELinux·방화벽·HTTPS 역프록시·운영)은 [Rocky 10 구축 가이드](../docs/ops/rocky-linux-deploy.md)** 를 따른다. 아래는 요약.
이 VM 은 **감시 대상 서버의 포트에 접속할 수 있는 망**에 있어야 한다(외부 클라우드에서는 사설망 서버를 볼 수 없다).
```bash
cd monitoring
cp .env.example .env                      # GRAFANA_ADMIN_PASSWORD 설정
cp -r alertmanager/secrets.example alertmanager/secrets   # smtp_password, webhook_url 값 수정(권한 600)
cp prometheus/targets/servers.yml.example prometheus/targets/servers.yml   # 실제 서버로 수정
docker compose up -d
```
- Grafana: `http://<VM>:3000` (기본 로컬 바인딩. 교내 접속은 `GRAFANA_BIND=0.0.0.0` + **HTTPS 역프록시** 권장)
- 설정 변경 후: 대상 목록은 1분 내 자동 반영, 규칙·prometheus.yml 은 `curl -X POST http://127.0.0.1:9090/-/reload`

## 대상 등록
`prometheus/targets/servers.yml` 에 `호스트명:포트` 와 레이블(group/service/os/owner)을 적는다. 호스트명(SNI)을 쓰는 것이 정확하다.
서버가 많으면 CSV 로 관리해 변환한다.
```bash
python scripts/csv_to_targets.py servers.csv -o prometheus/targets/servers.yml
```
CSV 열: `host,port,group,service,os,owner[,module]` (메일 STARTTLS 는 `module=smtp`).

## 알림
| 심각도 | 규칙 | 채널·반복 |
|---|---|---|
| critical | 만료됨, 1일·3일 이내 만료, 수집 중단 | 메일 + 웹훅, 4시간마다 |
| warning | 7일·14일 이내 만료, **갱신 지연**, 조회 실패(15분) | 메일, 24시간마다 |
| info | 30일 이내 만료, 구형 TLS(1.0/1.1) | 메일(묶음), 7일마다 |

SMTP 주소·수신자는 `alertmanager/alertmanager.yml` 의 `TODO` 를 수정한다. 비밀번호·웹훅 URL 은 `alertmanager/secrets/` 파일로만 둔다.
Teams/Slack/Mattermost 설정 예시는 같은 파일 주석 참고.

## 대시보드 (Grafana › 인증서 › 인증서 현황)
- 상단 요약: 감시 대상 수 / 조회 실패 / 30일 이내 만료 / 만료됨
- **인증서 현황**: 만료 임박 순 목록(그룹·서비스·OS·일련번호 필터)
- **같은 인증서를 쓰는 서버 수**: 일련번호별 설치 위치·서버 수·최소 잔여일 → 교체 대상 파악
- **최근 7일 내 발급**: 교체가 반영된 서버 확인, **와일드카드 사용 현황**, 그룹별 잔여일 추이, TLS 버전 분포
- 로그인: Grafana 는 LDAP/OIDC 를 지원한다(교내 계정 연동은 Grafana 문서의 `auth.ldap` 설정).

## 교체 체크리스트 (인증서 교체 전후 확인)
```bash
python scripts/cert_inventory.py serials                    # 같은 인증서를 쓰는 서버 파악
python scripts/cert_inventory.py snapshot --serial <일련번호> -o before.csv    # 교체 전 대상 저장
# ... 인증서 배포 ...
python scripts/cert_inventory.py check --snapshot before.csv -o result.csv     # 교체 완료/미교체/조회 실패
```
미교체·조회 실패가 있으면 종료 코드 1. 상세 절차는 [교체 체크리스트](../docs/ops/cert-rotation-checklist.md).

## 운영
- 데이터: Docker 볼륨 `prometheus-data`(이력 400일), `alertmanager-data`, `grafana-data`. 정기 백업 대상은 `prometheus-data` 와 `grafana-data`.
- 용량: 대상 50개 규모에서 수십 MB 수준(실측 아님, 대상 수와 보관 기간에 비례).
- 업그레이드: `docker-compose.yml` 의 이미지 태그를 올리고 `docker compose pull && docker compose up -d`.
- 감시 자체의 감시: `CertExporterDown`, `CertTargetScrapeFailed` 경보가 수집 중단을 알린다. Grafana 자체 접속 주소도 대상에 등록하면 좋다.

## 검증 현황 (정직한 범위)
| 항목 | 상태 |
|---|---|
| 알림 규칙 | ✅ `promtool test rules` 단위 테스트(구간·`for`·갱신 지연 경계) |
| 설정 문법 | ✅ `promtool check config/rules`, `amtool check-config`, PromQL 파서 |
| 실제 동작 | ✅ 실제 ssl_exporter + Prometheus + Alertmanager 를 로컬에서 띄워 만료/임박/갱신 지연/조회 실패 알림이 웹훅까지 전달되는 것 확인 |
| 대시보드 쿼리 | ✅ 모든 패널의 PromQL 을 실제 Prometheus 에서 실행해 결과 확인 |
| **Grafana 화면 렌더링** | ❌ 직접 확인하지 못함(실행 환경에서 Grafana 를 받을 수 없었음). 첫 접속 후 패널 표시를 확인해 주세요 |
| **docker compose 기동** | ❌ 직접 실행하지 못함(Docker 데몬 없음). 이미지 태그 4종은 Docker Hub 에 **실재함을 확인**했고, ssl_exporter·Prometheus·Alertmanager 는 같은 버전 바이너리의 동작도 확인했다 |
| 갱신 스크립트(`renewal/`) | ⚠ 초안. 문법 검사만 했고 실제 발급·배포는 시험하지 않았다 |

실행: `pytest tests/test_monitoring.py` (promtool/amtool 이 PATH 에 있거나 `PROMTOOL`/`AMTOOL` 환경변수로 지정되면 도구 검증도 수행, 없으면 해당 항목은 건너뜀). CI 에서는 릴리스 바이너리를 내려받아 전체 검증한다.

## 문제 해결
| 증상 | 확인 |
|---|---|
| 대시보드에 데이터 없음 | `docker compose logs prometheus`, Prometheus `/targets` 에서 `ssl-endpoints` 상태 확인 |
| 모든 대상 "조회 실패" | VM 에서 대상 포트로 접속 가능한지(방화벽), 호스트명 해석 여부 |
| 조회는 되는데 다른 인증서가 보임 | SNI: IP 가 아닌 호스트명을 대상에 사용, 가상호스트별 인증서 확인 |
| 메일이 안 옴 | `docker compose logs alertmanager`, SMTP 릴레이 허용·인증 설정, `smtp_auth_*` 줄 |
| 알림이 너무 많음 | `alertmanager.yml` 의 `repeat_interval`, 심각도 라우팅 조정 |
