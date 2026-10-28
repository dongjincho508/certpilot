# VM 설치·테스트 매뉴얼 (처음부터 끝까지)

대상: 교내 전산실 · Rocky Linux 10.x · 서버 50대 이하(Windows 소수). 이 문서는 **순서표**이고, 세부 명령은 각 단계의 링크 문서에 있다.

> ⚠️ **현재 RapidSSL 와일드카드는 2026-11-12 08:59(KST) 만료**다. 이 시스템의 테스트 완료를 기다리지 말고, 만료 전 교체는 기존 절차([교체 체크리스트](cert-rotation-checklist.md))로 진행한다. 아래 4단계(수동 인증서)는 그 교체본으로 `certdeploy` 를 **처음 실사용**해 보는 안전한 기회이기도 하다(실패해도 롤백됨).

## 0. 구성과 역할
| VM | 역할 | 비고 |
|---|---|---|
| ① 감시 VM | Prometheus·ssl_exporter·Alertmanager·Grafana·Pushgateway(Docker) | 개인키 없음. [감시 서버 구축 가이드](rocky-linux-deploy.md) |
| ② 발급·배포 VM(분리 권장) | `certdeploy`(+선택 lego) | **개인키 보관** → 접근 계정 최소화. [certdeploy](certdeploy.md) 3절 |
| (Render) | CertPilot 앱(보류 상태) | 서버 목록 관리가 필요할 때만. 진단 탭: [debugging.md](debugging.md) |
처음에는 ①②를 한 VM 에 두고 시험해도 되지만, 운영 전에 분리한다.

## 1. 준비물 체크 (설치 전)
- [ ] VM 2대(또는 1대): 4 vCPU / 8 GB / 100 GB 이상(감시), 2 vCPU / 2 GB / 20 GB(발급). **CPU 가 x86-64-v3 지원**(Rocky 10 요구) — VM 설정에서 호스트 CPU 패스스루
- [ ] 방화벽: 감시 VM → 대상 443(및 서비스 포트) 허용, 발급 VM → 대상 22 허용, 발급 VM → 감시 VM 9091(Pushgateway)·9093 허용
- [ ] 대상 서버 목록(호스트·포트·OS·웹서버 종류) CSV, 대상별 `deploy` 계정 생성 가능 여부
- [ ] (자동 발급 시) Infoblox: 위임 영역·API 계정 — 수동 인증서만 쓰면 불필요
- [ ] 메일 서버(SMTP)·Teams 웹훅 URL(선택)

## 2. 감시 VM 설치 (①)
[rocky-linux-deploy.md](rocky-linux-deploy.md) 0~6절을 순서대로. 이 단계의 **합격 기준**:
1. `docker compose config -q` 통과 후 `docker compose up -d`, 5개 컨테이너 모두 `Up`
2. Prometheus `/targets` 에서 `ssl-exporter-self`·`prometheus`·`alertmanager` 가 UP
3. 대상 CSV → `monitoring/scripts/csv_to_targets.py` 로 생성한 대상이 `ssl-endpoints` 에서 UP (인증서가 없는 포트는 DOWN 이 정상이므로 CSV 에서 제외)
4. Grafana 대시보드 `cert-overview` 에 인증서·만료일이 보임
5. Alertmanager 테스트 알림이 메일/Teams 로 도착

## 3. 발급·배포 VM 설치 (②)
[certdeploy.md](certdeploy.md) 3절(계정·설치·SSH 키·sudoers·SELinux) → 설정 파일 작성. 합격 기준:
```bash
sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy --version
```
```bash
sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml validate
```
```bash
sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml preflight
```
`preflight` 는 접속·쓰기 권한·명령·sudo·여유 공간·현재 TLS 를 **변경 없이** 점검한다. 모든 대상이 통과해야 다음 단계로 간다.

## 4. 인증서 준비 — 두 가지 경로 중 선택
**A. 수동(상용 CA, DNS 연동 없음)** — [certdeploy.md 5-1](certdeploy.md)
```bash
sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml csr --domains '*.univ.example,univ.example' --country KR --org '대학명'
```
CSR 을 CA 에 제출 → 받은 서버 인증서·중간 CA 를 올린 뒤:
```bash
sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml import --file /tmp/server.cer --file /tmp/intermediates.p7b --dry-run
```
**B. 자동(lego + Infoblox)** — [acme-automation.md](acme-automation.md). 반드시 `issue --staging --no-deploy` 로 먼저 시험(운영 한도·운영 인증서와 무관).

## 5. 배포 시험 (위험 낮은 순서)
1. `plan` → 계획 확인 (변경 없음)
2. **스테이징/시험 서버 1대**(canary)만 `deploy --target <이름>`
3. `status` / `check` 로 서빙 인증서 일치 확인, 브라우저·`openssl s_client` 로 체인 확인
4. 의도적 실패 시험(아래 T-07)으로 롤백 확인 → 그 후 나머지 대상 `deploy`
```bash
sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml plan
```
```bash
sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml deploy --target web-canary
```
```bash
sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml check
```

## 6. 자동화·감시 연동
- 타이머: [certdeploy.md](certdeploy.md) 4절의 systemd 타이머 설치(수동 인증서만 쓰면 `renew` 타이머는 불필요 — 대신 `check` 를 cron/Zabbix 로)
- 지표 푸시: 설정 `notify.pushgateway_url` → 감시 VM 대시보드 「certdeploy」 패널에 표시
- 연동 점검: 
```bash
sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml diagnose --prometheus http://<감시VM>:9090 --pushgateway http://<감시VM>:9091
```

## 7. 시험 항목표 (결과를 표로 남긴다)
| ID | 시험 | 방법 | 합격 기준 |
|---|---|---|---|
| T-01 | 감시 수집 | Prometheus `/targets` | 대상 UP, 인증서 만료일 표시 |
| T-02 | 만료 알림 | 규칙 임계값을 임시로 크게 하거나 짧은 인증서 | 메일/Teams 수신, 해소 시 복구 알림 |
| T-03 | 사전 점검 | `preflight` | 전 대상 통과, 시스템 변경 없음 |
| T-04 | 수동 가져오기 | `csr` → CA → `import --dry-run` | 키 일치·SAN·체인 OK, 루트 자동 제외 |
| T-05 | 단건 배포 | canary `deploy` | 서빙 일련번호 = 새 인증서 |
| T-06 | 멱등성 | 같은 명령 재실행 | "건너뜀", 재로드 없음 |
| T-07 | 실패→롤백 | 대상 1대의 `check_cmd` 를 일부러 실패시킴 | "롤백됨", 서비스 정상, 알림 수신, 지표 `run_ok=0` |
| T-08 | 전체 배포 | 순서·canary 대로 전 대상 | 전부 "배포 완료", `check` 종료 코드 0 |
| T-09 | 제품별 | Apache·Tomcat·WebtoB/JEUS·IIS·Node.js 각 1대 | 재로드 후 새 인증서 서빙(제품별 재로드 방식 확인) |
| T-10 | 감사 로그 | `verify-audit` | 해시 체인 정상 |
| T-11 | 백업·복원 | `backup` / `restore` | 별도 위치에 복원·내용 확인 |
| T-12 | 장애 복구 | 발급 VM 재부팅·타이머 | 재부팅 후 타이머 동작, 잠금 파일 잔여 없음 |
| T-13 | 감시 장애 | 감시 VM 중지 | 배포는 정상 진행(지표 푸시 실패는 오류 이벤트로만 기록) |

## 8. 버그를 만났을 때 (수정 루프)
1. 실패한 명령 앞에 `--debug` 를 붙여 재실행(단계가 실시간 출력됨).
2. 다음을 수집해 전달한다(모두 비밀값 마스킹됨):
```bash
sudo -u certdeploy /opt/certdeploy/venv/bin/certdeploy -c /etc/certdeploy/certdeploy.yml diagnose --out /tmp/diag.json
```
   - 감시 쪽: `docker compose ps`, `docker compose logs --tail=100 <서비스>`
   - 화면(CertPilot): 진단 탭의 「진단 번들」과 오류 메시지의 `[요청 ID …]`
3. 전달 형식: **시험 ID(T-xx) · 실행한 명령 · 기대 결과 · 실제 결과 · diag.json**. 호스트명 노출이 곤란하면 가려서 보낸다.
4. 수정 후 같은 시험 ID 를 재실행해 합격을 확인하고, 회귀 방지를 위해 재현 조건을 자동 테스트로 추가한다(`tests/test_pipeline_e2e.py` 에 실패 조건만 더하면 된다).

## 9. 운영 전환 체크리스트
- [ ] T-01~T-13 합격 · 결과표 보관
- [ ] 개인키 파일 권한 600, `certdeploy` 계정 외 접근 불가, 백업본 암호화 보관
- [ ] 알림 수신자 확정(메일·Teams), 야간·휴일 담당 지정
- [ ] 만료 60/30/14/7일 알림이 실제로 울리는지 확인
- [ ] 수동 인증서 운영 시 갱신 달력(약 200일 주기, 단축 예정) 등록
- [ ] 롤백 절차(`rollback --target`) 담당자 숙지
