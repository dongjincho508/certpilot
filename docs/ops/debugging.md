# 전 과정 디버깅 가이드 (서버 등록 → 발급 → 배포 → 감시)

문제가 생겼을 때 **어느 단계에서 왜** 실패했는지 한 번에 보이도록 모든 단계가 같은 형식의 진단 이벤트(성공·실패·소요시간)를 남긴다.
개인키 PEM, 비밀번호·토큰류 값, Bearer 토큰은 기록 전에 자동 마스킹된다.

## 1. 관리자 화면 (CertPilot) — 「진단」 탭 (관리자 전용)
| 항목 | 내용 |
|---|---|
| 환경 점검 | DB·데이터 디렉터리 쓰기·감사 체인·관리자 존재·ssh-agent(키 환경변수 설정 시) |
| 단계별 이벤트 | 연결 테스트(`probe/ssh_connected`, `probe/ssh_failed`), 조회(`scan/*`, 재시도 `connect_retry`), 모든 API 요청(`api/request`) |
| 작업 ID(run) | 한 요청에 속한 이벤트를 묶음(`req-…`). 링크를 누르면 해당 작업만 필터 |
| 진단 번들 | 버전·환경(설정 여부만)·점검 결과·서버 요약·최근 이벤트 500건 JSON (비밀값 제외) |

- 화면 오류 메시지가 서버 내부 오류(500)면 끝에 `[요청 ID xxxx]` 가 붙는다 → 진단 탭의 작업 ID 필터에 넣으면 원인(예외 종류·위치)이 나온다.
- 화면에 노출하지 않는 SSH 원문 오류(`detail`)는 이 진단 탭(관리자)에서만 볼 수 있다.
- API: `GET /debug/events?limit=&component=&level=&run_id=&since=`, `GET /debug/selfcheck`, `GET /debug/bundle`.
- 서버 로그로도 보려면 `CERTPILOT_DEBUG=1`(stderr 실시간 출력), 파일로 남기려면 `CERTPILOT_TRACE_FILE=/경로/trace.jsonl`.

## 2. certdeploy (발급·배포)
```bash
certdeploy -c cd.yml --debug deploy        # 단계가 실시간으로 stderr 에 출력됨
certdeploy -c cd.yml trace --errors        # 최근 실행에서 경고·오류만 (항상 <state_dir>/trace.jsonl 에 기록)
certdeploy -c cd.yml trace --run deploy-ab12cd --debug   # 한 번의 실행 전체(상세 포함)
certdeploy -c cd.yml diagnose --out diag.json --prometheus http://127.0.0.1:9090 --pushgateway http://127.0.0.1:9091
```
- 단계 이름: `import/build_bundle|install`, `issue/lego_start|lego_done`, `deploy/served_serial|connect|install_file|check_cmd|reload_cmd|verify_attempt|failure|target`, `audit/write`, `metrics/textfile|pushgateway`, `notify/*`, `report/finish`.
- 부가 동작(감사·메트릭·알림)은 실패해도 배포 결과를 바꾸지 않으므로, 실패하면 **조용히 지나가지 않고** `error` 이벤트로 남는다.
- `diagnose` 는 설정 문법·인증서 상태/만료·키 파일 권한·마지막 실행 결과·감사 체인과 (주소를 주면) 감시 스택을 점검해 `[문제] … → 조치` 로 보여 준다. 종료 코드 1 = 문제 있음. `--out` 번들은 0600, 마스킹됨.

## 3. 감시 스택
`diagnose` 의 `--prometheus/--alertmanager/--pushgateway` 가 확인하는 것: 수집 대상 up/down 과 `lastError`, 규칙 로드 오류, 발화 중 알림, certdeploy 지표(`certdeploy_last_run_timestamp_seconds`)가 Prometheus·Pushgateway 에 도달했는지.

## 4. 전 과정 시나리오 테스트 (수정 → 재현 → 확인 루프)
```bash
PIPELINE_VERBOSE=1 python -m pytest tests/test_pipeline_e2e.py -s -q
```
서버 등록(연결 테스트·조회) → CSR → 수동 발급 → 가져오기 → 자동 배포(canary) → 지표 푸시 → 실패 주입(web2 재로드 오류→롤백) → `trace`/`diagnose` 로 원인 확인 → 수정 후 재배포 → 복구 까지 한 번에 돌리고, 전체 타임라인을 출력한다. 문제를 고칠 때는 같은 시나리오에 실패 조건만 추가하면 재현·검증이 된다.

## 5. 공유할 때
`certdeploy diagnose --out` 파일, 진단 탭의 「진단 번들」, 또는 `certdeploy trace --errors` 출력을 그대로 전달하면 된다(비밀값 마스킹됨). 그래도 공유 전 한 번 훑어보고 내부 호스트명 노출이 곤란하면 가려서 보낸다.
