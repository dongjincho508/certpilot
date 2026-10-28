# Render 배포 가이드

`render.yaml` 블루프린트 하나로 배포한다. 서비스는 Docker 단일 컨테이너(gunicorn 1 worker)이며 UI 는 같은 서비스가 제공한다.

## 1. 사전 준비

| 항목 | 내용 |
|---|---|
| 플랜 | **starter 이상** — `/data`(SQLite DB, 감사 로그, TOFU 호스트 키)에 영구 디스크가 필요하다. 무료 플랜은 재배포·유휴 후 데이터가 사라져 감사 로그 무결성 요구와 맞지 않는다 |
| 조회 전용 키 | `ssh-keygen -t ed25519 -N "" -f certpilot_scan` (암호 없는 키. 컨테이너 시작 시 메모리 ssh-agent 에만 로드) |
| 대상 서버 계정 | 인증서 읽기 권한만 가진 전용 계정에 공개키 등록. 권장: `authorized_keys` 에 `restrict,from="<Render 출구 IP>"` 접두 |
| 방화벽 | 대상 서버 SSH 포트에 **Render 서비스의 아웃바운드 IP**(대시보드 Connect > Outbound) 허용. 사설망 서버는 Render 에서 닿지 않는다 |

## 2. 배포

1. Render 대시보드 → New → Blueprint → 이 저장소 선택 (`render.yaml` 자동 인식)
2. 비밀 값 입력
   - `CERTPILOT_ADMIN_PASSWORD`: 12자 이상, 대/소문자·숫자·특수문자 중 3종 이상, 계정명 미포함
   - `CERTPILOT_SSH_PRIVATE_KEY`: `certpilot_scan` 파일 내용 전체(줄바꿈 포함)
3. 배포 후 `https://<서비스>.onrender.com` 접속 → `admin` 로그인 → 서버 등록 → 조회

## 3. 동작 방식

- 시작 시 `startup.sh` 가 `CERTPILOT_SSH_PRIVATE_KEY` 를 `ssh-agent` 에 올리고 **환경변수에서 즉시 제거**한다. 키는 디스크에 쓰지 않는다.
- 키를 바꾸려면 환경변수를 갱신하고 재배포한다(회전 절차). 키 보관 방식 확정은 [OPEN_ITEMS](../OPEN_ITEMS.md) O-3.
- 헬스체크 `/health`, HTTPS 는 Render 가 종단하므로 `CERTPILOT_SECURE_COOKIE=1`(쿠키 Secure) 이 켜져 있다.
- 관리자 최초 생성은 `CERTPILOT_ADMIN_USER`/`PASSWORD` 로 1회(이미 있으면 건너뜀). 이후 사용자는 UI 에서 추가한다.

## 4. 점검

| 증상 | 원인 |
|---|---|
| 모든 서버 "인증 실패" | 키 미설정·형식 오류(로그에 "ssh-agent 에 로드하지 못했습니다"), 공개키 미등록 |
| "연결 시간 초과" | 대상 방화벽에서 Render 출구 IP 미허용, 사설망 |
| 재배포 후 서버 목록·감사 로그 소실 | 영구 디스크 없음(무료 플랜) |
| 로그인 직후 로그아웃 | HTTP 로 접속(Secure 쿠키). HTTPS 주소로 접속 |
| 전체 조회가 오래 걸려 실패 | 서버가 많으면 서버 수 ÷ 20 × 서버당 시간. 대규모는 비동기 작업 큐 이월 항목 I-3 |

## 5. Vercel 과 함께 쓸 때
UI 만 Vercel 에 둘 수도 있으나 필수는 아니다. 그 경우 `vercel.json` 의 rewrites 로 `/auth`, `/servers`, `/scan`, `/users`, `/audit-logs`, `/export.csv` 를 Render 주소로 넘겨 **같은 출처**로 보이게 해야 `SameSite=Strict` 쿠키가 동작한다.
