# CertPilot — 텔레그램 결정 수집: 오너 작업 체크리스트 (v2, 정정판)

작성: Commander (00-commander)
대상 프로필: `00-commander` (HERMES_HOME = `C:\Users\Master\AppData\Local\hermes\profiles\00-commander`)
예상 소요: 5~10분

> **v2 정정**: v1에서 안내한 `hermes -p 00-commander gateway run` 은 **이 환경에서 exit 78로 실패합니다**.
> 이 호스트는 **게이트웨이 1개가 모든 프로필을 서빙**하는 멀티플렉스 구조이며(기본 프로필 config에 `gateway.multiplex_profiles: true` 실측 확인),
> 게이트웨이는 **기본 프로필에서** 시작해야 합니다. → **4단계가 정정된 내용입니다.**

## 실측 baseline

| 항목 | 상태 |
|---|---|
| 게이트웨이 (전 프로필) | ✗ 전부 not running (`hermes gateway list` 실측) |
| Telegram 설정 | ✗ 미설정 (활성 `TELEGRAM_*` 키 0개) |
| 기본 프로필 멀티플렉스 | ✓ `gateway.multiplex_profiles: true` |
| 00-commander standalone | 미설정 (→ 호스트가 서빙하는 정상 상태) |

---

## 전체 흐름 한눈에

| 단계 | 누가 | 내용 | 필수 |
|---|---|---|---|
| 1 | 오너 | @BotFather로 봇 생성 → 토큰 획득 | ✅ |
| 2 | 오너 | **00-commander 프로필**에 토큰 등록 (.env 권장) | ✅ |
| 3 | 오너 | 본인 Telegram id 확보 (allowlist 또는 페어링) | ✅ |
| 4 | 오너 | **기본 프로필에서 호스트 게이트웨이 실행** ← 정정 | ✅ |
| 5 | 오너 | 봇에게 DM 1회 (채널 발견) | ✅ |
| 6 | 오너 | "설정했어" 통보 | ✅ |
| 7 | Commander | 연결 검증 → 질문 전송 | — |
| 8 | 오너 | 텔레그램에서 결정 | ✅ |

---

## 1단계 — 봇 만들기 (@BotFather)

1. 텔레그램 앱에서 검색창에 `BotFather` 입력 → 파란 체크가 있는 **@BotFather** 선택
2. `Start` 누르고 `/newbot` 전송
3. **봇 표시 이름** 입력 (예: `CertPilot Commander`) — 자유롭게
4. **봇 username** 입력 — **반드시 `bot`으로 끝나야 함**
   - 예: `certpilot_commander_bot`
   - 이미 사용 중이면 다른 이름 시도 (BotFather가 알려줌)
5. BotFather가 **토큰**을 반환한다. 형태:
   ```
   123456789:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   ```
6. **이 토큰을 복사해 두세요.** ⚠️ **이 대화창에 붙여넣지 마세요.**

> 토큰은 비밀번호와 동일한 자격증명입니다. 노출됐다고 판단되면 BotFather에서 `/revoke` 후 재발급하세요.

---

## 2단계 — Hermes에 등록

### 방법 A — 마법사 (대안)

**Windows 터미널**(PowerShell 또는 cmd)을 열고 실행:

```powershell
hermes -p 00-commander gateway setup
```

진행:
1. 플랫폼 목록에서 **Telegram** 선택
2. 봇 토큰 붙여넣기 (1단계에서 복사한 값)
3. 허용 사용자(allowlist)를 묻거든 → 3단계에서 확인한 **본인 숫자 id** 입력
   - id를 아직 모르면 **비워두고** 3단계의 페어링 방식을 사용
4. 완료 후 자격증명이 프로필 `.env`에 저장된다

> ⚠️ 마법사의 **마지막 "게이트웨이 시작" 단계는 exit 78로 실패**하며 아래 메시지가 나옵니다:
> *"Profile '00-commander' does not get a gateway of its own."*
> **이는 정상입니다.** 자격증명 저장은 이미 끝난 상태이므로 무시하고 4단계로 진행하세요.

### 방법 B — `.env` 직접 편집 (권장 · 혼동 없음)

PowerShell에서 메모장 열기:
```powershell
notepad "$env:LOCALAPPDATA\hermes\profiles\00-commander\.env"
```

파일 **맨 끝**에 두 줄 추가하고 **저장(Ctrl+S)**:
```
TELEGRAM_BOT_TOKEN=<1단계에서 받은 토큰>
TELEGRAM_ALLOWED_USERS=<본인 숫자 id>
```

주의사항:
- 이름은 **정확히 대문자** `TELEGRAM_BOT_TOKEN`, `TELEGRAM_ALLOWED_USERS`
- 앞에 `#` 붙이지 말 것 (주석이 되면 적용 안 됨)
- 값에 따옴표·공백 넣지 말 것
- 이 파일에는 이미 주석 처리된 자리표시자들이 있음 — **주석을 해제하지 말고 새 줄로 추가**할 것

---

## 3단계 — 본인 Telegram id 확보 (둘 중 하나)

### 방법 1 — id 직접 확인 (allowlist 방식)

1. 텔레그램에서 `@userinfobot` 검색 → 대화 시작
2. 아무 메시지 전송
3. 봇이 `Id: 123456789` 형태로 **숫자 id**를 반환
4. 이 숫자를 `TELEGRAM_ALLOWED_USERS` 에 입력

### 방법 2 — DM 페어링 (id를 몰라도 됨)

1. allowlist를 비워둔 채로 4단계까지 진행
2. 텔레그램에서 내 봇에게 DM 전송
3. 봇이 **일회용 페어링 코드**를 반환: `Pairing code: XKGH5N7P`
4. 본인 터미널에서 승인:
   ```powershell
   hermes -p 00-commander pairing approve telegram XKGH5N7P
   ```
5. 확인:
   ```powershell
   hermes -p 00-commander pairing list
   ```
   - 코드는 **1시간 후 만료**되며 재시도 횟수 제한이 있습니다.

---

## 4단계 — 호스트 게이트웨이 실행 ⭐ 정정된 단계

**기본 프로필에서** 실행합니다. (`-p 00-commander` 를 붙이면 exit 78로 거부됩니다)

### 테스트용 (창을 닫으면 종료)
```powershell
hermes gateway run
```

### 상시 운영 (권장 · Windows 작업 스케줄러 등록, 로그인 시 자동 시작)
```powershell
hermes gateway install
```

위 명령이 프로필 해석 문제로 거부되면:
```powershell
hermes -p default gateway install
```

### 동작 원리
- 이 호스트는 **게이트웨이 1개가 모든 프로필을 서빙**합니다(멀티플렉스). 기본 프로필에서 시작한 그 프로세스가 `00-commander` 의 텔레그램 봇도 함께 폴링합니다.
- 호스트 게이트웨이가 살아 있는 동안 `hermes -p 00-commander gateway run` 은 **새 프로세스를 만들지 않고 "attach"만** 합니다(호스트 PID와 서빙 목록을 출력하고 종료).

### 상태 확인
```powershell
hermes gateway list        # 프로필별 상태 (9개 프로필 전부 표시)
hermes gateway status      # 호스트 게이트웨이 상태
```
- 현재(설정 전) 출력: 전 프로필 `✗ not running`

---

## 5단계 — 봇에게 DM 1회 (채널 발견)

1. 텔레그램에서 1단계에서 만든 **봇 username** 검색 → 대화 시작
2. `안녕` 등 아무 메시지 전송
3. 봇이 응답하면 연결 성공

> **중요**: Hermes가 채널을 알기 위해서는 **게이트웨이가 최소 1회 실행**되어야 합니다. 게이트웨이를 아직 돌리지 않았다면 `hermes send --list` 가 비어 있는 것이 정상입니다.

---

## 6단계 — Commander에게 통보

이 대화창에 **"설정했어"** 라고만 보내주세요. 그러면 제가 아래를 검증합니다:

```powershell
hermes gateway list
hermes -p 00-commander send --list telegram
```

통과하면 제가 **차단 질문 9건**부터 텔레그램으로 전송하고, 봇에게 `CertPilot 결정 질문 시작` 이라고 보내시면 5개씩 질문이 시작됩니다.

---

## 보안 주의사항 (필수)

- **토큰을 이 채팅, 스크린샷, GitHub, 메신저에 노출하지 마세요.** 노출 시 BotFather에서 `/revoke` 로 즉시 재발급.
- **allowlist에는 본인만** 넣으세요. 이 봇은 **터미널 접근 권한을 가진 에이전트**입니다.
- `GATEWAY_ALLOW_ALL_USERS=true` 는 **사용하지 마세요**.
- **그룹 채팅에 봇을 추가하지 마세요.** (MVP 단계에서는 DM만 사용)
- 호스트 게이트웨이는 **모든 프로필을 서빙**하는 상시 프로세스입니다. 불필요해지면 `hermes gateway stop` 으로 중지하세요.

---

## 문제 해결

| 증상 | 확인 / 조치 |
|---|---|
| `Profile '…' does not get a gateway of its own` | **정상 동작.** 게이트웨이는 기본 프로필에서 실행 → 4단계 |
| `hermes send --list` 가 비어 있음 | 게이트웨이를 아직 한 번도 실행하지 않음 → 4단계 실행 |
| 봇이 응답하지 않음 | allowlist에 내 id가 있는지 / `hermes -p 00-commander pairing list` |
| `Gateway is not running` | 4단계 미실행 |
| 봇이 "Pairing code" 만 반복 | 3단계 방법 2의 승인 명령을 실행하지 않음 |
| `hermes gateway list` 에서 00-commander 가 not running | 호스트가 아직 이 프로필을 서빙하지 않음 → 30초 대기(재스캔) 또는 `hermes gateway restart` |
| 토큰 오류 | BotFather에서 토큰 재확인 또는 `/revoke` 후 재발급 |

---

## 대안 — 텔레그램 없이 진행

텔레그램 설정이 부담되면 **이 대화창에서 바로 결정**하셔도 됩니다. 데스크톱 앱도 `clarify` 선택지를 지원합니다. 그 경우 "여기서 질문해줘"라고 말씀해 주세요 — 동일한 49건을 5개씩 묻고 `DECISIONS.md` 에 기록합니다.
