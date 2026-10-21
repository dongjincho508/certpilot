# CertPilot 저장소 커밋 준비안 (7번 승인 대응)

작성: Commander · 2026-10-21
결정: 6번 = **(b) 직접 git push** · 7번 = **(a) 커밋**
→ **에이전트는 저장소에 쓰지 않습니다.** 아래 내용을 오너가 직접 커밋·푸시합니다.

---

## 1. 저장소 현황 (실측)

| 항목 | 값 |
|---|---|
| 저장소 | `dongjincho508/certpilot` (public) |
| 기본 브랜치 | `main` |
| 현재 내용 | `README.md` **1개 (11 bytes)** |
| 커밋 | **1개** — `c5565fba…` `"Initial commit"` |
| MCP 접근 | read-only 유지 (쓰기 도구 미노출) |

---

## 2. 커밋 대상 파일

로컬 위치: `C:\Users\Master\AppData\Local\hermes\profiles\00-commander\plans\certpilot\`

| 로컬 파일 | 저장소 목적지 (제안) | 크기 | 비고 |
|---|---|---|---|
| `PRD_v0.2.md` | `docs/PRD.md` | 33 KB | **확정본** — 기준선 |
| `DECISIONS.md` | `docs/decisions.md` | 26 KB | PRD 결정 50건 기록 |
| `OWNER_DECISIONS.md` | `docs/owner-decisions.md` | 3 KB | 프로젝트 승인 10건 기록 |
| `PRD_v0.1.md` | `docs/history/PRD_v0.1.md` | 7.6 KB | 이력 보존 |
| `PRD_v0.2_draft.md` | `docs/history/PRD_v0.2_draft.md` | 29 KB | 이력 보존 |
| `TELEGRAM_SETUP_STEPS.md` | `docs/ops/telegram-setup.md` | 8.7 KB | 운영 문서 |

**제외 (커밋하지 않음)**
- `.prd_approved`, `.nudge_state.json` — 로컬 상태 파일
- 스크립트(`scripts/certpilot_*.py`) — 별도 결정 필요 (저장소에 넣을지 오너 판단)

---

## 3. 제안 저장소 구조

```
certpilot/
├── README.md                  # 기존 파일 대체 (아래 4번 참조)
└── docs/
    ├── PRD.md                 # 확정본 (기준선)
    ├── decisions.md           # PRD 결정 50건
    ├── owner-decisions.md     # 프로젝트 승인 10건
    ├── history/
    │   ├── PRD_v0.1.md
    │   └── PRD_v0.2_draft.md
    └── ops/
        └── telegram-setup.md
```

---

## 4. README.md 대체안

현재 README는 11 bytes(거의 빈 파일)입니다. 아래로 교체 제안:

```markdown
# CertPilot

기업용 SSL/TLS 인증서 수명주기 관리 플랫폼 (개발 중)

## 현재 상태

- **PRD v0.2 확정** (2026-10-21) — 결정 50건 반영, 오너 승인 완료
- 다음 단계: v0.2 독립 검토 라운드 → 설계 착수

## MVP 범위 (PRD v0.2)

Linux 서버를 대상으로 SSH를 통한 인증서 조회와 만료 모니터링.
인증서 발급·갱신·배포 자동화는 후속 단계.

- 대상: Linux 서버 (SSH)
- 기능: 인증서 조회(디스크 파일 + 실행 중 서비스) · 만료 모니터링 · 현황 화면
- 형식: PEM / PKCS#12 / JKS (인증서만 추출, 개인키 미접근)
- 상태: 정상 · 만료 임박(≤30일) · 만료 · 조회 실패 · 인증서 미발견 · 확인 필요
- MVP 제외: 자동 발급·갱신, 파일 배포, 개인키 관리, Windows/AIX/네트워크 장비, CA API 통합

## 문서

- [PRD](docs/PRD.md) — 제품 요구사항 정의서 (확정본)
- [결정 기록](docs/decisions.md) — PRD 결정 50건
- [승인 기록](docs/owner-decisions.md) — 프로젝트 승인 10건
```

---

## 5. 커밋 메시지 초안

**커밋 1 — 확정 PRD 및 결정 기록**
```
docs: add CertPilot PRD v0.2 (approved) and decision records

- PRD v0.2: 50 owner decisions applied, approved 2026-10-21
- decisions.md: full decision log with values and rationale
- owner-decisions.md: project-level approvals (10 items)
- history/: v0.1 and v0.2-draft retained for traceability
```

**커밋 2 — README**
```
docs: replace placeholder README with project overview
```

---

## 6. 오너 실행 절차

```bash
git clone https://github.com/dongjincho508/certpilot.git
cd certpilot
mkdir -p docs/history docs/ops

# 로컬 파일 복사 (경로는 실제 위치에 맞게 조정)
cp "<HERMES_HOME>/plans/certpilot/PRD_v0.2.md"          docs/PRD.md
cp "<HERMES_HOME>/plans/certpilot/DECISIONS.md"         docs/decisions.md
cp "<HERMES_HOME>/plans/certpilot/OWNER_DECISIONS.md"   docs/owner-decisions.md
cp "<HERMES_HOME>/plans/certpilot/PRD_v0.1.md"          docs/history/PRD_v0.1.md
cp "<HERMES_HOME>/plans/certpilot/PRD_v0.2_draft.md"    docs/history/PRD_v0.2_draft.md
cp "<HERMES_HOME>/plans/certpilot/TELEGRAM_SETUP_STEPS.md" docs/ops/telegram-setup.md

git add docs/
git commit -m "docs: add CertPilot PRD v0.2 (approved) and decision records"
git push origin main
```

> `HERMES_HOME` = `C:\Users\Master\AppData\Local\hermes\profiles\00-commander`

---

## 7. 확인 필요 (오너 결정)

- 저장소 구조를 위 제안대로 할지, 다른 배치를 원하는지
- `scripts/certpilot_*.py` (넛지·파서·폼) 을 저장소에 포함할지
- README 대체를 승인할지
