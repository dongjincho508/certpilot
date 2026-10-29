"""문서·화면 연결 점검: 시작 가이드가 모든 화면 탭과 설치 단계를 설명하고, 문서 링크·이미지가 깨지지 않았는지"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", ROOT / "docs/README.md", *sorted((ROOT / "docs/ops").glob("*.md"))]


def test_relative_links_and_images_resolve():
    bad = []
    for f in DOCS:
        for m in re.finditer(r"\]\(([^)\s]+)\)", f.read_text(encoding="utf-8")):
            link = m.group(1).split("#")[0]
            if not link or link.startswith(("http://", "https://", "mailto:")):
                continue
            if not (f.parent / link).resolve().exists():
                bad.append(f"{f.relative_to(ROOT)} → {link}")
    assert not bad, bad


def test_quickstart_covers_screens_steps_and_is_linked():
    q = (ROOT / "docs/ops/quickstart.md").read_text(encoding="utf-8")
    html = (ROOT / "frontend/templates/index.html").read_text(encoding="utf-8")
    for tab in ("현황", "시작하기·요약", "인증서·승인", "알림", "백업", "감사 로그", "사용자", "진단"):
        assert tab in q, tab
        assert tab.split("·")[0] in html
    for step in ("preflight", "base", "docker", "source", "monitoring", "nginx", "certdeploy", "admin", "verify"):
        assert step in (ROOT / "scripts/install-mgmt-server.sh").read_text(encoding="utf-8")
    for must in ("install-mgmt-server.sh", "설치 마법사", "--dry-run", "같은 명령을 다시 실행", "서버 밖", "증상", "백업 비밀번호", "T-01~T-28"):
        assert must in q, must
    assert "quickstart.md" in (ROOT / "docs/README.md").read_text(encoding="utf-8") and "quickstart.md" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "quickstart.md" in (ROOT / "docs/ops/vm-install-and-test.md").read_text(encoding="utf-8")


def test_scenarios_count_matches_docs():
    s = (ROOT / "docs/ops/test-scenarios.md").read_text(encoding="utf-8")
    ids = sorted(set(re.findall(r"^### (T-\d+[a-z]?)\b", s, re.M)))
    assert "T-28" in ids and len(ids) >= 28
    for f in (ROOT / "docs/ops/quickstart.md", ROOT / "docs/ops/vm-install-and-test.md"):
        assert "T-01~T-28" in f.read_text(encoding="utf-8")


def test_wizard_questions_are_documented():
    q = (ROOT / "docs/ops/quickstart.md").read_text(encoding="utf-8")
    sh = (ROOT / "scripts/install-mgmt-server.sh").read_text(encoding="utf-8")
    for var in ("HOSTNAME_FQDN", "MAIL_TO", "SMTP_SMARTHOST", "ADMIN_CIDR", "REQUIRE_MFA", "ENABLE_BACKUP", "BACKUP_COPY_DIR", "DISCOVER_CIDR", "ENABLE_RENEW_TIMER"):
        assert "ask" in sh and var in sh.split("wizard() {")[1].split("print_plan() {")[0], var
    for col in ("서버 호스트명", "알림 메일", "관리자 PC 대역", "2단계 인증 필수", "백업", "자동 탐색", "자동 갱신"):
        assert col in q, col


def test_ui_uses_new_tab_names_everywhere():
    for f in DOCS + [ROOT / "scripts/install-mgmt-server.sh", ROOT / "frontend/templates/index.html"]:
        assert "발급·배포 설정" not in f.read_text(encoding="utf-8"), f
