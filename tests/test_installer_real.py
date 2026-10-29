"""설치 스크립트를 가짜 시스템 명령(dnf·systemctl·docker 등)만 끼운 격리 환경(overlay 마운트 네임스페이스)에서 **실제로 끝까지** 실행한다.
설치 → 비밀번호 생성·권한 → 설정 파일 생성 → 설치된 설정으로 실제 백업 실행 → 관리자 화면 기동·로그인·2단계 인증 강제까지 확인.
unshare/overlay 를 쓸 수 없는 환경(권한 없음)에서는 건너뛴다."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HARNESS, VERIFY = ROOT / "tests/installer_harness.sh", ROOT / "tests/installer_verify.py"


def _can_overlay(tmp_path_factory) -> bool:
    if not shutil.which("unshare") or os.geteuid() != 0:
        return False
    d = tmp_path_factory.mktemp("ovprobe")
    for n in ("up", "wk"):
        (d / n).mkdir()
    r = subprocess.run(["unshare", "-m", "--propagation", "private", "bash", "-c",
                        f"mount -t overlay overlay -o lowerdir=/etc,upperdir={d}/up,workdir={d}/wk /etc && true"], capture_output=True)
    return r.returncode == 0


@pytest.fixture(scope="module")
def overlay_ok(tmp_path_factory):
    if not _can_overlay(tmp_path_factory):
        pytest.skip("overlay 마운트 네임스페이스를 쓸 수 없음(root·unshare 필요)")


def run(scen, tmp_path, *opts, env=None):
    work = tmp_path / scen
    work.mkdir()
    p = subprocess.run(["bash", str(HARNESS), scen, str(work), *opts], capture_output=True, text=True, timeout=600,
                       env={**os.environ, "VERIFY": str(VERIFY), **(env or {})})
    assert p.returncode == 0 and f"INSTALL_VERIFY_OK {scen}" in p.stdout, (p.stdout[-1500:] + p.stderr[-1500:] + _tail(work))
    return work


def _tail(work):
    f = work / "install1.out"
    return "\n--- install1.out ---\n" + f.read_text()[-1500:] if f.exists() else ""


FULL = ["--hostname", "mgmt.hnu.kr", "--mail-to", "a@hnu.kr,b@hnu.kr", "--smtp-host", "smtp.hnu.kr:587", "--smtp-from", "c@hnu.kr",
        "--smtp-user", "svc@hnu.kr", "--admin-cidr", "10.10.0.0/24", "--enable-renew-timer", "--discover-cidr", "10.10.0.0/24,10.20.0.0/24",
        "--require-mfa", "--enable-backup", "--backup-copy-dir", "/mnt/nas/cd"]


def test_full_install_end_to_end(overlay_ok, tmp_path):
    run("full", tmp_path, *FULL, env={"SMTP_PASSWORD": "smtp-secret-pw"})


def test_rerun_is_idempotent_and_keeps_passwords(overlay_ok, tmp_path):
    run("rerun", tmp_path, "--hostname", "mgmt.hnu.kr", "--mail-to", "a@hnu.kr", "--smtp-host", "smtp.hnu.kr:587", "--smtp-from", "c@hnu.kr", "--enable-backup")


def test_failure_then_resume_continues_where_it_stopped(overlay_ok, tmp_path):
    run("resume", tmp_path, "--hostname", "mgmt.hnu.kr", "--mail-to", "a@hnu.kr", "--smtp-host", "smtp.hnu.kr:587", "--smtp-from", "c@hnu.kr")


def test_minimal_install_without_options(overlay_ok, tmp_path):
    run("minimal", tmp_path)


def test_refuses_non_rocky(overlay_ok, tmp_path):
    run("notrocky", tmp_path)
