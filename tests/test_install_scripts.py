"""관리 서버 자동 설치 스크립트 검증: 문법·shellcheck·dry-run(무변경)·Alertmanager 렌더링(+amtool)·Kickstart·문서 연결"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/install-mgmt-server.sh"
RENDER = ROOT / "scripts/render_alertmanager.py"
KS = ROOT / "scripts/kickstart/rocky10-mgmt.ks.example"
AM_SRC = ROOT / "monitoring/alertmanager/alertmanager.yml"
DRY = ["bash", str(SCRIPT), "--dry-run", "--skip-os-check", "--yes", "--hostname", "mgmt.hnu.kr",
       "--mail-to", "a@hnu.kr,b@hnu.kr", "--smtp-host", "smtp.hnu.kr:587", "--smtp-from", "cert-monitor@hnu.kr"]

sys.path.insert(0, str(ROOT / "scripts"))
import render_alertmanager as ra  # noqa: E402


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=60, **kw)


def test_bash_syntax():
    assert sh(["bash", "-n", str(SCRIPT)]).returncode == 0


@pytest.mark.skipif(not shutil.which("shellcheck"), reason="shellcheck 없음")
def test_shellcheck_clean():
    r = sh(["shellcheck", "-x", "-S", "warning", str(SCRIPT)])
    assert r.returncode == 0, r.stdout


def test_help_and_bad_option():
    assert "--hostname" in sh(["bash", str(SCRIPT), "--help"]).stdout
    assert sh(["bash", str(SCRIPT), "--nope"]).returncode == 2


def test_dry_run_lists_all_steps_and_changes_nothing():
    before = {p: p.exists() for p in map(Path, ["/var/lib/cert-install", "/root/cert-install-summary.txt", "/etc/certdeploy"])}
    r = sh(DRY)
    assert r.returncode == 0, r.stdout + r.stderr
    for n, step in enumerate("preflight base docker source monitoring nginx certdeploy admin verify".split(), 1):
        assert f"[{n}/9] {step}" in r.stdout
    assert "dnf -y install docker-ce" in r.stdout and "pip install --quiet -e" in r.stdout
    assert {p: p.exists() for p in before} == before        # 아무 것도 만들지 않음


def test_dry_run_never_prints_secrets():
    env = dict(os.environ, SMTP_PASSWORD="s3cr3t-smtp-pw", HOOKURL="https://hook.example/x?token=zzz")
    r = sh(DRY + ["--smtp-user", "u@hnu.kr", "--webhook-url-env", "HOOKURL"], env=env)
    assert r.returncode == 0
    assert "s3cr3t-smtp-pw" not in r.stdout + r.stderr and "token=zzz" not in r.stdout + r.stderr


@pytest.mark.parametrize("bad", [["--hostname", "a b;rm"], ["--mail-to", "x"], ["--smtp-host", "smtp"],
                                 ["--admin-user", "A;x"], ["--admin-cidr", "10.0.0.0"], ["--config-template", "zz"],
                                 ["--only", "bogus"]])
def test_input_validation(bad):
    r = sh(["bash", str(SCRIPT), "--dry-run", "--skip-os-check", "--yes", *bad])
    assert r.returncode != 0


def test_partial_mail_options_rejected():
    r = sh(["bash", str(SCRIPT), "--dry-run", "--skip-os-check", "--yes", "--mail-to", "a@hnu.kr"])
    assert r.returncode != 0 and "함께" in r.stdout


def test_only_runs_selected_step():
    r = sh(DRY + ["--only", "nginx"])
    assert "[6/9] nginx" in r.stdout and "[2/9] base" not in r.stdout


def test_config_file_rejects_unknown_key(tmp_path):
    f = tmp_path / "c.conf"
    f.write_text("EVIL=1\n")
    assert sh(["bash", str(SCRIPT), "--dry-run", "--config", str(f)]).returncode != 0
    f.write_text('HOSTNAME_FQDN="mgmt.hnu.kr"\n')
    assert sh(["bash", str(SCRIPT), "--dry-run", "--skip-os-check", "--yes", "--config", str(f)]).returncode == 0


# ---------------------------------------------------------------- render_alertmanager
def test_render_replaces_all_recipients_and_removes_auth():
    out = ra.render(AM_SRC.read_text(), "smtp.hnu.kr:587", "cert-monitor@hnu.kr", "a@hnu.kr,b@hnu.kr")
    assert out.count('to: "a@hnu.kr,b@hnu.kr"') == 3 and "univ.example" not in out
    assert "smtp_auth_username" not in out and "smtp_auth_password_file" not in out
    assert "webhook_configs" not in out


def test_render_keeps_auth_and_webhook_when_requested():
    out = ra.render(AM_SRC.read_text(), "smtp.hnu.kr:587", "c@hnu.kr", "a@hnu.kr", user="u@hnu.kr", webhook=True)
    assert 'smtp_auth_username: "u@hnu.kr"' in out and "smtp_auth_password_file" in out and "webhook_configs" in out


def test_render_no_tls():
    out = ra.render(AM_SRC.read_text(), "smtp.hnu.kr:25", "c@hnu.kr", "a@hnu.kr", tls=False)
    assert "smtp_require_tls: false" in out


@pytest.mark.parametrize("bad", ['a"b@x', "a\nb@x", "a\\b@x"])
def test_render_rejects_injection(bad):
    with pytest.raises(ValueError):
        ra.render(AM_SRC.read_text(), "smtp.hnu.kr:587", "c@hnu.kr", bad)


@pytest.mark.parametrize("kw", [{}, {"user": "u@hnu.kr", "webhook": True}, {"tls": False}])
def test_rendered_config_passes_amtool(tmp_path, kw):
    amtool = os.environ.get("AMTOOL") or shutil.which("amtool")
    if not amtool:
        pytest.skip("amtool 없음")
    base = tmp_path / "am"
    shutil.copytree(ROOT / "monitoring/alertmanager", base, ignore=shutil.ignore_patterns("secrets"))
    shutil.copytree(ROOT / "monitoring/alertmanager/secrets.example", base / "secrets")
    out = base / "alertmanager.local.yml"
    out.write_text(ra.render(AM_SRC.read_text(), "smtp.hnu.kr:587", "c@hnu.kr", "a@hnu.kr,b@hnu.kr", **kw))
    text = out.read_text().replace("/etc/alertmanager/", f"{base}/")
    out.write_text(text)
    r = sh([amtool, "check-config", str(out)])
    assert r.returncode == 0, r.stdout + r.stderr


def test_render_cli(tmp_path):
    out = tmp_path / "o.yml"
    r = sh([sys.executable, str(RENDER), "--in", str(AM_SRC), "--out", str(out), "--smarthost", "s.hnu.kr:587",
            "--from", "c@hnu.kr", "--to", "a@hnu.kr"])
    assert r.returncode == 0 and "a@hnu.kr" in out.read_text()


# ---------------------------------------------------------------- Kickstart / 연결 점검
@pytest.mark.skipif(not shutil.which("ksvalidator"), reason="pykickstart 없음")
def test_kickstart_valid_for_rhel10():
    r = sh(["ksvalidator", "-v", "RHEL10", str(KS)])
    assert r.returncode == 0, r.stdout + r.stderr


def test_kickstart_has_no_plaintext_password():
    t = KS.read_text()
    assert "--iscrypted" in t and "rootpw --lock" in t and "--plaintext" not in t


def test_script_references_exist_in_repo():
    t = SCRIPT.read_text()
    for rel in re.findall(r'\$SRC_DIR/([\w./-]+)', t):
        if rel.endswith(("local.yml", "override.yml")) or "$" in rel:
            continue
        assert (ROOT / rel).exists() or (ROOT / (rel + ".example")).exists(), rel
    for rel in ["monitoring/nginx/grafana.conf.example", "monitoring/nginx/certdeploy-admin.conf.example",
                "certdeploy/systemd/certdeploy-admin.service", "certdeploy/systemd/certdeploy-renew.timer",
                "certdeploy/certdeploy.manual.example.yml", "certdeploy/certdeploy.acme.example.yml",
                "certdeploy/certdeploy.waf-manual.example.yml", "monitoring/.env.example"]:
        assert (ROOT / rel).exists(), rel


def test_alertmanager_secrets_owned_by_container_user():
    t = SCRIPT.read_text()
    assert "65534:65534" in t and "chmod 700" in t


def test_generated_files_are_gitignored():
    ig = (ROOT / ".gitignore").read_text()
    for p in ["alertmanager.local.yml", "docker-compose.override.yml", "monitoring/alertmanager/secrets/"]:
        assert p in ig


def test_docs_mention_install_script():
    d = (ROOT / "docs/ops/vm-install-and-test.md").read_text()
    assert "install-mgmt-server.sh" in d and "rocky10-mgmt.ks.example" in d
