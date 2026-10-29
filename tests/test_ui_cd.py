"""설정·운영 화면을 실제 브라우저(Playwright/Chromium)로 확인: 체크리스트·탭·이동 버튼·모바일 폭. node/playwright 가 없으면 건너뜀."""
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest
import yaml
from werkzeug.serving import make_server

from certdeploy import approval, backupjob as bj
from certdeploy.bundle import load_bundle
from certdeploy.config import parse_config
from certpilot_api.app import create_app
from pki_helpers import make_pki

ROOT = Path(__file__).resolve().parent.parent
PW = "Str0ng!Passw0rd"


def _node_env():
    node = shutil.which("node")
    if not node:
        return None
    r = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True) if shutil.which("npm") else None
    path = (r.stdout.strip() if r and r.returncode == 0 else "")
    probe = subprocess.run([node, "-e", "require('playwright')"], capture_output=True, env={**os.environ, "NODE_PATH": path})
    return {**os.environ, "NODE_PATH": path} if probe.returncode == 0 else None


@pytest.fixture
def server(tmp_path, monkeypatch):
    etc, state, admin, mon = tmp_path / "etc", tmp_path / "state", tmp_path / "admin", tmp_path / "mon"
    for d in (etc, state / "hnu/managed", admin, mon):
        d.mkdir(parents=True)
    c, k, _, _ = make_pki(state / "hnu/managed", name="hnu", san=("*.hnu.kr",), days_to=19)
    monkeypatch.setenv("BK_PASS", "backup-Pass-phrase-1")
    cfg = {"state_dir": str(state), "approval": {"required": True, "approvers": 2},
           "notify": {"smtp": {"host": "smtp.hnu.kr", "from": "c@hnu.kr", "to": ["a@hnu.kr"]}},
           "backup": {"dir": str(tmp_path / "bk"), "passphrase_env": "BK_PASS", "etc_dir": str(etc), "admin_data_dir": str(admin),
                      "monitoring_dir": str(mon), "nginx_files": [], "copy_to": [{"kind": "dir", "name": "nas", "path": str(tmp_path / "nas")}]},
           "certificates": [{"name": "hnu", "certificate": {"cert_file": str(c), "key_file": str(k)},
                             "targets": [{"name": "w", "type": "apache", "cert_path": "/c", "key_path": "/k"}]}]}
    (etc / "certdeploy.yml").write_text(yaml.safe_dump(cfg, allow_unicode=True))
    pc = parse_config(cfg)
    approval.gate("hnu", pc.certs[0].state_dir, pc.certs[0].approval, load_bundle(str(c), str(k)), ["w"], "renew")
    bj.save_status(str(state), bj.run_backup(pc, str(etc / "certdeploy.yml"), pc.backup, "backup-Pass-phrase-1"))
    app = create_app({"DATA_DIR": str(tmp_path / "data"), "ADMIN_USER": "root1", "ADMIN_PASSWORD": PW, "SECURE_COOKIE": False, "CERTDEPLOY_CONFIG": str(etc / "certdeploy.yml")})
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_cd_screen_in_real_browser(server):
    env = _node_env()
    if not env:
        pytest.skip("node/playwright 없음")
    r = subprocess.run(["node", str(ROOT / "tests/ui_cd_smoke.js"), server, "root1", PW], capture_output=True, text=True, env=env, timeout=120)
    assert r.returncode == 0 and "UI_OK" in r.stdout, r.stdout + r.stderr
