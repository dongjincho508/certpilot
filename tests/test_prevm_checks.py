"""VM 설치 전 점검: 문서·설정·유닛·compose 의 정적 검증, openssl 교차 검증, 입력 퍼징, 성능, 신규 점검 기능."""
import json
import os
import random
import re
import shlex
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from click.testing import CliRunner
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from certdeploy import manual as mn
from certdeploy.cli import main as cd_main
from certdeploy.config import ConfigError, parse_config
from certdeploy.schema import config_schema
from certpilot_cli.cli import main as cp_main
from certpilot_core import netutil
from certpilot_core.store import Store
from pki_helpers import make_pki, sign_csr

ROOT = os.path.join(os.path.dirname(__file__), "..")
DOCS = [os.path.join(dp, f) for dp, _, fs in os.walk(os.path.join(ROOT, "docs")) for f in fs if f.endswith(".md")
        and "archive" not in dp and "history" not in dp] + [os.path.join(ROOT, "README.md"), os.path.join(ROOT, "monitoring", "README.md")]


def read(p):
    return open(p, encoding="utf-8").read()


# ------------------------------------------------------------------ 문서 정합성
def bash_blocks():
    out = []
    for p in DOCS:
        for m in re.finditer(r"```bash\n(.*?)```", read(p), re.S):
            out.append((os.path.relpath(p, ROOT), m.group(1)))
    return out


@pytest.mark.parametrize("path,block", bash_blocks(), ids=lambda v: v if isinstance(v, str) and len(v) < 60 else None)
def test_doc_bash_blocks_have_valid_syntax(path, block):
    block = re.sub(r"<[가-힣A-Za-z][^<>\s]*>", "PLACEHOLDER", block)           # 문서의 <호스트> 같은 자리표시자
    r = subprocess.run(["bash", "-n"], input=block, capture_output=True, text=True)
    assert r.returncode == 0, f"{path}\n{r.stderr}\n{block[:300]}"


def test_doc_certdeploy_commands_exist_in_cli():
    """문서의 `certdeploy [-c 파일] [--옵션] <명령>` 줄이 실제 CLI 하위 명령과 일치하는지(명령 위치에 있을 때만 검사)."""
    sub = set(cd_main.commands)
    pat = re.compile(r"^\s*(?:\$ )?(?:sudo(?:\s+-u\s+\w+)?\s+)?(?:\S*/)?certdeploy(?:\s+(?:-c|--cert)\s+\S+|\s+--(?:debug|verbose)|\s+-v)*\s+([a-z][a-z-]+)\b")
    cd_var = re.compile(r"^\s*\$CD(?:\s+--debug)?\s+([a-z][a-z-]+)\b")        # 시험 시나리오의 $CD <명령>
    seen = set()
    for _, block in bash_blocks():
        for line in block.splitlines():
            m = pat.match(line) or cd_var.match(line)
            if m:
                seen.add(m.group(1))
    assert seen, "검사할 명령을 하나도 찾지 못했습니다(패턴 점검 필요)"
    assert not (seen - sub), f"문서에 있으나 CLI 에 없는 certdeploy 하위 명령: {seen - sub}"


def test_doc_relative_links_resolve():
    broken = []
    for p in DOCS:
        for m in re.finditer(r"\]\((?!https?://|#|mailto:)([^)\s#]+)(?:#[^)]*)?\)", read(p)):
            target = os.path.normpath(os.path.join(os.path.dirname(p), m.group(1)))
            if not os.path.exists(target):
                broken.append(f"{os.path.relpath(p, ROOT)} → {m.group(1)}")
    assert not broken, broken


# ------------------------------------------------------------------ 설정·유닛·compose
def test_systemd_units_verify(tmp_path):
    if not shutil.which("systemd-analyze"):
        pytest.skip("systemd-analyze 없음")
    d = os.path.join(ROOT, "certdeploy", "systemd")
    r = subprocess.run(["systemd-analyze", "verify", f"{d}/certdeploy-renew.service", f"{d}/certdeploy-renew.timer"], capture_output=True, text=True)
    problems = [l for l in r.stderr.splitlines() if l and "is not executable" not in l and "No such file" not in l]   # 설치 전이라 바이너리가 없는 것은 정상
    assert not problems, problems


def test_compose_renders_and_fails_fast_without_secrets(tmp_path):
    if not shutil.which("docker"):
        pytest.skip("docker CLI 없음")
    mon = os.path.join(ROOT, "monitoring")
    base = ["docker", "compose", "--env-file", os.path.join(mon, ".env.example"), "-f", os.path.join(mon, "docker-compose.yml")]
    r = subprocess.run(base + ["config", "-q"], capture_output=True, text=True)
    if "docker" in r.stderr and "not found" in r.stderr:
        pytest.skip("docker compose 없음")
    assert r.returncode != 0 and "GRAFANA_ADMIN_PASSWORD" in r.stderr                  # 비밀번호 없이는 기동하지 않는다
    env = tmp_path / ".env"
    env.write_text(read(os.path.join(mon, ".env.example")).replace("GRAFANA_ADMIN_PASSWORD=", "GRAFANA_ADMIN_PASSWORD=Xx-test-password-1"))
    ok = subprocess.run(["docker", "compose", "--env-file", str(env), "-f", os.path.join(mon, "docker-compose.yml"), "config", "--format", "json"],
                        capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    cfg = json.loads(ok.stdout)
    assert {"ssl-exporter", "prometheus", "pushgateway", "alertmanager", "grafana"} <= set(cfg["services"])
    for name, svc in cfg["services"].items():
        for port in svc.get("ports", []):
            assert port.get("host_ip") in ("127.0.0.1", "::1"), f"{name} 포트가 외부에 노출됨: {port}"


def test_example_config_parses_and_matches_schema():
    jsonschema = pytest.importorskip("jsonschema")
    for name in ("certdeploy.example.yml", "certdeploy.manual.example.yml", "certdeploy.acme.example.yml"):
        jsonschema.validate(yaml.safe_load(read(os.path.join(ROOT, "certdeploy", name))), config_schema())
        parse_config(yaml.safe_load(read(os.path.join(ROOT, "certdeploy", name))))
    bad = {"state_dir": "relative", "targets": [{"name": "x y", "type": "iis"}]}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, config_schema())
    r = CliRunner().invoke(cd_main, ["-c", "x", "schema"])
    assert r.exit_code == 0 and json.loads(r.output)["title"] == "certdeploy 설정"


# ------------------------------------------------------------------ 독립 구현(openssl) 교차 검증
def test_imported_chain_verifies_with_openssl_in_any_input_order(tmp_path):
    ca = {}
    make_pki(tmp_path, "seed", shared_ca=ca)
    key_pem, csr_pem = mn.generate_csr(["*.univ.example", "univ.example"])
    leaf = sign_csr(csr_pem, ca)
    certs = [ca["root"], leaf, ca["inter"]]
    random.Random(1).shuffle(certs)
    b, _ = mn.build_bundle(certs, __import__("cryptography").hazmat.primitives.serialization.load_pem_private_key(key_pem, None))
    (tmp_path / "root.pem").write_bytes(ca["root"].public_bytes(Encoding.PEM))
    (tmp_path / "full.pem").write_bytes(b.fullchain_pem())
    r = subprocess.run(["openssl", "verify", "-CAfile", str(tmp_path / "root.pem"), "-untrusted", str(tmp_path / "full.pem"),
                        "-verify_hostname", "www.univ.example", "-purpose", "sslserver", str(tmp_path / "full.pem")], capture_output=True, text=True)
    assert r.returncode == 0 and "OK" in r.stdout, r.stdout + r.stderr
    # 키와 인증서 공개키 일치도 openssl 로 확인
    pub_c = subprocess.run(["openssl", "x509", "-in", str(tmp_path / "full.pem"), "-noout", "-pubkey"], capture_output=True, text=True).stdout
    (tmp_path / "k.pem").write_bytes(key_pem)
    pub_k = subprocess.run(["openssl", "pkey", "-in", str(tmp_path / "k.pem"), "-pubout"], capture_output=True, text=True).stdout
    assert pub_c == pub_k and pub_c


# ------------------------------------------------------------------ 퍼징: 잘못된 입력에도 예외로 터지지 않는다
def test_import_parsers_never_raise_unexpected_errors(tmp_path):
    rnd = random.Random(7)
    ca = {}
    make_pki(tmp_path, "seed", shared_ca=ca)
    good = ca["inter"].public_bytes(Encoding.PEM)
    samples = [b"", b"\x00" * 64, os.urandom(300), good[:-30], good.replace(b"MII", b"XXX", 1), good + b"\n" + os.urandom(40),
               b"-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n", pkcs7.serialize_certificates([ca["inter"]], Encoding.DER)[:-5],
               b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"]
    for i in range(30):
        b = bytearray(good)
        for _ in range(rnd.randint(1, 8)):
            b[rnd.randrange(len(b))] = rnd.randrange(256)
        samples.append(bytes(b))
    for n, data in enumerate(samples):
        f = tmp_path / f"s{n}"
        f.write_bytes(data)
        for fn in (lambda: mn.collect_certs([str(f)]), lambda: mn.load_key_file(str(f)), lambda: mn.load_pfx(str(f), "x")):
            try:
                fn()
            except mn.ManualError:
                pass                                                            # 정의된 오류만 허용


@pytest.mark.parametrize("bad", [None, 1, [], "x", {"targets": "x"}, {"targets": [None]}, {"targets": [{"name": 1}]},
                                 {"targets": [{"name": "a", "type": "tomcat", "keystore_path": 5}], "certificate": []},
                                 {"state_dir": 5}, {"options": []}, {"notify": []}, {"notify": {"smtp": []}}, {"defaults": []}])
def test_config_parser_rejects_garbage_with_config_error(bad):
    with pytest.raises(ConfigError):
        parse_config(bad)


# ------------------------------------------------------------------ 신규: Nagios 형식 점검
def cfg_for(tmp_path, days_to):
    cert, key = make_pki(tmp_path, "c", days_from=-1, days_to=days_to)[:2]
    p = tmp_path / "cd.yml"
    p.write_text(yaml.safe_dump({"state_dir": str(tmp_path / "st"), "certificate": {"cert_file": str(cert), "key_file": str(key)},
                                 "targets": [{"name": "w", "type": "generic", "reload_cmd": "none",
                                              "files": [{"path": str(tmp_path / "o.crt"), "content": "fullchain"}]}]}))
    return str(p)


@pytest.mark.parametrize("days,code,word", [(90, 0, "OK"), (20, 1, "WARNING"), (5, 2, "CRITICAL")])
def test_check_thresholds_and_perfdata(tmp_path, days, code, word):
    r = CliRunner().invoke(cd_main, ["-c", cfg_for(tmp_path, days), "check"])
    assert r.exit_code == code and r.output.startswith(f"CERTDEPLOY {word} - ") and "_days_left'=" in r.output and ";30;14" in r.output


def test_check_custom_thresholds_and_unknown(tmp_path):
    r = CliRunner().invoke(cd_main, ["-c", cfg_for(tmp_path, 60), "check", "--warn", "90", "--crit", "10"])
    assert r.exit_code == 1
    assert CliRunner().invoke(cd_main, ["-c", str(tmp_path / "missing.yml"), "check"]).exit_code == 3
    p = tmp_path / "nocert.yml"
    p.write_text(yaml.safe_dump({"certificate": {"cert_file": "/nope.crt", "key_file": "/nope.key"},
                                 "targets": [{"name": "w", "type": "generic", "reload_cmd": "none", "files": [{"path": "/x", "content": "cert"}]}]}))
    r = CliRunner().invoke(cd_main, ["-c", str(p), "check"])
    assert r.exit_code == 3 and "UNKNOWN" in r.output


def test_check_flags_stale_and_unreachable_served_certificate(tmp_path, monkeypatch):
    cfg = cfg_for(tmp_path, 90)
    raw = yaml.safe_load(open(cfg))
    raw["targets"][0]["verify"] = {"host": "127.0.0.1", "port": 9}
    open(cfg, "w").write(yaml.safe_dump(raw))
    r = CliRunner().invoke(cd_main, ["-c", cfg, "check"])
    assert r.exit_code == 2 and "서빙 확인 실패" in r.output                          # 접속 불가 = CRITICAL
    monkeypatch.setattr("certdeploy.engine.Deployer._tls", lambda self, t: 12345)
    r = CliRunner().invoke(cd_main, ["-c", cfg, "check"])
    assert r.exit_code == 1 and "이전/다른 인증서 서빙" in r.output


# ------------------------------------------------------------------ 신규: file_sd 내보내기
def test_export_targets_file_sd(tmp_path):
    db = str(tmp_path / "c.db")
    st = Store(db)
    for name, host, ports, grp, os_t in (("a", "a.univ.example", [443, 8443], "홈페이지", "rhel"), ("b", "b.univ.example", [], "홈페이지", "rhel"), ("c", "c.univ.example", [443], None, "auto")):
        st.add_server({"id": name, "name": name, "hostname": host, "port": 22, "account": "u", "paths": [], "tls_ports": ports,
                       "warn_days": 30, "os_type": os_t, "group": grp, "memo": None, "created_at": "2026-01-01T00:00:00Z"})
    out = tmp_path / "t.yml"
    r = CliRunner().invoke(cp_main, ["export-targets", "--db", db, "-o", str(out)])
    assert r.exit_code == 0 and "4개" in r.output
    data = yaml.safe_load(out.read_text())
    by = {tuple(sorted(g["targets"])): g["labels"] for g in data}
    assert by[("a.univ.example:443", "a.univ.example:8443", "b.univ.example:443")] == {"group": "홈페이지", "os": "linux"}
    assert by[("c.univ.example:443",)] == {}


# ------------------------------------------------------------------ 보안 보강
@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/", "gopher://x", "/etc/passwd"])
def test_only_http_urls_are_opened(url):
    with pytest.raises(OSError):
        netutil.urlopen(url)


def test_update_user_rejects_unknown_columns(tmp_path):
    with pytest.raises(ValueError):
        Store(str(tmp_path / "s.db")).update_user("u", **{"role=role, password_hash": "x"})


# ------------------------------------------------------------------ 성능: 50대 동시 조회
def test_scan_all_50_servers_is_fast(tmp_path, sandbox):
    from certpilot_api.app import create_app
    from certpilot_core.remote import SandboxExecutor
    from conftest import make_cert, pem
    sandbox.put("/etc/nginx/ssl/a.crt", pem(make_cert("a.test", -1, 90, ["a.test"])[1]))
    app = create_app({"DATA_DIR": str(tmp_path / "d"), "ADMIN_USER": "root1", "ADMIN_PASSWORD": "Str0ng!Passw0rd", "SECURE_COOKIE": False},
                     executor_factory=lambda t: SandboxExecutor(sandbox.path), sleep=lambda s: None)
    c = app.test_client()
    c.post("/auth/login", json={"username": "root1", "password": "Str0ng!Passw0rd"})
    for i in range(50):
        assert c.post("/servers", json={"name": f"s{i}", "hostname": f"s{i}.example", "account": "u"}).status_code == 201
    t0 = time.monotonic()
    r = c.post("/scan")
    assert r.status_code == 200 and r.json["scanned"] == 50 and time.monotonic() - t0 < 30
    assert all(s["status"] == "OK" for s in r.json["servers"])


def test_scenario_doc_covers_all_tests_and_commands():
    text = read(os.path.join(ROOT, "docs", "ops", "test-scenarios.md"))
    for n in range(1, 14):
        assert f"### T-{n:02d} " in text, f"T-{n:02d} 시나리오 누락"
        assert f"| T-{n:02d} |" in text                                          # 결과 기록표
    used = set(re.findall(r"^\$CD ([a-z][a-z-]+)", text, re.M))
    assert {"validate", "preflight", "csr", "import", "deploy", "status", "check", "verify-audit", "backup", "restore", "trace", "plan"} <= used
    assert not (used - set(cd_main.commands))


def test_install_manual_commands_and_files_exist():
    text = read(os.path.join(ROOT, "docs", "ops", "vm-install-and-test.md"))
    for rel in re.findall(r"/opt/cert-monitor/src/([\w./*-]+)", text):
        if rel.endswith("/"):
            continue
        import glob
        assert glob.glob(os.path.join(ROOT, rel)), f"매뉴얼이 가리키는 파일 없음: {rel}"
    used = set(re.findall(r"(?:^|&& )\$CD ([a-z][a-z-]+)", text, re.M))
    assert {"validate", "preflight", "csr", "import", "plan", "deploy", "check", "diagnose", "backup"} <= used
    assert not (used - set(cd_main.commands))
    for img in re.findall(r"prom/(?:prometheus|alertmanager):v[\d.]+", text):
        assert img in read(os.path.join(ROOT, "monitoring", "docker-compose.yml")), f"compose 와 이미지 태그가 다름: {img}"
    for svc in ("ssl-exporter", "prometheus", "pushgateway", "alertmanager", "grafana"):
        assert svc in text
