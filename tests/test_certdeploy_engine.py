import logging
import os
import socket
import ssl
import stat
import threading

import pytest
from cryptography import x509

from certdeploy.bundle import load_bundle
from certdeploy.config import parse_config
from certdeploy.engine import Deployer
from certdeploy.notify import NullNotifier
from certdeploy.state import LockedError, State, exclusive_lock
from certdeploy.transport import LocalTransport
from certdeploy.verify import VerifyError, tls_serial
from pki_helpers import make_pki


class Recorder(NullNotifier):
    def __init__(self):
        self.fired, self.resolved = [], []

    def fire(self, target, summary, description, severity="critical"):
        self.fired.append((target, description))

    def resolve(self, target):
        self.resolved.append(target)


def file_verifier(path):
    """배포된 PEM 파일을 서빙 중인 인증서로 간주하는 가짜 검증기(재로드는 명령 성공 여부로 모사)."""
    def verify(host, port, sni=None):
        try:
            return x509.load_pem_x509_certificates(open(path, "rb").read())[0].serial_number
        except (OSError, ValueError):
            raise VerifyError("서빙 중인 인증서 없음")
    return verify


class Env:
    def __init__(self, tmp_path, **kw):
        self.tmp = tmp_path
        self.cert, self.key, self.leaf, _ = make_pki(tmp_path / "issued_dir" if (tmp_path / "issued_dir").mkdir() is None else tmp_path)
        self.web = tmp_path / "web"
        self.web.mkdir()
        self.marks = tmp_path / "marks"
        self.marks.mkdir()
        self.kw = kw

    def target(self, name="web1", **over):
        t = {"name": name, "type": "generic", "files": [
            {"path": str(self.web / f"{name}.crt"), "content": "fullchain"},
            {"path": str(self.web / f"{name}.key"), "content": "key", "mode": "0600"}],
             "check_cmd": f"echo check >> {self.marks}/{name}.log", "reload_cmd": f"echo reload >> {self.marks}/{name}.log",
             "verify": {"host": "www.univ.example", "port": 443}}
        t.update(over)
        return t

    def deployer(self, targets, verifier=None, notifier=None, sleeps=None, environ=None, **opts):
        cfg = parse_config({"certificate": {"cert_file": str(self.cert), "key_file": str(self.key)},
                            "state_dir": str(self.tmp / "state"), "targets": targets,
                            "options": {"verify_attempts": 3, "verify_interval": 1, **opts}})
        bundle = load_bundle(str(self.cert), str(self.key))
        return Deployer(cfg, bundle, State(cfg.state_dir), transport_factory=lambda tr: LocalTransport(),
                        verifier=verifier or file_verifier(self.web / "web1.crt"), notifier=notifier or Recorder(),
                        sleep=(sleeps.append if sleeps is not None else (lambda s: None)), environ=environ or {})


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def test_deploy_success_permissions_state_and_commands(env):
    d = env.deployer([env.target()])
    (r,) = d.deploy()
    assert r.status == "deployed" and "완료" in r.message
    assert (env.web / "web1.crt").read_bytes() == d.bundle.fullchain_pem()
    assert (env.web / "web1.key").read_bytes() == d.bundle.key_pem()
    assert mode(env.web / "web1.key") == 0o600 and mode(env.web / "web1.crt") == 0o644      # 개인키는 600
    assert (env.marks / "web1.log").read_text().split() == ["check", "reload"]                # 점검 → 재로드
    assert not [p for p in os.listdir(env.web) if ".new." in p]                               # 임시 파일 없음
    assert d.state.target("web1")["status"] == "ok" and d.state.target("web1")["serial"] == f"{d.bundle.serial:x}"
    assert d.notifier.resolved == ["web1"]
    assert State(d.cfg.state_dir).load().data["certificate"]["serial"] == f"{d.bundle.serial:x}"   # 디스크에 저장됨


def test_existing_files_are_backed_up_with_owner_preserved(env):
    old = env.web / "web1.crt"
    old.write_text("OLD CERT")
    os.chmod(old, 0o640)
    env.deployer([env.target()]).deploy()
    baks = [p for p in os.listdir(env.web) if p.startswith("web1.crt.bak-")]
    assert len(baks) == 1 and (env.web / baks[0]).read_text() == "OLD CERT"
    assert mode(env.web / baks[0]) == 0o640            # cp -p 로 권한 보존


def test_idempotent_second_run_skips(env):
    d = env.deployer([env.target()])
    assert d.deploy()[0].status == "deployed"
    log_before = (env.marks / "web1.log").read_text()
    r = env.deployer([env.target()]).deploy()[0]
    assert r.status == "skipped" and (env.marks / "web1.log").read_text() == log_before       # 재로드조차 안 함
    assert env.deployer([env.target()]).deploy(force=True)[0].status == "deployed"


def test_dry_run_changes_nothing(env):
    d = env.deployer([env.target()])
    r = d.deploy(dry_run=True)[0]
    assert r.status == "dry_run" and os.listdir(env.web) == [] and not (env.tmp / "state").exists()


def test_check_failure_rolls_back_and_notifies(env):
    (env.web / "web1.crt").write_text("OLD CERT")
    (env.web / "web1.key").write_text("OLD KEY")
    n = Recorder()
    d = env.deployer([env.target(check_cmd="echo 'bad config' >&2; false")], notifier=n)
    r = d.deploy()[0]
    assert r.status == "rolled_back" and "설정 점검 실패" in r.message and "bad config" in r.message
    assert (env.web / "web1.crt").read_text() == "OLD CERT" and (env.web / "web1.key").read_text() == "OLD KEY"
    assert not [p for p in os.listdir(env.web) if ".new." in p or ".bak-" in p]    # 롤백 후 잔여물 없음
    assert n.fired and n.fired[0][0] == "web1" and not n.resolved
    assert d.state.target("web1")["status"] == "rolled_back"
    assert (env.marks / "web1.log").read_text().split() == ["reload"]       # 점검 단계에서 실패해 재로드는 롤백 시 1회만


def test_rollback_removes_files_that_did_not_exist(env):
    d = env.deployer([env.target(check_cmd="false")])
    assert d.deploy()[0].status == "rolled_back"
    assert os.listdir(env.web) == []


def test_reload_failure_rolls_back_and_reloads_old_config(env):
    (env.web / "web1.crt").write_text("OLD")
    (env.web / "web1.key").write_text("OLDK")
    d = env.deployer([env.target(reload_cmd=f"echo reload >> {env.marks}/r.log; [ $(wc -l < {env.marks}/r.log) -ge 2 ]")])
    r = d.deploy()[0]
    assert r.status == "rolled_back" and "재로드 실패" in r.message
    assert (env.web / "web1.crt").read_text() == "OLD"
    assert len((env.marks / "r.log").read_text().split()) == 2        # 롤백 후 이전 설정으로 한 번 더 재로드


def test_verify_failure_retries_then_rolls_back(env):
    sleeps = []
    (env.web / "web1.crt").write_text("OLD")
    (env.web / "web1.key").write_text("OLDK")
    calls = []

    def stuck(host, port, sni=None):
        calls.append(1)
        return 12345                       # 계속 이전(다른) 인증서를 서빙
    d = env.deployer([env.target()], verifier=stuck, sleeps=sleeps)
    r = d.deploy()[0]
    assert r.status == "rolled_back" and "새 인증서가 확인되지 않음" in r.message and "12345" not in r.message.replace(f"{12345:x}", "")
    assert sleeps == [1, 1] and len(calls) == 1 + 3          # 사전 확인 1회 + 재시도 3회
    assert (env.web / "web1.crt").read_text() == "OLD"


def test_verify_succeeds_after_delay(env):
    state = {"n": 0}
    served = file_verifier(env.web / "web1.crt")

    def slow(host, port, sni=None):
        if (env.web / "web1.crt").exists() and state["n"] < 2 and (env.marks / "web1.log").exists():
            state["n"] += 1
            raise VerifyError("아직 재시작 중")
        return served(host, port, sni)
    assert env.deployer([env.target()], verifier=slow).deploy()[0].status == "deployed"


def test_missing_directory_fails_before_touching_anything(env):
    t = env.target(files=[{"path": "/nonexistent-dir-xyz/a.crt", "content": "fullchain"}])
    r = env.deployer([t]).deploy()[0]
    assert r.status == "failed" and "대상 디렉터리" in r.message


def test_failure_stops_remaining_targets_unless_continue(env):
    bad, good = env.target("web1", check_cmd="false", order=1), env.target("web2", order=2)
    d = env.deployer([bad, good], verifier=lambda *a, **k: 0)
    res = d.deploy()
    assert [r.status for r in res] == ["rolled_back", "not_run"]
    d2 = env.deployer([bad, good], verifier=lambda *a, **k: 0)
    res2 = d2.deploy(continue_on_error=True)
    assert res2[0].status == "rolled_back" and res2[1].status != "not_run"


def test_canary_first_then_order(env):
    ts = [env.target("c", order=1), env.target("b", order=2, canary=True), env.target("a", order=3)]
    names = [t.name for t in env.deployer(ts).ordered()]
    assert names == ["b", "c", "a"]
    assert [t.name for t in env.deployer(ts).ordered(only=["a", "c"])] == ["c", "a"]


def test_pkcs12_target_needs_password_env_and_deploys(env):
    t = {"name": "tc", "type": "tomcat", "format": "pkcs12", "keystore_path": str(env.web / "keystore.p12"),
         "password_env": "TC_PASS", "alias": "tomcat", "reload_cmd": "true", "verify": {"host": "www.univ.example"}}
    d = env.deployer([t], verifier=lambda *a, **k: d.bundle.serial, environ={"TC_PASS": "changeit"})
    assert d.deploy(force=True)[0].status == "deployed"
    from cryptography.hazmat.primitives.serialization import pkcs12
    k, c, extra = pkcs12.load_key_and_certificates((env.web / "keystore.p12").read_bytes(), b"changeit")
    assert c.serial_number == d.bundle.serial and mode(env.web / "keystore.p12") == 0o600
    d2 = env.deployer([t], verifier=lambda *a, **k: 1, environ={})
    assert any("TC_PASS" in p for p in d2.validate_targets())
    r = d2.deploy()[0]
    assert r.status in ("failed", "rolled_back") and "TC_PASS" in r.message


def test_validate_targets_san_mismatch(env):
    t = env.target(verify={"host": "evil.other.org"})
    assert any("SAN" in p for p in env.deployer([t]).validate_targets())


def test_plan_has_no_key_material_and_lists_steps(env):
    d = env.deployer([env.target(), env.target("web2", canary=True)])
    text = "\n".join(d.plan())
    assert "web1" in text and "canary" in text and "fullchain" in text and "재로드" in text
    key_body = d.bundle.key_pem().decode().splitlines()[1]
    assert key_body not in text


def test_key_material_never_logged(env, caplog):
    caplog.set_level(logging.DEBUG)
    key_body = load_bundle(str(env.cert), str(env.key)).key_pem().decode().splitlines()[1]
    d = env.deployer([env.target(check_cmd="false")])
    r = d.deploy()[0]
    assert key_body not in caplog.text and key_body not in r.message
    assert key_body not in repr(d.state.data)


def test_manual_rollback_restores_from_state_backups(env):
    (env.web / "web1.crt").write_text("OLD")
    (env.web / "web1.key").write_text("OLDK")
    d = env.deployer([env.target()])
    d.deploy()
    assert (env.web / "web1.crt").read_bytes() != b"OLD"
    r = d.rollback("web1")
    assert r.status == "rolled_back" and (env.web / "web1.crt").read_text() == "OLD" and (env.web / "web1.key").read_text() == "OLDK"
    assert d.rollback("web1").status == "failed"           # 되돌릴 기록 없음
    with pytest.raises(KeyError):
        d.rollback("nope")


def test_old_backups_are_pruned(env):
    for i in range(5):
        d = env.deployer([env.target()], keep_backups=2)
        d.clock = (lambda i=i: __import__("datetime").datetime(2026, 1, 1, 0, 0, i))
        d.deploy(force=True)
    baks = sorted(p for p in os.listdir(env.web) if p.startswith("web1.crt.bak-"))
    assert len(baks) == 2


# ------------------------------------------------------------------ 실제 TLS 확인 + 잠금 + 알림
class LiveTls:
    """접속마다 PEM 파일을 다시 읽는 TLS 서버 — 파일을 교체하면 '재로드 없이' 새 인증서가 서빙된다."""

    def __init__(self, cert, key, serve_new=True):
        self.cert, self.key, self.serve_new = cert, key, serve_new
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(10)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        cached = None
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                if self.serve_new or cached is None:         # serve_new=False: 처음 읽은 인증서를 계속 사용(재로드 안 되는 서비스)
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(self.cert, self.key)
                    cached = ctx
                cached.wrap_socket(conn, server_side=True).close()
            except Exception:
                conn.close()


def test_real_tls_verification_end_to_end(env, tmp_path):
    old_cert, old_key, old_leaf, _ = make_pki(tmp_path, name="old")
    live_dir = tmp_path / "live"
    live_dir.mkdir()
    import shutil
    shutil.copy(old_cert, live_dir / "web1.crt")
    shutil.copy(old_key, live_dir / "web1.key")
    os.chmod(live_dir / "web1.key", 0o600)
    srv = LiveTls(str(live_dir / "web1.crt"), str(live_dir / "web1.key"))
    assert tls_serial("127.0.0.1", srv.port) == old_leaf.serial_number
    t = env.target(files=[{"path": str(live_dir / "web1.crt"), "content": "fullchain"},
                          {"path": str(live_dir / "web1.key"), "content": "key", "mode": "0600"}],
                   verify={"host": "127.0.0.1", "port": srv.port, "sni": "www.univ.example"})
    d = env.deployer([t], verifier=tls_serial)
    r = d.deploy()[0]
    assert r.status == "deployed" and r.serial_before == old_leaf.serial_number
    assert tls_serial("127.0.0.1", srv.port) == d.bundle.serial


def test_real_tls_stuck_service_triggers_rollback(env, tmp_path):
    old_cert, old_key, old_leaf, _ = make_pki(tmp_path, name="old")
    live = tmp_path / "live"
    live.mkdir()
    import shutil
    shutil.copy(old_cert, live / "web1.crt")
    shutil.copy(old_key, live / "web1.key")
    os.chmod(live / "web1.key", 0o600)
    srv = LiveTls(str(live / "web1.crt"), str(live / "web1.key"), serve_new=False)   # 재로드가 안 되는 서비스
    t = env.target(files=[{"path": str(live / "web1.crt"), "content": "fullchain"},
                          {"path": str(live / "web1.key"), "content": "key", "mode": "0600"}],
                   verify={"host": "127.0.0.1", "port": srv.port, "sni": "www.univ.example"})
    n = Recorder()
    d = env.deployer([t], verifier=tls_serial, notifier=n)
    r = d.deploy()[0]
    assert r.status == "rolled_back" and n.fired
    assert (live / "web1.crt").read_bytes() == old_cert.read_bytes()       # 원래 파일 복원


def test_tls_serial_error_is_classified():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(VerifyError):
        tls_serial("127.0.0.1", port, timeout=2)


def test_exclusive_lock_blocks_second_runner(tmp_path):
    with exclusive_lock(str(tmp_path / "st")):
        with pytest.raises(LockedError):
            with exclusive_lock(str(tmp_path / "st")):
                pass
    with exclusive_lock(str(tmp_path / "st")):      # 해제 후에는 다시 획득 가능
        pass


def test_state_file_permissions_and_atomic_write(tmp_path):
    s = State(str(tmp_path / "st"))
    s.set_target("a", status="ok")
    s.save()
    assert mode(tmp_path / "st" / "state.json") == 0o600
    assert State(str(tmp_path / "st")).load().target("a")["status"] == "ok"


def test_backup_prune_failure_does_not_fail_deployment(env):
    from certdeploy.transport import TransportError

    class FlakyAfterDeploy(LocalTransport):
        def run(self, cmd, stdin=None, timeout=60):
            if cmd.startswith("ls -1t"):
                raise TransportError("연결 끊김")
            return super().run(cmd, stdin, timeout)
    d = env.deployer([env.target()])
    d.transport_factory = lambda tr: FlakyAfterDeploy()
    assert d.deploy()[0].status == "deployed"
    assert d.state.target("web1")["status"] == "ok"         # 상태가 정상 저장됨


def test_corrupt_state_file_is_reported_cleanly(tmp_path):
    from click.testing import CliRunner
    import yaml
    from certdeploy.cli import main
    cert, key, *_ = make_pki(tmp_path)
    st = tmp_path / "st"
    st.mkdir()
    (st / "state.json").write_text("{not json")
    cfg = tmp_path / "c.yml"
    cfg.write_text(yaml.safe_dump({"state_dir": str(st), "certificate": {"cert_file": str(cert), "key_file": str(key)},
                                   "targets": [{"name": "a", "type": "generic", "reload_cmd": "none",
                                                "files": [{"path": str(tmp_path / "x.crt"), "content": "cert"}]}]}))
    r = CliRunner().invoke(main, ["-c", str(cfg), "plan"])
    assert r.exit_code == 1 and "상태 파일을 읽을 수 없습니다" in r.output and "Traceback" not in r.output


# ------------------------------------------------------------------ 엄격 TLS 검증 / 헬스체크 / 훅 / 소크 / password_file
import http.server  # noqa: E402


def live_dir_with(tmp_path, name="old", **pki):
    import shutil
    cert, key, leaf, _ = make_pki(tmp_path, name=name, **pki)
    live = tmp_path / "live"
    live.mkdir(exist_ok=True)
    shutil.copy(cert, live / "web1.crt")
    shutil.copy(key, live / "web1.key")
    os.chmod(live / "web1.key", 0o600)
    return live, tmp_path / f"{name}.root.pem", leaf


def live_target(env, live, port, **verify):
    return env.target(files=[{"path": str(live / "web1.crt"), "content": "fullchain"},
                             {"path": str(live / "web1.key"), "content": "key", "mode": "0600"}],
                      verify={"host": "127.0.0.1", "port": port, "sni": "www.univ.example", **verify})


def test_strict_tls_accepts_full_chain(env, tmp_path):
    ca = {}
    live, root, old_leaf = live_dir_with(tmp_path, shared_ca=ca)
    env.cert, env.key, *_ = make_pki(tmp_path / "issued_dir", name="renewed", shared_ca=ca)     # 같은 CA 에서 갱신 발급
    srv = LiveTls(str(live / "web1.crt"), str(live / "web1.key"))
    assert tls_serial("127.0.0.1", srv.port, "www.univ.example", strict=True, cafile=str(root)) == old_leaf.serial_number
    d = env.deployer([live_target(env, live, srv.port, strict=True, ca_file=str(root))], verifier=tls_serial)
    assert d.deploy()[0].status == "deployed"


def test_strict_tls_detects_missing_intermediate_and_rolls_back(env, tmp_path):
    """중간 CA 가 빠진 인증서를 배포하면 일련번호는 맞아도 체인 검증에서 걸러져 롤백된다."""
    ca = {}
    live, root, _ = live_dir_with(tmp_path, shared_ca=ca)
    # 배포할 새 인증서는 같은 CA 가 발급했지만 체인(중간 CA) 없이 배포되는 상황
    env.cert, env.key, *_ = make_pki(tmp_path / "issued_dir", name="nochain", chain=False, shared_ca=ca)
    srv = LiveTls(str(live / "web1.crt"), str(live / "web1.key"))
    n = Recorder()
    d = env.deployer([live_target(env, live, srv.port, strict=True, ca_file=str(root))], verifier=tls_serial, notifier=n)
    r = d.deploy()[0]
    assert r.status == "rolled_back" and "인증서 검증 실패" in r.message and "issuer" in r.message.lower()
    assert n.fired


def test_strict_tls_hostname_mismatch(tmp_path):
    live, root, _ = live_dir_with(tmp_path)
    srv = LiveTls(str(live / "web1.crt"), str(live / "web1.key"))
    with pytest.raises(VerifyError, match="인증서 검증 실패"):
        tls_serial("127.0.0.1", srv.port, "evil.other.org", strict=True, cafile=str(root))


class Http(http.server.BaseHTTPRequestHandler):
    code = 200

    def do_GET(self):
        self.send_response(Http.code)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def http_srv():
    srv = http.server.HTTPServer(("127.0.0.1", 0), Http)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    Http.code = 200
    yield f"http://127.0.0.1:{srv.server_port}/health"
    srv.shutdown()


def test_http_health_check_gates_deployment(env, http_srv):
    from certdeploy.verify import http_health
    http_health(http_srv)
    Http.code = 503
    with pytest.raises(VerifyError, match="503"):
        http_health(http_srv)
    t = env.target(health={"url": http_srv, "expect": 200})
    d = env.deployer([t])
    d.health_checker = http_health
    d.verifier = lambda *a, **k: d.bundle.serial
    (env.web / "web1.crt").write_text("OLD")
    (env.web / "web1.key").write_text("OLDK")
    r = d.deploy(force=True)[0]
    assert r.status == "rolled_back" and "헬스체크 실패" in r.message and "503" in r.message
    assert (env.web / "web1.crt").read_text() == "OLD"
    Http.code = 200
    assert d.deploy(force=True)[0].status == "deployed"
    with pytest.raises(VerifyError, match="접속 실패"):
        http_health("http://127.0.0.1:9/x", timeout=1)


def test_pre_cmd_failure_changes_nothing_and_post_cmd_gets_status(env):
    calls = []

    def hooks(cmd, e, timeout):
        calls.append((cmd, e["CERTDEPLOY_STATUS"], e["CERTDEPLOY_TARGET"]))
        return (1, "lb api down") if cmd == "drain" else (0, "")
    d = env.deployer([env.target(pre_cmd="drain", post_cmd="undrain")])
    d.hook_runner = hooks
    r = d.deploy()[0]
    assert r.status == "failed" and "pre_cmd 실패" in r.message and "lb api down" in r.message
    assert os.listdir(env.web) == [] and calls == [("drain", "pre", "web1")]      # 서버를 건드리지 않음
    d2 = env.deployer([env.target(pre_cmd="ok-pre", post_cmd="undrain")])
    d2.hook_runner = hooks
    assert d2.deploy()[0].status == "deployed"
    assert ("undrain", "deployed", "web1") in calls


def test_post_cmd_runs_after_rollback_and_its_failure_is_only_a_warning(env):
    seen = []
    d = env.deployer([env.target(check_cmd="false", post_cmd="undrain")])
    d.hook_runner = lambda cmd, e, t: (seen.append(e["CERTDEPLOY_STATUS"]) or (2, "boom"))
    r = d.deploy()[0]
    assert r.status == "rolled_back" and "post_cmd 실패" in r.message and seen == ["rolled_back"]
    d2 = env.deployer([env.target(post_cmd="x")])
    d2.hook_runner = lambda cmd, e, t: (1, "fail")
    r2 = d2.deploy()[0]
    assert r2.status == "deployed" and "post_cmd 실패" in r2.message           # 배포 성공은 유지


def test_soak_keeps_verifying_and_rolls_back_if_serial_changes(env):
    sleeps = []
    state = {"n": 0}
    d = env.deployer([env.target(soak_seconds=30, soak_interval=10)], sleeps=sleeps)
    served = file_verifier(env.web / "web1.crt")

    def flaky(host, port, sni=None, **kw):
        if (env.marks / "web1.log").exists() and (env.web / "web1.crt").exists():
            state["n"] += 1
            if state["n"] >= 4:                   # 소크 도중 다른 인증서로 바뀜(예: 롤백된 다른 노드)
                return 999
        return served(host, port, sni)
    d.verifier = flaky
    (env.web / "web1.crt").write_text("OLD")
    (env.web / "web1.key").write_text("OLDK")
    r = d.deploy()[0]
    assert r.status == "rolled_back" and "소크" in r.message and sleeps[:2] == [10, 10]
    ok = env.deployer([env.target(soak_seconds=30, soak_interval=10)], sleeps=(s2 := []))
    ok.verifier = served
    assert ok.deploy(force=True)[0].status == "deployed" and s2 == [10, 10, 10]


def test_keystore_password_file_permissions(env, tmp_path):
    t = {"name": "tc", "type": "tomcat", "format": "pkcs12", "keystore_path": str(env.web / "ks.p12"),
         "password_file": str(tmp_path / "pw"), "reload_cmd": "true"}
    pw = tmp_path / "pw"
    pw.write_text("changeit\n")
    os.chmod(pw, 0o644)
    d = env.deployer([t], verifier=lambda *a, **k: 0)
    assert any("권한이 너무 넓습니다" in p for p in d.validate_targets())
    r = d.deploy()[0]
    assert r.status in ("failed", "rolled_back") and "권한" in r.message
    os.chmod(pw, 0o600)
    assert d.validate_targets() == []
    assert d.deploy(force=True)[0].status == "deployed"
    from cryptography.hazmat.primitives.serialization import pkcs12
    assert pkcs12.load_key_and_certificates((env.web / "ks.p12").read_bytes(), b"changeit")[1].serial_number == d.bundle.serial
    pw.unlink()
    assert any("비밀번호" in p for p in d.validate_targets())
