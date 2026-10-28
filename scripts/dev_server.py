#!/usr/bin/env python
"""데모/개발 서버: 가상 원격 파일시스템(샌드박스)에 상태별 샘플 인증서를 심고 API+UI 를 띄운다.
SSH 서버 없이 화면과 API 를 확인할 수 있다.   사용: python scripts/dev_server.py [포트]
계정: admin / Demo!Passw0rd-1234 (로컬 개발 전용)"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))

from certpilot_api.app import create_app  # noqa: E402
from certpilot_core.remote import FailureCause, RemoteError, SandboxExecutor  # noqa: E402
from conftest import make_cert, pem  # noqa: E402


def main(port: int = 8080):
    root = tempfile.mkdtemp(prefix="certpilot-demo-")
    samples = {"ok": (-1, 200), "warn": (-60, 10), "expired": (-100, -2)}
    for name, (a, b) in samples.items():
        path = os.path.join(root, "etc/nginx/ssl", f"{name}.crt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "wb").write(pem(make_cert(f"{name}.demo.test", a, b, [f"{name}.demo.test"])[1]))

    def factory(target):
        if target.name == "down-host":
            raise RemoteError(FailureCause.TIMEOUT, "demo")
        if target.name == "empty-host":
            return SandboxExecutor(tempfile.mkdtemp())
        return SandboxExecutor(root)

    app = create_app({"DATA_DIR": tempfile.mkdtemp(prefix="certpilot-data-"),
                      "ADMIN_USER": "admin", "ADMIN_PASSWORD": "Demo!Passw0rd-1234",
                      "SECURE_COOKIE": False}, executor_factory=factory, sleep=lambda s: None)
    svc = app.extensions["certpilot"]["service"]
    for n, g in (("web-prod-1", "prod"), ("empty-host", "prod"), ("down-host", "stage")):
        svc.add_server({"name": n, "hostname": f"{n}.example", "account": "certscan", "group": g}, "demo")
    svc.scan_all("demo")
    app.run(host="127.0.0.1", port=port)


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 8080)
