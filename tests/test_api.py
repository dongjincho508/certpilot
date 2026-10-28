import pytest


@pytest.fixture
def client(monkeypatch, tmp_path):
    import certpilot_core.audit_storage as a
    orig = a.AuditLogWriter.__init__
    monkeypatch.setattr(a.AuditLogWriter, "__init__",
                        lambda self, p, log_type="audit": orig(self, str(tmp_path), log_type))
    from certpilot_api.app import app
    return app.test_client()


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json["status"] == "ok"


def test_index_served(client):
    assert client.get("/").status_code == 200


@pytest.mark.parametrize("path", ["/static/css/style.css", "/static/js/app.js"])
def test_static_assets(client, path):
    assert client.get(path).status_code == 200


def test_server_register_requires_fields(client):
    assert client.post("/servers", json={"hostname": "a"}).status_code == 400


def test_server_register_and_list(client):
    r = client.post("/servers", json={"hostname": "h1", "username": "u"})
    assert r.status_code == 201
    assert any(s["hostname"] == "h1" for s in client.get("/servers").json["servers"])
