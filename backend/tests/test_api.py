"""End-to-end API tests. No real network or Supabase needed."""
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.utils import ssrf_guard


@pytest.fixture
def client(monkeypatch):
    async def fake_resolve(host, port, *, timeout=3.0):
        import ipaddress
        try:
            ip = ipaddress.ip_address(host)
            if not ssrf_guard.is_public_ip(ip):
                raise ssrf_guard.SSRFBlocked("x")
        except ValueError:
            pass
        return ["93.184.216.34"]
    monkeypatch.setattr(ssrf_guard, "resolve_public_addresses", fake_resolve)
    with TestClient(create_app(Settings(app_env="development"))) as c:
        yield c


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_invalid_url_uses_error_envelope(client):
    r = client.post("/api/scan", json={"url": "not a url"})
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "INVALID_URL" and err["request_id"].startswith("req_") and "detail" not in r.json()


def test_unsupported_scheme(client):
    assert client.post("/api/scan", json={"url": "ftp://example.com"}).json()["error"]["code"] == "UNSUPPORTED_SCHEME"


def test_missing_body_field_is_invalid_url(client):
    assert client.post("/api/scan", json={}).json()["error"]["code"] == "INVALID_URL"


def test_blocked_destination_leaks_nothing(client):
    r = client.post("/api/scan", json={"url": "http://127.0.0.1/admin"})
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "BLOCKED_DESTINATION" and "127" not in err["message"]


def test_scan_with_stub_modules_is_inconclusive_not_safe(client):
    r = client.post("/api/scan", json={"url": "https://example.com/login"})
    assert r.status_code == 200
    body = r.json()
    assert body["schema_version"] == "0.1-proposal" and body["status"] == "completed"
    assert body["overall"]["classification"] == "inconclusive" and body["overall"]["risk_score"] is None
    assert len(body["modules"]) == 5 and all(m["risk_score"] is None for m in body["modules"])
    # retrievable afterwards
    again = client.get(f"/api/scan/{body['scan_id']}")
    assert again.status_code == 200 and again.json()["scan_id"] == body["scan_id"]


def test_unknown_scan_id_404(client):
    assert client.get("/api/scan/b7e1c2a4-5d3f-4a8e-9c1b-2f6d8e0a1b34").json()["error"]["code"] == "SCAN_NOT_FOUND"
    assert client.get("/api/scan/not-a-uuid").json()["error"]["code"] == "SCAN_NOT_FOUND"


def test_reports_unavailable_without_supabase(client):
    assert client.post("/api/report", json={"url": "https://bad.example/"}).status_code == 503
    assert client.get("/api/reports").status_code == 503


def test_rate_limit(client):
    codes = [client.post("/api/scan", json={"url": "ftp://x"}).status_code for _ in range(12)]
    assert 429 in codes
