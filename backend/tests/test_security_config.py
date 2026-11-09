from types import SimpleNamespace

import pytest

from app.modules import security_config


@pytest.fixture
def context():
    return SimpleNamespace(
        url=SimpleNamespace(normalized="https://example.com"),
        settings=SimpleNamespace(),
        http=SimpleNamespace(),
    )


@pytest.mark.anyio
async def test_missing_security_headers(context, monkeypatch):
    async def fake_fetch(*args, **kwargs):
        return SimpleNamespace(
            final_url="https://example.com",
            status_code=200,
            headers={},
        )

    monkeypatch.setattr(security_config, "safe_fetch", fake_fetch)

    result = await security_config.SecurityConfigModule().run(context)

    assert result.status == "completed"
    assert result.risk_score == 53
    assert len(result.findings) == 6


@pytest.mark.anyio
async def test_secure_headers(context, monkeypatch):
    async def fake_fetch(*args, **kwargs):
        return SimpleNamespace(
            final_url="https://example.com",
            status_code=200,
            headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "geolocation=()",
            },
        )

    monkeypatch.setattr(security_config, "safe_fetch", fake_fetch)

    result = await security_config.SecurityConfigModule().run(context)

    assert result.status == "completed"
    assert result.risk_score == 0
    assert result.findings == []


@pytest.mark.anyio
async def test_http_url_flagged(context, monkeypatch):
    async def fake_fetch(*args, **kwargs):
        return SimpleNamespace(
            final_url="http://example.com",
            status_code=200,
            headers={},
        )

    monkeypatch.setattr(security_config, "safe_fetch", fake_fetch)

    result = await security_config.SecurityConfigModule().run(context)

    assert result.status == "completed"
    assert any(
        finding.code == "HTTPS_NOT_ENFORCED"
        for finding in result.findings
    )


@pytest.mark.anyio
async def test_fetch_failure_returns_failed(context, monkeypatch):
    async def fake_fetch(*args, **kwargs):
        raise RuntimeError("simulated fetch failure")

    monkeypatch.setattr(security_config, "safe_fetch", fake_fetch)

    result = await security_config.SecurityConfigModule().run(context)

    assert result.status == "failed"
    assert result.risk_score is None
    assert result.status_reason is not None