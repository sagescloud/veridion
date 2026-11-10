from types import SimpleNamespace

import pytest

import app.modules.threat_reputation as threat_module
from app.modules.threat_reputation import ThreatReputationModule


def make_context(url, *, key=None, http=None):
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    hostname = parsed.hostname or ""

    return SimpleNamespace(
        url=SimpleNamespace(
            hostname=hostname,
            normalized=url,
            has_userinfo=parsed.username is not None or parsed.password is not None,
            is_ip_literal=False,
        ),
        settings=SimpleNamespace(
            urlhaus_auth_key=key,
            http_total_timeout_s=15,
            max_response_bytes=1_000_000,
        ),
        http=http,
    )


def fake_response(payload, status_code=200):
    import json

    return SimpleNamespace(
        status_code=status_code,
        body=json.dumps(payload).encode(),
        truncated=False,
    )


@pytest.mark.anyio
async def test_normal_url_without_provider_client_is_partial():
    result = await ThreatReputationModule().run(
        make_context("https://example.com")
    )

    assert result.id == "threat_reputation"
    assert result.status == "partial"
    assert result.risk_score is None
    assert result.details["external_providers"]["urlhaus"] == "not_configured"


@pytest.mark.anyio
async def test_ip_address_is_flagged():
    result = await ThreatReputationModule().run(
        make_context("http://192.0.2.10")
    )

    assert any(f.code == "IP_ADDRESS_HOST" for f in result.findings)
    assert result.risk_score is None


@pytest.mark.anyio
async def test_punycode_hostname_is_flagged():
    result = await ThreatReputationModule().run(
        make_context("https://xn--e1afmkfd.example")
    )

    assert any(f.code == "PUNYCODE_HOSTNAME" for f in result.findings)


@pytest.mark.anyio
async def test_sensitive_hostname_terms_are_flagged():
    result = await ThreatReputationModule().run(
        make_context("https://login.example.com")
    )

    assert any(f.code == "SENSITIVE_HOSTNAME_TERMS" for f in result.findings)


@pytest.mark.anyio
async def test_embedded_credentials_are_flagged():
    result = await ThreatReputationModule().run(
        make_context("https://user:password@example.com")
    )

    assert any(f.code == "URL_EMBEDDED_CREDENTIALS" for f in result.findings)
    assert result.risk_score is None


@pytest.mark.anyio
async def test_heuristics_do_not_claim_confirmed_phishing():
    result = await ThreatReputationModule().run(
        make_context("https://login.example.com")
    )

    assert not any(f.code == "CONFIRMED_PHISHING" for f in result.findings)


@pytest.mark.anyio
async def test_urlhaus_match_creates_malicious_finding(monkeypatch):
    async def fake_safe_post(*args, **kwargs):
        assert kwargs["data"]["url"] == "https://malicious.example"
        assert kwargs["headers"]["Auth-Key"] == "test-key"
        return fake_response({
            "query_status": "ok",
            "threat": "malware_download",
            "url_status": "online",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
        })

    monkeypatch.setattr(threat_module, "safe_post", fake_safe_post)

    result = await ThreatReputationModule().run(
        make_context(
            "https://malicious.example",
            key="test-key",
            http=object(),
        )
    )

    assert result.status == "partial"
    assert result.risk_score == 90
    assert result.details["external_providers"]["urlhaus"] == "matched"
    assert any(
        f.code == "URLHAUS_MALICIOUS_URL"
        and f.type == "malicious_indicator"
        for f in result.findings
    )


@pytest.mark.anyio
async def test_urlhaus_no_results_returns_zero_score(monkeypatch):
    async def fake_safe_post(*args, **kwargs):
        return fake_response({"query_status": "no_results"})

    monkeypatch.setattr(threat_module, "safe_post", fake_safe_post)

    result = await ThreatReputationModule().run(
        make_context(
            "https://clean.example",
            key="test-key",
            http=object(),
        )
    )

    assert result.status == "partial"
    assert result.risk_score == 0
    assert result.details["external_providers"]["urlhaus"] == "queried_no_match"
    assert not any(
        f.code == "URLHAUS_MALICIOUS_URL"
        for f in result.findings
    )


@pytest.mark.anyio
async def test_urlhaus_failure_does_not_claim_clean_result(monkeypatch):
    async def fake_safe_post(*args, **kwargs):
        raise TimeoutError("provider timed out")

    monkeypatch.setattr(threat_module, "safe_post", fake_safe_post)

    result = await ThreatReputationModule().run(
        make_context(
            "https://example.com",
            key="test-key",
            http=object(),
        )
    )

    assert result.status == "partial"
    assert result.risk_score is None
    assert result.details["external_providers"]["urlhaus"] == "error"
    assert result.status_reason.code == "URLHAUS_QUERY_FAILED"
