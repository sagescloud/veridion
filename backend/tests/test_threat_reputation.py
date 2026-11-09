from types import SimpleNamespace

import pytest

from app.modules.threat_reputation import ThreatReputationModule


def make_context(url):
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
    )


@pytest.mark.anyio
async def test_normal_url_returns_partial_result():
    result = await ThreatReputationModule().run(
        make_context("https://example.com")
    )

    assert result.id == "threat_reputation"
    assert result.status == "partial"
    assert result.risk_score is None
    assert result.status_reason.code == "EXTERNAL_INTELLIGENCE_NOT_CONNECTED"


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
async def test_external_intelligence_is_never_claimed_complete():
    result = await ThreatReputationModule().run(
        make_context("https://example.com")
    )

    assert result.status == "partial"
    assert result.details["external_providers"]["urlhaus"] == "not_connected"
    assert result.details["external_providers"]["phishtank"] == "not_connected"


@pytest.mark.anyio
async def test_heuristics_do_not_claim_confirmed_phishing():
    result = await ThreatReputationModule().run(
        make_context("https://login.example.com")
    )

    assert not any(f.code == "CONFIRMED_PHISHING" for f in result.findings)
