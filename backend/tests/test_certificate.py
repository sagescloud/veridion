
import ssl
from types import SimpleNamespace

import pytest

from app.modules import certificate


@pytest.fixture
def context():
    return SimpleNamespace(
        url=SimpleNamespace(
            scheme="https",
            hostname="example.com",
            port=None,
        ),
        resolved_ips=["93.184.216.34"],
        settings=SimpleNamespace(http_timeout_s=5),
    )


@pytest.fixture
def valid_certificate():
    return {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Example CA"),),),
        "not_before": "Jan  1 00:00:00 2025 GMT",
        "not_after": "Dec 31 23:59:59 2035 GMT",
        "subject_alt_names": (("DNS", "example.com"),),
        "tls_version": "TLSv1.3",
        "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
    }


@pytest.mark.anyio
async def test_valid_certificate(context, valid_certificate, monkeypatch):
    monkeypatch.setattr(
        certificate,
        "_inspect_certificate",
        lambda *args: valid_certificate,
    )

    result = await certificate.CertificateModule().run(context)

    assert result.status == "completed"
    assert result.risk_score == 0
    assert result.findings == []
    assert result.details["verification"] == "passed"
    assert result.details["issuer"] != "Not available"


@pytest.mark.anyio
async def test_certificate_expiring_soon(
    context,
    valid_certificate,
    monkeypatch,
):
    valid_certificate["not_after"] = "Dec 1 00:00:00 2026 GMT"

    monkeypatch.setattr(
        certificate,
        "_inspect_certificate",
        lambda *args: valid_certificate,
    )

    result = await certificate.CertificateModule().run(context)

    assert result.status == "completed"
    assert result.risk_score > 0
    assert any(
        finding.code == "CERTIFICATE_EXPIRING_SOON"
        for finding in result.findings
    )


@pytest.mark.anyio
async def test_invalid_certificate(context, monkeypatch):
    def failed_inspection(*args):
        raise ssl.SSLCertVerificationError("hostname mismatch")

    monkeypatch.setattr(
        certificate,
        "_inspect_certificate",
        failed_inspection,
    )

    result = await certificate.CertificateModule().run(context)

    assert result.status == "completed"
    assert result.risk_score == 45
    assert result.findings[0].code == "TLS_CERTIFICATE_INVALID"


@pytest.mark.anyio
async def test_http_url_unavailable(context):
    context.url.scheme = "http"

    result = await certificate.CertificateModule().run(context)

    assert result.status == "unavailable"
    assert result.risk_score is None
    assert result.status_reason is not None


@pytest.mark.anyio
async def test_no_validated_ips(context):
    context.resolved_ips = []

    result = await certificate.CertificateModule().run(context)

    assert result.status == "unavailable"
    assert result.risk_score is None
    assert result.status_reason is not None


@pytest.mark.anyio
async def test_connection_failure(context, monkeypatch):
    def failed_inspection(*args):
        raise TimeoutError("connection timed out")

    monkeypatch.setattr(
        certificate,
        "_inspect_certificate",
        failed_inspection,
    )

    result = await certificate.CertificateModule().run(context)

    assert result.status == "failed"
    assert result.risk_score is None
    assert result.status_reason is not None
