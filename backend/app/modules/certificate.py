"""TLS certificate analysis using SSRF-validated IP addresses."""

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from app.models.scan import Evidence, Finding, ModuleResult
from app.modules.base import ScanContext, not_run


def _inspect_certificate(
    hostname: str,
    ip_address: str,
    port: int,
    timeout: float,
) -> dict:
    """Inspect TLS by connecting to a validated IP while preserving SNI."""

    context = ssl.create_default_context()

    with socket.create_connection((ip_address, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as tls:
            cert = tls.getpeercert()

            return {
                "subject": cert.get("subject", ()),
                "issuer": cert.get("issuer", ()),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "subject_alt_names": cert.get("subjectAltName", ()),
                "tls_version": tls.version(),
                "cipher": tls.cipher(),
            }


def _format_name(name: tuple) -> str:
    parts = [
        f"{key}={value}"
        for group in name
        for key, value in group
    ]
    return ", ".join(parts) or "Not available"


class CertificateModule:
    id = "certificate"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        if ctx.url.scheme.lower() != "https":
            return not_run(
                self.id,
                "unavailable",
                "HTTPS_NOT_AVAILABLE",
                "TLS certificate analysis requires an HTTPS URL.",
            )

        if not ctx.resolved_ips:
            return not_run(
                self.id,
                "unavailable",
                "NO_VALIDATED_IPS",
                "No validated public IP address was available.",
            )

        hostname = ctx.url.hostname
        port = ctx.url.port or 443
        timeout = float(ctx.settings.http_timeout_s)

        certificate = None
        verification_error = None

        # Only connect to IPs already validated by the SSRF pre-flight.
        for ip_address in ctx.resolved_ips:
            try:
                certificate = await asyncio.to_thread(
                    _inspect_certificate,
                    hostname,
                    ip_address,
                    port,
                    timeout,
                )
                break
            except ssl.SSLCertVerificationError as exc:
                verification_error = str(exc)
                break
            except (OSError, ssl.SSLError, TimeoutError):
                continue

        if verification_error is not None:
            finding = Finding(
                id="tls_certificate_invalid",
                code="TLS_CERTIFICATE_INVALID",
                type="misconfiguration",
                severity="high",
                title="TLS certificate verification failed",
                description=(
                    "The certificate could not be verified against trusted "
                    "certificate authorities and the requested hostname."
                ),
                evidence=[
                    Evidence(
                        label="Verification error",
                        value=verification_error[:500],
                    )
                ],
            )

            return ModuleResult(
                id=self.id,
                status="completed",
                risk_score=45,
                status_reason=None,
                findings=[finding],
                details={
                    "hostname": hostname,
                    "port": port,
                    "verification": "failed",
                    "assessment_scope": "TLS trust and hostname verification",
                },
            )

        if certificate is None:
            return not_run(
                self.id,
                "failed",
                "CERTIFICATE_CONNECTION_FAILED",
                "Could not retrieve a TLS certificate from the validated destination.",
            )

        findings = []
        score = 0
        not_after = certificate.get("not_after")
        days_remaining = None

        if not_after:
            try:
                expiry_timestamp = ssl.cert_time_to_seconds(not_after)
                expiry_date = datetime.fromtimestamp(
                    expiry_timestamp,
                    tz=timezone.utc,
                )
                days_remaining = (
                    expiry_date - datetime.now(timezone.utc)
                ).days

                if days_remaining <= 30:
                    points = 15 if days_remaining > 0 else 35

                    findings.append(
                        Finding(
                            id="certificate_expiring_soon",
                            code="CERTIFICATE_EXPIRING_SOON",
                            type="misconfiguration",
                            severity="medium" if days_remaining > 0 else "high",
                            title="TLS certificate is expiring soon",
                            description=(
                                "The certificate expires within 30 days. "
                                "Renewal is recommended."
                            ),
                            evidence=[
                                Evidence(
                                    label="Certificate expiry",
                                    value=not_after,
                                ),
                                Evidence(
                                    label="Days remaining",
                                    value=str(days_remaining),
                                ),
                            ],
                        )
                    )
                    score += points

            except (ValueError, OverflowError, OSError):
                days_remaining = None

        return ModuleResult(
            id=self.id,
            status="completed",
            risk_score=min(score, 100),
            status_reason=None,
            findings=findings,
            details={
                "hostname": hostname,
                "port": port,
                "verification": "passed",
                "subject": _format_name(certificate.get("subject", ())),
                "issuer": _format_name(certificate.get("issuer", ())),
                "not_before": certificate.get("not_before"),
                "not_after": not_after,
                "days_remaining": days_remaining,
                "subject_alt_names": [
                    list(item)
                    for item in certificate.get("subject_alt_names", ())
                ],
                "tls_version": certificate.get("tls_version"),
                "cipher": certificate.get("cipher"),
                "assessment_scope": (
                    "TLS trust, hostname verification, expiry and connection details"
                ),
            },
        )
