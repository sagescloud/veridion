"""Threat reputation analysis using local heuristics and URLhaus."""
from __future__ import annotations

import ipaddress
import json
import logging
from urllib.parse import urlsplit

from app.models.scan import Evidence, Finding, ModuleResult, StatusReason
from app.modules.base import ScanContext
from app.utils.ssrf_guard import safe_post

log = logging.getLogger("veridion.threat_reputation")

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"

SUSPICIOUS_TERMS = {
    "login", "verify", "wallet", "password",
    "account", "signin", "banking", "credential",
}


def _finding(
    code: str,
    severity: str,
    title: str,
    description: str,
    evidence: list[Evidence],
    finding_type: str = "suspicious_indicator",
) -> Finding:
    return Finding(
        id=code.lower(),
        code=code,
        type=finding_type,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
    )


class ThreatReputationModule:
    id = "threat_reputation"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        parsed = ctx.url
        hostname = parsed.hostname.lower().rstrip(".")
        normalized = parsed.normalized
        parts = urlsplit(normalized)

        findings: list[Finding] = []

        # Local heuristics: indicators only, never numerical reputation scores.

        if parsed.has_userinfo:
            findings.append(_finding(
                "URL_EMBEDDED_CREDENTIALS", "high",
                "Credentials embedded in URL",
                "The URL contains user-information credentials before the hostname.",
                [Evidence(label="Hostname", value=hostname)],
            ))

        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            findings.append(_finding(
                "IP_ADDRESS_HOST", "medium",
                "Website uses an IP address",
                "The destination uses an IP address instead of a conventional domain. "
                "This alone does not establish malicious activity.",
                [Evidence(label="IP address", value=hostname)],
            ))

        if "xn--" in hostname:
            findings.append(_finding(
                "PUNYCODE_HOSTNAME", "medium",
                "Internationalized hostname detected",
                "The hostname contains punycode labels. Inspect it for possible "
                "character impersonation.",
                [Evidence(label="Hostname", value=hostname)],
            ))

        labels = hostname.split(".")

        if len(labels) >= 5:
            findings.append(_finding(
                "EXCESSIVE_SUBDOMAINS", "low",
                "Unusually complex hostname",
                "The hostname contains many subdomain labels.",
                [Evidence(label="Subdomain count", value=str(len(labels) - 2))],
            ))

        if len(hostname) > 55:
            findings.append(_finding(
                "LONG_HOSTNAME", "low",
                "Unusually long hostname",
                "The hostname is unusually long and may be harder to inspect.",
                [Evidence(label="Hostname length", value=str(len(hostname)))],
            ))

        matched_terms = sorted(term for term in SUSPICIOUS_TERMS if term in labels)

        if matched_terms:
            findings.append(_finding(
                "SENSITIVE_HOSTNAME_TERMS", "low",
                "Sensitive-action terms in hostname",
                "The hostname contains terms associated with account access "
                "or credential collection. Context is required.",
                [Evidence(label="Matched terms", value=", ".join(matched_terms))],
            ))

        matched_paths = sorted(
            term for term in SUSPICIOUS_TERMS
            if term in parts.path.lower().split("/")
        )

        if matched_paths:
            findings.append(_finding(
                "SENSITIVE_PATH_TERMS", "low",
                "Sensitive-action terms in URL path",
                "The URL path contains terms associated with account access. "
                "This alone does not establish malicious intent.",
                [Evidence(label="Matched terms", value=", ".join(matched_paths))],
            ))

        # Live URLhaus lookup.
        settings = getattr(ctx, "settings", None)
        client = getattr(ctx, "http", None)
        auth_key = getattr(settings, "urlhaus_auth_key", None)

        urlhaus_state = "not_configured"
        urlhaus_score: int | None = None
        failure_reason = None

        if auth_key and client:
            try:
                response = await safe_post(
                    client,
                    URLHAUS_API,
                    settings,
                    data={"url": normalized},
                    headers={"Auth-Key": auth_key},
                )

                if response.status_code != 200 or response.truncated:
                    raise ValueError(
                        f"URLhaus returned HTTP {response.status_code} "
                        "or a truncated response"
                    )

                payload = json.loads(response.body)

                if payload.get("query_status") == "no_results":
                    urlhaus_state = "queried_no_match"
                    urlhaus_score = 0

                elif payload.get("query_status") == "ok":
                    urlhaus_state = "matched"
                    urlhaus_score = 90

                    findings.append(_finding(
                        "URLHAUS_MALICIOUS_URL",
                        "critical",
                        "URL listed in URLhaus threat database",
                        "URLhaus reports this URL as a malicious distribution "
                        "or attack destination. Avoid interacting with it.",
                        [
                            Evidence(label="Threat type", value=str(
                                payload.get("threat", "Unknown")
                            )),
                            Evidence(label="URLhaus status", value=str(
                                payload.get("url_status", "Unknown")
                            )),
                            Evidence(label="URLhaus reference", value=str(
                                payload.get("urlhaus_reference", "Not provided")
                            )),
                        ],
                        finding_type="malicious_indicator",
                    ))

                else:
                    raise ValueError(
                        "URLhaus returned an unrecognized query status"
                    )

            except Exception:
                log.exception("URLhaus lookup failed")
                urlhaus_state = "error"
                failure_reason = "URLHAUS_QUERY_FAILED"

        # PhishTank is optional; registration is currently unavailable.
        phishtank_state = "not_configured"

        if urlhaus_state == "queried_no_match":
            reason_code = "PHISHTANK_NOT_CONFIGURED"
            reason_message = (
                "URLhaus returned no match. PhishTank has not been configured, "
                "so the reputation assessment remains incomplete."
            )
        elif urlhaus_state == "matched":
            reason_code = "PHISHTANK_NOT_CONFIGURED"
            reason_message = (
                "URLhaus reported a malicious URL. PhishTank has not been "
                "configured, so additional provider coverage is unavailable."
            )
        elif failure_reason:
            reason_code = failure_reason
            reason_message = (
                "The URLhaus lookup could not be completed. No clean reputation "
                "verdict can be made."
            )
        else:
            reason_code = "EXTERNAL_INTELLIGENCE_NOT_CONNECTED"
            reason_message = (
                "URLhaus credentials or the guarded HTTP client are unavailable. "
                "External reputation checks have not been completed."
            )

        return ModuleResult(
            id=self.id,
            status="partial",
            risk_score=urlhaus_score,
            status_reason=StatusReason(
                code=reason_code,
                message=reason_message,
            ),
            findings=findings,
            details={
                "local_heuristics": "completed",
                "external_providers": {
                    "urlhaus": urlhaus_state,
                    "phishtank": phishtank_state,
                },
                "heuristic_findings": len([
                    f for f in findings
                    if f.code != "URLHAUS_MALICIOUS_URL"
                ]),
            },
        )
