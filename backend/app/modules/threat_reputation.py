"""Threat reputation analysis using conservative local URL heuristics.

External threat-intelligence providers will be integrated separately.
Local heuristics are partial evidence, never a clean reputation verdict.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from app.models.scan import Evidence, Finding, ModuleResult, StatusReason
from app.modules.base import ScanContext


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
) -> Finding:
    return Finding(
        id=code.lower(),
        code=code,
        type="suspicious_indicator",
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
        scores: list[int] = []

        # 1. Embedded credentials in URLs.
        if parsed.has_userinfo:
            findings.append(_finding(
                "URL_EMBEDDED_CREDENTIALS",
                "high",
                "Credentials embedded in URL",
                "The URL contains user-information credentials before the hostname.",
                [Evidence(label="Hostname", value=hostname)],
            ))
            scores.append(65)

        # 2. IP address used instead of a domain.
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            findings.append(_finding(
                "IP_ADDRESS_HOST",
                "medium",
                "Website uses an IP address",
                "The destination uses an IP address instead of a conventional domain name. "
                "This is not proof of malicious activity.",
                [Evidence(label="IP address", value=hostname)],
            ))
            scores.append(35)

        # 3. Internationalized/punycode hostname.
        if "xn--" in hostname:
            findings.append(_finding(
                "PUNYCODE_HOSTNAME",
                "medium",
                "Internationalized hostname detected",
                "The hostname contains punycode labels. Inspect the displayed domain "
                "carefully for possible character impersonation.",
                [Evidence(label="Hostname", value=hostname)],
            ))
            scores.append(35)

        # 4. Unusually complex hostname.
        labels = hostname.split(".")

        if len(labels) >= 5:
            findings.append(_finding(
                "EXCESSIVE_SUBDOMAINS",
                "low",
                "Unusually complex hostname",
                "The hostname contains many subdomain labels. This can make "
                "the actual registered domain harder to recognize.",
                [Evidence(label="Subdomain count", value=str(len(labels) - 2))],
            ))
            scores.append(15)

        if len(hostname) > 55:
            findings.append(_finding(
                "LONG_HOSTNAME",
                "low",
                "Unusually long hostname",
                "The hostname is unusually long and may be harder to inspect.",
                [Evidence(label="Hostname length", value=str(len(hostname)))],
            ))
            scores.append(15)

        # 5. Sensitive-action terms in hostname labels.
        matched_terms = sorted(
            term for term in SUSPICIOUS_TERMS
            if term in labels
        )

        if matched_terms:
            findings.append(_finding(
                "SENSITIVE_HOSTNAME_TERMS",
                "low",
                "Sensitive-action terms in hostname",
                "The hostname contains terms commonly associated with account "
                "access or credential collection. Context is required.",
                [Evidence(label="Matched terms", value=", ".join(matched_terms))],
            ))
            scores.append(15)

        # 6. Suspicious URL path terms.
        path_lower = parts.path.lower()
        matched_paths = sorted(
            term for term in SUSPICIOUS_TERMS
            if term in path_lower.split("/")
        )

        if matched_paths:
            findings.append(_finding(
                "SENSITIVE_PATH_TERMS",
                "low",
                "Sensitive-action terms in URL path",
                "The URL path contains terms associated with account access "
                "or sensitive actions. This alone does not establish malicious intent.",
                [Evidence(label="Matched terms", value=", ".join(matched_paths))],
            ))
            scores.append(10)

        # A heuristic-only result is always partial because no external
        # reputation database has been queried.
        return ModuleResult(
            id=self.id,
            status="partial",
            risk_score=None,
            status_reason=StatusReason(
                code="EXTERNAL_INTELLIGENCE_NOT_CONNECTED",
                message=(
                    "Local URL heuristics were evaluated, but external threat "
                    "intelligence providers have not been queried. "
                    "This is not a complete reputation assessment."
                ),
            ),
            findings=findings,
            details={
                "local_heuristics": "completed",
                "external_providers": {
                    "urlhaus": "not_connected",
                    "phishtank": "not_connected",
                },
                "heuristic_findings": len(findings),
            },
        )
