"""app/modules/url_domain.py
URL and Domain Intelligence module for Veridion.

Performs structural analysis of URLs and domains. Does NOT make external API calls,
perform DNS lookups, or claim reputation verdicts. See docs/security-url-domain-api-schema.md
for the complete interface contract and limitations.

Only uses Python standard library + the idna library (already a dependency).
"""
from __future__ import annotations

import re
from typing import Any, List, Optional

from ipaddress import IPv4Address, IPv6Address, ip_address

from app.models.scan import Finding, ModuleResult, StatusReason
from app.modules.base import AnalysisModule, ScanContext, not_run
from app.utils.url_tools import ParsedUrl, parse_url


# ---------------------------------------------------------------------------
# Typosquat detection: common character substitution patterns that are
# frequently used in typosquatting but do NOT require a known-brand database.
# These heuristics identify *patterns* that are commonly abused, not
# confirmed typosquatting against a specific brand.
# Raw strings are used for the regex patterns to avoid Python escape-sequence
# warnings (e.g. \d, \s).
# ---------------------------------------------------------------------------
TYPOSQUAT_PATTERNS: list[tuple[str, str]] = [
    # numeral-for-letter substitutions common in typosquatting
    (r"1", "l"),   # 1 instead of l
    (r"0", "O"),   # 0 instead of O
    (r"5", "s"),   # 5 instead of s
]


def _count_subdomains(hostname: str) -> int:
    """Count the number of subdomain levels in *hostname*.

    Splits on '.' and counts parts beyond the registered domain.
    - example.com          -> 0 subdomains
    - sub.example.com    -> 1 subdomain
    - sub.sub.example.com -> 2 subdomains
    """
    parts = hostname.split(".")
    if len(parts) <= 1:
        return 0
    return max(0, len(parts) - 2)


def _has_typosquat_pattern(hostname: str) -> bool:
    """Heuristic: detect character-substitution patterns common in typosquatting.

    Does NOT check against a known-brand database. Only identifies *patterns*
    that are frequently abused (e.g. 1 instead of l, 0 instead of O).
    """
    for pattern, replacement in TYPOSQUAT_PATTERNS:
        # Check if the pattern-digit exists in the hostname
        if pattern in hostname:
            # Simple further check: ensure the character is surrounded by
            # letter-like neighbours (not just part of a random number sequence).
            idx = hostname.index(pattern)
            before = hostname[idx - 1] if idx > 0 else ""
            after = hostname[idx + len(pattern)] if idx + len(pattern) < len(hostname) else ""
            # If surrounded by letters, it's more likely a typosquat pattern.
            if before.isalpha() or after.isalpha():
                return True
    return False


def _classify_typosquat_severity(hostname: str) -> str:
    """Return a severity string for a detected typosquat pattern."""
    if len(hostname) <= 15:
        return "medium"
    return "low"


def _build_evidence(label: str, value: str) -> dict:
    """Return a structured evidence entry {label, value}."""
    return {"label": label, "value": value}


def _analyse_hostname(hostname: str) -> list[Finding]:
    """Produce findings based on the *hostname* component of a URL.

    Performs structural analysis only. No DNS, no external lookups, no
    brand‑database checks.
    """
    findings: list[Finding] = []

    # --- IP-based URL detection -------------------------------------------
    try:
        ip = ip_address(hostname)
        if ip.version == 4:
            findings.append(Finding(
                id="f1",
                code="IP_BASED_URL",
                type="misconfiguration",
                severity="medium",
                title="IP-based URL detected",
                description="The URL uses an IP address instead of a hostname.",
                evidence=[_build_evidence("IP address", str(ip))],
            ))
        elif ip.version == 6:
            findings.append(Finding(
                id="f2",
                code="IP_BASED_URL",
                type="misconfiguration",
                severity="low",
                title="IP-based URL detected",
                description="The URL uses an IPv6 address.",
                evidence=[_build_evidence("IP address", str(ip))],
            ))
    except ValueError:
        pass  # not an IP literal

    # --- Subdomain structure -----------------------------------------------
    subdomain_count = _count_subdomains(hostname)
    if subdomain_count >= 2:
        findings.append(Finding(
            id="f3",
            code="SUBDOMAIN_STRUCTURE",
            type="suspicious_indicator",
            severity="medium",
            title="Unusual subdomain structure",
            description="The domain contains multiple nested subdomains.",
            evidence=[_build_evidence("Subdomain count", str(subdomain_count))],
        ))

    # --- IDN/punycode detection -------------------------------------------
    try:
        import idna  # type: ignore
        puny = idna.encode(hostname).decode("ascii")
        if puny != hostname.lower():
            findings.append(Finding(
                id="f4",
                code="IDN_DOMAIN",
                type="informational",
                severity="low",
                title="Internationalized domain name",
                description="The domain uses non‑ASCII characters (IDN).",
                evidence=[
                    _build_evidence("Hostname (punycode)", puny),
                    _build_evidence("Original hostname", hostname),
                ],
            ))
    except Exception:
        pass  # idna not available — skip IDN analysis

    # --- Typosquat pattern detection (structural heuristics only) ---------
    if _has_typosquat_pattern(hostname):
        severity = _classify_typosquat_severity(hostname)
        findings.append(Finding(
            id="f5",
            code="TYPOSQUAT",
            type="suspicious_indicator",
            severity=severity,
            title="Potential typosquatting detected",
            description="The domain contains character-level patterns "
                        "commonly used in typosquatting (e.g. substituting "
                        "numerals for letters). This does not confirm the "
                        "domain is malicious, but warrants caution.",
            evidence=[
                _build_evidence("Suspicious pattern", " numeral 1 instead of letter l"),
                _build_evidence("Input domain", hostname),
            ],
        ))

    return findings


def _analyse_url_length(normalized_url: str) -> Optional[Finding]:
    """Analyze the URL length and return a finding if it exceeds the threshold."""
    url_len = len(normalized_url)
    if url_len > 100:
        return Finding(
            id="f6",
            code="LONG_URL",
            type="suspicious_indicator",
            severity="medium",
            title="Unusually long URL",
            description="The submitted URL is longer than typical. This may be "
                        "an attempt to obfuscate the destination.",
            evidence=[_build_evidence("URL length", str(url_len))],
        )
    return None


def _analyse_suspicious_patterns(normalized_url: str) -> list[Finding]:
    """Run structural pattern checks on the normalized URL string."""
    findings: list[Finding] = []
    lower = normalized_url.lower()
    misleading_paths = ["/login", "/signin", "/secure", "/verify"]
    for path in misleading_paths:
        if path in lower:
            findings.append(Finding(
                id="f7",
                code="MISLEADING_PATH",
                type="suspicious_indicator",
                severity="low",
                title="Misleading path pattern",
                description="The URL path contains a term commonly used "
                            "to mislead visitors into thinking the site is "
                            "secure or authenticated.",
            ))
            break  # only report once
    return findings


def analyse_url(ctx: "ScanContext") -> ModuleResult:
    """Entry point called by the orchestrator.

    Reuses parse_url() for normalization; performs structural analysis
    on the URL and hostname only. No network requests, no DNS lookups,
    no reputation checks.

    The returned ModuleResult conforms to the backend contract
    (app/models/scan.py:ModuleResult) including risk_score, status,
    status_reason, and finding schemas.
    """
    # The orchestrator already validated the URL and performed SSRF checks.
    # ctx.url is a ParsedUrl; ctx.resolved_ips are public IPs from SSRF guard.
    url = ctx.url

    findings: list[Finding] = []

    # 1. Hostname analysis
    findings.extend(_analyse_hostname(url.hostname))

    # 2. URL length analysis
    length_finding = _analyse_url_length(url.normalized)
    if length_finding is not None:
        findings.append(length_finding)

    # 3. Suspicious pattern analysis
    findings.extend(_analyse_suspicious_patterns(url.normalized))

    # 4. If no findings were produced, the module is still "completed"
    #    with a low risk score (well‑behaved URL).
    if not findings:
        findings = []

    # Compute a risk_score 0–100 based on the findings.
    # Heuristic:
    #   - IP-based URL:               65
    #   - Typosquat pattern:          55
    #   - Long URL (>100 chars):      25
    #   - Misleading path:            15
    #   - IDN domain:                 10
    #   - 2+ subdomains:              30
    #   - No issues:                  5
    score = 0
    has_ip = any(f.code == "IP_BASED_URL" for f in findings)
    has_typosquat = any(f.code == "TYPOSQUAT" for f in findings)
    has_long_url = any(f.code == "LONG_URL" for f in findings)
    has_misleading = any(f.code == "MISLEADING_PATH" for f in findings)
    has_idn = any(f.code == "IDN_DOMAIN" for f in findings)
    has_2plus_subdomain = any(f.code == "SUBDOMAIN_STRUCTURE" for f in findings)
    if has_ip:
        score = 65
    elif has_typosquat:
        score = 55
    elif has_long_url:
        score = 25
    elif has_misleading:
        score = 15
    elif has_idn:
        score = 10
    elif has_2plus_subdomain:
        score = 30
    else:
        score = 5

    # Build the ModuleResult ------------------------------------------------
    status = "completed"
    status_reason = None  # completed modules should not have status_reason

    return ModuleResult(
        id="url_domain",
        status=status,
        risk_score=score,
        status_reason=status_reason,
        findings=findings,
        details=None,
    )


# The module protocol requires an async `run` method.
# The orchestrator calls `module.run(ctx)` — we wrap the synchronous
# analyse_url in an async function.
async def run(ctx: ScanContext) -> ModuleResult:
    """Async entry point per the AnalysisModule protocol."""
    return analyse_url(ctx)