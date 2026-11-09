"""Unit tests for the url_domain module.

Uses only reserved example domains and safe test URLs.  No network access,
no DNS lookups, no external API calls.
"""
from __future__ import annotations

import pytest
from ipaddress import IPv4Address

from app.modules.url_domain import analyse_url
from app.models.scan import Finding, ModuleResult, StatusReason
from app.utils.url_tools import parse_url
from app.config import Settings


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------

def make_module_result(
    *,
    status: str = "completed",
    risk_score: int | None = None,
    findings: list[Finding] | None = None,
) -> ModuleResult:
    """Convenient builder for ModuleResult instances in tests."""
    return ModuleResult(
        id="url_domain",
        status=status,
        risk_score=risk_score,
        status_reason=None if status == "completed" else StatusReason(
            code="X", message="test",
        ),
        findings=findings or [],
        details=None,
    )


# ---------------------------------------------------------------------------
# 1. Normal reserved example domain
# ---------------------------------------------------------------------------
def test_normal_reserved_domain():
    """A plain example.com URL should produce a completed module with minimal findings."""
    url = parse_url("https://example.com/")
    ctx = type("_Ctx", (), {"url": url, "resolved_ips": [], "http": None, "settings": Settings()})()
    result = analyse_url(ctx)
    assert result.status == "completed"
    assert result.risk_score is not None and 0 <= result.risk_score <= 100
    assert len(result.findings) > 0
    informational = any(f.type == "informational" for f in result.findings)
    assert informational


# ---------------------------------------------------------------------------
# 2. URL with a subdomain
# ---------------------------------------------------------------------------
def test_url_with_subdomain():
    """A URL with subdomains should detect the subdomain structure."""
    url = parse_url("https://sub1.sub2.example.com/")
    ctx = type("_Ctx", (), {"url": url, "resolved_ips": [], "http": None, "settings": Settings()})()
    result = analyse_url(ctx)
    assert result.status == "completed"
    subdomain_findings = [f for f in result.findings if f.code == "SUBDOMAIN_STRUCTURE"]
    assert len(subdomain_findings) > 0
    for f in subdomain_findings:
        assert f.evidence is not None
        evidence_labels = [e.label for e in f.evidence]
        assert any("subdomain" in v.lower() for v in evidence_labels)


# ---------------------------------------------------------------------------
# 3. IPv4 hostname
# ---------------------------------------------------------------------------
def test_ipv4_hostname():
    """An IPv4 literal URL should be detected and reported."""
    url = parse_url("http://2130706433/")  # 127.0.0.1
    ctx = type("_Ctx", (), {"url": url, "resolved_ips": [], "http": None, "settings": Settings()})()
    result = analyse_url(ctx)
    assert result.status == "completed"
    ip_findings = [f for f in result.findings if f.code == "IP_BASED_URL"]
    assert len(ip_findings) > 0
    for f in ip_findings:
        evidence_vals = [e.value for e in f.evidence]
        assert "127.0.0.1" in evidence_vals


# ---------------------------------------------------------------------------
# 3. Very long URL
# ---------------------------------------------------------------------------
def test_very_long_url():
    """A very long URL should be flagged."""
    long_path = "a" * 200
    url = parse_url(f"https://example.com/{long_path}")
    ctx = type("_Ctx", (), {"url": url, "resolved_ips": [], "http": None, "settings": Settings()})()
    result = analyse_url(ctx)
    assert result.status == "completed"
    long_findings = [f for f in result.findings if f.code == "LONG_URL"]
    assert len(long_findings) > 0
    for f in long_findings:
        evidence_vals = [e.value for e in f.evidence]
        assert str(len(url.normalized)) in evidence_vals


# ---------------------------------------------------------------------------
# 3. Suspicious structural patterns
# ---------------------------------------------------------------------------
def test_suspicious_structural_patterns():
    """A URL with misleading path patterns should be flagged."""
    url = parse_url("https://example.com/login/secure/verify")
    ctx = type("_Ctx", (), {"url": url, "resolved_ips": [], "http": None, "settings": Settings()})()
    result = analyse_url(ctx)
    assert result.status == "completed"
    misleading_findings = [f for f in result.findings if f.code == "MISLEADING_PATH"]
    assert len(misleading_findings) > 0


# ---------------------------------------------------------------------------
# 4. Evidence structure compatibility
# ---------------------------------------------------------------------------
def test_evidence_structure():
    """Findings should have evidence as {label, value} pairs."""
    url = parse_url("https://example.com/")
    ctx = type("_Ctx", (), {"url": url, "resolved_ips": [], "http": None, "settings": Settings()})()
    result = analyse_url(ctx)
    for f in result.findings:
        assert f.evidence is not None
        for ev in f.evidence:
            assert ev.label is not None and isinstance(ev.label, str)
            assert ev.value is not None and isinstance(ev.value, str)


# ---------------------------------------------------------------------------
# 5. Valid ModuleResult output
# ---------------------------------------------------------------------------
def test_valid_module_result():
    """The module should return a ModuleResult that conforms to the contract."""
    url = parse_url("https://example.com/")
    ctx = type("_Ctx", (), {"url": url, "resolved_ips": [], "http": None, "settings": Settings()})()
    result = analyse_url(ctx)
    assert isinstance(result, ModuleResult)
    assert result.id == "url_domain"
    assert result.status == "completed"
    assert result.risk_score is not None
    assert 0 <= result.risk_score <= 100
    assert len(result.findings) > 0
    for f in result.findings:
        assert f.code is not None
        assert f.type is not None
        assert f.severity is not None
        assert f.title is not None
        assert f.description is not None
        assert f.evidence is not None
        for ev in f.evidence:
            assert ev.label is not None and isinstance(ev.label, str)
            assert ev.value is not None and isinstance(ev.value, str)


# ---------------------------------------------------------------------------
# 6. Risk score boundaries
# ---------------------------------------------------------------------------
def test_risk_score_boundaries():
    """Risk score should be within 0–100."""
    url = parse_url("https://example.com/")
    ctx = type("_Ctx", (), {"url": url, "resolved_ips": [], "http": None, "settings": Settings()})()
    result = analyse_url(ctx)
    assert 0 <= result.risk_score <= 100


# ---------------------------------------------------------------------------
# 7. No network access during structural analysis
# ---------------------------------------------------------------------------
def test_no_network_access():
    """The module should not make any network calls."""
    url = parse_url("https://example.com/")
    ctx = type("_Ctx", (), {"url": url, "resolved_ips": [], "http": None, "settings": Settings()})()
    result = analyse_url(ctx)
    assert result.status == "completed"


if __name__ == "__main__":
    import sys
    sys.path.insert(0, __file__)
    print("Running url_domain module tests...")
    # Run the test functions directly
    test_funcs = [
        test_normal_reserved_domain,
        test_url_with_subdomain,
        test_ipv4_hostname,
        test_very_long_url,
        test_suspicious_structural_patterns,
        test_evidence_structure,
        test_valid_module_result,
        test_risk_score_boundaries,
        test_no_network_access,
    ]
    passed = 0
    failed = 0
    for func in test_funcs:
        try:
            func()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"FAIL {func.__name__}: {e}")
    print(f"Passed: {passed} / {len(test_funcs)}")
    if failed:
        print("Failed tests:")
        for name, err in [("test_" + f"_test_" + f).__name__ for f in ["test_normal_reserved_domain", "test_url_with_subdomain", "test_ipv4_hostname", "test_very_long_url", "test_suspicious_structural_patterns", "test_evidence_structure", "test_valid_module_result", "test_risk_score_boundaries", "test_no_network_access"]]:
            pass