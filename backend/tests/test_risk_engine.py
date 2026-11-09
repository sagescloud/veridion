from app.models.scan import Finding, ModuleResult, StatusReason
from app.services.risk_engine import assess


def done(mid, score, findings=()):
    return ModuleResult(id=mid, status="completed", risk_score=score, findings=list(findings))


def gone(mid, status="unavailable"):
    return ModuleResult(id=mid, status=status, risk_score=None,
                        status_reason=StatusReason(code="X", message="could not run"))


def test_missing_modules_are_not_counted_as_zero():
    results = [done("url_domain", 80), gone("threat_reputation"), gone("certificate"),
               gone("security_config"), gone("website_behaviour")]
    overall, _ = assess(results, None)
    assert overall.risk_score == 80          # not diluted by 'unavailable' modules
    assert overall.confidence.level == "low"


def test_nothing_ran_is_inconclusive_never_safe():
    results = [gone(m) for m in ("url_domain", "threat_reputation", "certificate", "security_config", "website_behaviour")]
    overall, recs = assess(results, None)
    assert overall.risk_score is None and overall.classification == "inconclusive"
    assert all("safe" not in r.text.lower() or "does not mean" in r.text.lower() for r in recs)


def test_confirmed_phishing_escalates_despite_clean_modules():
    phish = Finding(id="f1", code="CONFIRMED_PHISHING", type="malicious_indicator", severity="critical",
                    title="t", description="d")
    results = [done("threat_reputation", 10, [phish]), done("url_domain", 0), done("certificate", 0),
               done("security_config", 0), done("website_behaviour", 0)]
    overall, _ = assess(results, None)
    assert overall.escalation and overall.classification == "critical" and overall.risk_score >= 90


def test_confidence_capped_when_reputation_missing():
    results = [done("url_domain", 5), gone("threat_reputation"), done("certificate", 5),
               done("security_config", 5), done("website_behaviour", 5)]
    overall, _ = assess(results, None)
    assert overall.confidence.level == "medium"


def test_module_contract_rejects_zero_for_unavailable():
    import pytest
    with pytest.raises(ValueError):
        ModuleResult(id="certificate", status="unavailable", risk_score=0,
                     status_reason=StatusReason(code="X", message="m"))
