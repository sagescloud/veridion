"""
app/services/risk_engine.py
PROVISIONAL risk assessment (PRD Module 5). Owned by P: tune or replace freely,
as long as `assess()` keeps returning (Overall, list[Recommendation]).

Implemented rules:
  * Weighted average using the PRD weights, RE-NORMALISED over modules that
    actually produced a score. Missing modules never count as 0 ("safe").
  * Confidence is separate from risk: share of total weight that completed,
    capped at "medium" if threat reputation did not complete (absence of data
    is not evidence of safety).
  * Confirmed phishing escalates to critical instead of being diluted.
  * No module scored -> score null, classification "inconclusive".
Thresholds are provisional (PRD): 0-24 low, 25-49 moderate, 50-74 high, 75-100 critical.
"""
from __future__ import annotations

from app.models.report import CommunityIntel
from app.models.scan import (Confidence, Escalation, Finding, ModuleResult, Overall, Recommendation)

WEIGHTS: dict[str, int] = {
    "threat_reputation": 30, "url_domain": 25, "website_behaviour": 20,
    "certificate": 15, "security_config": 10,
}
LABELS = {
    "threat_reputation": "Threat reputation", "url_domain": "URL and domain analysis",
    "website_behaviour": "Website behaviour", "certificate": "Certificate check",
    "security_config": "Security configuration",
}
ESCALATION_FLOOR = 90


def classify(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "moderate"
    return "low"


def _confidence(results: list[ModuleResult]) -> Confidence:
    by_id = {r.id: r for r in results}
    coverage = 0.0
    for mid, w in WEIGHTS.items():
        r = by_id.get(mid)  # type: ignore[call-overload]
        if r is None:
            continue
        if r.status == "completed":
            coverage += w
        elif r.status == "partial":
            coverage += w / 2
        elif r.status == "skipped":
            coverage += w  # genuinely not applicable (e.g. no HTTPS), not a gap in evidence
    completed = sum(1 for r in results if r.status == "completed")
    reasons = [f"{completed} of {len(WEIGHTS)} analysis modules completed"]
    for r in results:
        if r.status != "completed" and r.status_reason:
            reasons.append(f"{LABELS.get(r.id, r.id)}: {r.status_reason.message}")

    level = "high" if coverage >= 85 else "medium" if coverage >= 50 else "low"
    rep = by_id.get("threat_reputation")  # type: ignore[call-overload]
    if level == "high" and (rep is None or rep.status != "completed"):
        level = "medium"
    return Confidence(level=level, reasons=reasons)  # type: ignore[arg-type]


def _all_findings(results: list[ModuleResult]) -> list[Finding]:
    return [f for r in results for f in r.findings]


def compute_overall(results: list[ModuleResult]) -> Overall:
    confidence = _confidence(results)
    scored = [(r, WEIGHTS[r.id]) for r in results if r.risk_score is not None]

    escalation = None
    for r in results:
        if r.id == "threat_reputation" and any(f.code == "CONFIRMED_PHISHING" for f in r.findings):
            escalation = Escalation(
                code="CONFIRMED_PHISHING",
                message="This address is listed as phishing by a threat intelligence source. Do not use it.")

    if not scored and escalation is None:
        confidence.reasons.insert(0, "No analysis module produced a result, so no risk score can be given")
        return Overall(risk_score=None, classification="inconclusive", confidence=confidence)

    if scored:
        total_w = sum(w for _, w in scored)
        score = round(sum(r.risk_score * w for r, w in scored) / total_w)  # type: ignore[operator]
    else:
        score = 0
    if escalation:
        score = max(score, ESCALATION_FLOOR)
    return Overall(risk_score=score, classification=classify(score),  # type: ignore[arg-type]
                   confidence=confidence, escalation=escalation)


# code -> actionable advice. P/frontend can extend. Unknown codes fall back to the finding's own text.
_ADVICE = {
    "CONFIRMED_PHISHING": "Do not open this site or enter any information on it.",
    "LOOKALIKE_DOMAIN": "Check the address carefully. It imitates a well-known brand. Go to the real site by typing its address yourself.",
    "NO_HTTPS": "Do not enter passwords or payment details: this site does not encrypt your data.",
    "REDIRECT_TO_DIFFERENT_DOMAIN": "Be cautious: this link sends you through another website before showing content.",
}


def build_recommendations(results: list[ModuleResult], community: CommunityIntel | None) -> list[Recommendation]:
    recs: list[Recommendation] = []
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = [f for f in _all_findings(results) if f.severity in ("critical", "high", "medium")]
    findings.sort(key=lambda f: order[f.severity])
    seen: set[str] = set()
    for f in findings:
        text = _ADVICE.get(f.code, f"Review this finding before trusting the site: {f.title}.")
        if text in seen:
            continue
        seen.add(text)
        recs.append(Recommendation(id=f"r{len(recs) + 1}", priority="high" if f.severity in ("critical", "high") else "medium",
                                   text=text, related_finding_ids=[f.id]))
    if community and community.reported:
        recs.append(Recommendation(
            id=f"r{len(recs) + 1}", priority="high",
            text=f"Other users have reported this address ({community.report_count} report(s)). Treat it with caution.",
            related_finding_ids=[]))
    # PRD principle: no result is ever presented as "safe".
    recs.append(Recommendation(
        id=f"r{len(recs) + 1}", priority="low",
        text="No warnings does not mean a site is safe. Be careful with links you did not expect.",
        related_finding_ids=[]))
    return recs


def assess(results: list[ModuleResult], community: CommunityIntel | None) -> tuple[Overall, list[Recommendation]]:
    return compute_overall(results), build_recommendations(results, community)
