"""
app/models/scan.py
Pydantic models matching "Veridion: Proposed Scan API Schema" (0.1-proposal).

Deliberate additions beyond the proposal (flagged for frontend/security review):
  * overall.classification may be "inconclusive" and overall.risk_score may be
    null when NO module produced a score. The PRD forbids unsupported
    safe/unsafe conclusions, so we cannot invent a number.
  * top-level `community` block (needed by the PRD 'previously reported URL' test).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from app.models.report import CommunityIntel

SCHEMA_VERSION = "0.1-proposal"

ModuleId = Literal["url_domain", "threat_reputation", "certificate", "security_config", "website_behaviour"]
ModuleStatus = Literal["completed", "partial", "unavailable", "failed", "skipped"]
FindingType = Literal["malicious_indicator", "suspicious_indicator", "misconfiguration", "informational"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Classification = Literal["low", "moderate", "high", "critical", "inconclusive"]
ConfidenceLevel = Literal["low", "medium", "high"]
Priority = Literal["low", "medium", "high"]
ScanStatus = Literal["pending", "running", "completed"]  # per schema: sync MVP emits "completed" only


class ScanRequest(BaseModel):
    """POST /api/scan body."""
    url: str = Field(min_length=1, max_length=2048)


class Evidence(BaseModel):
    label: str
    value: str


class Finding(BaseModel):
    id: str
    code: str
    type: FindingType
    severity: Severity
    title: str
    description: str
    evidence: list[Evidence] = Field(default_factory=list)


class StatusReason(BaseModel):
    code: str
    message: str


class ModuleResult(BaseModel):
    id: ModuleId
    status: ModuleStatus
    risk_score: int | None = Field(default=None, ge=0, le=100)
    status_reason: StatusReason | None = None
    findings: list[Finding] = Field(default_factory=list)
    details: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _enforce_contract(self) -> "ModuleResult":
        # "null must never be treated as 0 or as safe": make the rule structural.
        if self.status == "completed" and self.risk_score is None:
            raise ValueError("a completed module must provide a risk_score")
        if self.status in ("unavailable", "failed", "skipped") and self.risk_score is not None:
            raise ValueError(f"a {self.status} module must have risk_score = null")
        if self.status != "completed" and self.status_reason is None:
            raise ValueError("non-completed modules must explain why via status_reason")
        return self


class Confidence(BaseModel):
    level: ConfidenceLevel
    reasons: list[str]


class Escalation(BaseModel):
    code: Literal["CONFIRMED_PHISHING"]
    message: str


class Overall(BaseModel):
    risk_score: int | None = Field(default=None, ge=0, le=100)
    classification: Classification
    confidence: Confidence
    escalation: Escalation | None = None


class Recommendation(BaseModel):
    id: str
    priority: Priority
    text: str
    related_finding_ids: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    schema_version: str = SCHEMA_VERSION
    scan_id: str
    status: ScanStatus = "completed"
    submitted_url: str
    normalized_url: str
    scanned_at: datetime
    duration_ms: int
    overall: Overall
    modules: list[ModuleResult]
    recommendations: list[Recommendation]
    community: CommunityIntel | None = None
