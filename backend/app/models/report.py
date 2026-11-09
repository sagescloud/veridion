"""
app/models/report.py
Community-report request/response models (PRD Module 6).
NOTE: these bodies are NOT in the proposed scan schema; they are proposed here
and must be agreed with the frontend.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

ReportCategory = Literal["phishing", "scam", "malware", "impersonation", "other"]

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ReportRequest(BaseModel):
    """POST /api/report body."""
    url: str = Field(min_length=1, max_length=2048)
    category: ReportCategory = "other"
    description: str | None = Field(default=None, max_length=500)

    @field_validator("description")
    @classmethod
    def _clean_description(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = _CONTROL_CHARS.sub("", v).strip()
        return v or None


class ReportCreated(BaseModel):
    """201 response for POST /api/report."""
    report_id: str
    normalized_url: str
    report_count: int          # total community reports for this URL, including this one
    created_at: datetime


class ReportSummary(BaseModel):
    """One entry per reported URL (individual reporters are never exposed)."""
    normalized_url: str
    report_count: int
    first_reported_at: datetime
    last_reported_at: datetime
    categories: list[str]


class ReportList(BaseModel):
    """GET /api/reports response."""
    reports: list[ReportSummary]
    total: int
    limit: int
    offset: int


class CommunityIntel(BaseModel):
    """Additive field on the scan report (PRD test: 'Previously reported URL')."""
    reported: bool
    report_count: int = 0
    first_reported_at: datetime | None = None
    last_reported_at: datetime | None = None
    categories: list[str] = Field(default_factory=list)
