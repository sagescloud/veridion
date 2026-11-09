"""
app/modules/base.py
The contract between the backend (T) and the security/intelligence modules (P).

To add or replace a module:
  1. Create a class with an `id` (a ModuleId) and `async def run(self, ctx) -> ModuleResult`.
  2. Register it in app/modules/__init__.py::get_modules().

Rules every module MUST follow (they come from the PRD):
  * Make network requests ONLY through ctx.http + safe_fetch (SSRF-guarded).
    For raw sockets, connect to an IP from ctx.resolved_ips, never re-resolve.
  * Never block the event loop: wrap blocking code in `await asyncio.to_thread(...)`.
  * Can't run?  Return status="unavailable"/"failed"/"skipped" with risk_score=None
    and a status_reason. NEVER return 0 for "didn't check" and never say "safe".
  * The orchestrator enforces a timeout, converts exceptions to status="failed",
    and renumbers finding ids, so modules can't crash a scan.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import httpx

from app.config import Settings
from app.models.scan import ModuleId, ModuleResult, StatusReason
from app.utils.url_tools import ParsedUrl


@dataclass
class ScanContext:
    url: ParsedUrl
    resolved_ips: list[str]            # already validated as public; empty if DNS failed
    http: httpx.AsyncClient            # SSRF-guarded client
    settings: Settings
    extras: dict = field(default_factory=dict)  # scratch space shared between modules if ever needed


class AnalysisModule(Protocol):
    id: ModuleId

    async def run(self, ctx: ScanContext) -> ModuleResult: ...


def not_run(module_id: ModuleId, status: str, code: str, message: str) -> ModuleResult:
    """Helper for honest 'no result' answers (unavailable / failed / skipped)."""
    return ModuleResult(id=module_id, status=status, risk_score=None,  # type: ignore[arg-type]
                        status_reason=StatusReason(code=code, message=message),
                        findings=[], details=None)
