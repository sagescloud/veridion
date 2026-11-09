"""
app/services/scan_orchestrator.py
Runs one scan: validate -> SSRF pre-flight -> run all modules CONCURRENTLY ->
assess risk -> build the report.

Failure isolation (PRD 7.1 / 7.3): each module has its own timeout and its own
try/except. A slow or crashing module becomes status="failed"; it can never
take down the scan or masquerade as a clean result.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

import httpx

from app.config import Settings
from app.errors import AppError
from app.models.report import CommunityIntel
from app.models.scan import ModuleResult, ScanReport
from app.modules.base import AnalysisModule, ScanContext, not_run
from app.services.risk_engine import assess
from app.utils.ssrf_guard import HostUnresolvable, assert_destination_allowed
from app.utils.url_tools import parse_url

log = logging.getLogger("veridion.scan")

CommunityLookup = Callable[[str], Awaitable[CommunityIntel | None]]


async def _run_module(module: AnalysisModule, ctx: ScanContext, timeout: float) -> ModuleResult:
    try:
        async with asyncio.timeout(timeout):
            result = await module.run(ctx)
        if not isinstance(result, ModuleResult):
            raise TypeError(f"module {module.id} returned {type(result).__name__}")
        if result.id != module.id:  # a module may not report under another module's id
            result = result.model_copy(update={"id": module.id})
        return result
    except TimeoutError:
        log.warning("module %s timed out after %.1fs", module.id, timeout)
        return not_run(module.id, "failed", "MODULE_TIMEOUT",
                       "This check took too long and was stopped. This is not a clean result.")
    except Exception:  # noqa: BLE001 - isolation boundary: nothing escapes
        log.exception("module %s crashed", module.id)
        return not_run(module.id, "failed", "MODULE_ERROR",
                       "This check failed unexpectedly. This is not a clean result.")


async def _safe_community(lookup: CommunityLookup | None, url: str) -> CommunityIntel | None:
    if lookup is None:
        return None
    try:
        async with asyncio.timeout(4.0):
            return await lookup(url)
    except Exception:  # noqa: BLE001 - community data is a bonus, never a blocker
        log.warning("community lookup failed", exc_info=True)
        return None


async def run_scan(url_input: str, *, settings: Settings, http: httpx.AsyncClient,
                   modules: list[AnalysisModule], community_lookup: CommunityLookup | None = None) -> ScanReport:
    started = time.monotonic()

    parsed = parse_url(url_input)                      # UrlError -> 422 INVALID_URL / UNSUPPORTED_SCHEME
    try:
        resolved = await assert_destination_allowed(parsed, settings)   # SSRFBlocked -> 422 BLOCKED_DESTINATION
    except HostUnresolvable:
        resolved = []  # unresolvable domains are still analysable (lookalike, reputation); fetch-based modules will report it

    ctx = ScanContext(url=parsed, resolved_ips=resolved, http=http, settings=settings)
    timeout = min(settings.module_timeout_s, settings.scan_overall_timeout_s)

    results_and_community = await asyncio.gather(
        asyncio.gather(*(_run_module(m, ctx, timeout) for m in modules)),
        _safe_community(community_lookup, parsed.normalized),
    )
    results: list[ModuleResult] = list(results_and_community[0])
    community: CommunityIntel | None = results_and_community[1]

    if results and all(r.status_reason and r.status_reason.code == "MODULE_TIMEOUT" for r in results):
        raise AppError("SCAN_TIMEOUT", "The scan took too long. Please try again.", 504)

    # Finding ids must be unique across the whole scan (modules only know their own).
    n = 0
    for r in results:
        for f in r.findings:
            n += 1
            f.id = f"f{n}"

    overall, recommendations = assess(results, community)
    return ScanReport(
        scan_id=str(uuid.uuid4()),
        status="completed",
        submitted_url=url_input,  # schema: exactly what the user entered
        normalized_url=parsed.normalized,
        scanned_at=datetime.now(timezone.utc).replace(microsecond=0),
        duration_ms=int((time.monotonic() - started) * 1000),
        overall=overall,
        modules=results,
        recommendations=recommendations,
        community=community,
    )
