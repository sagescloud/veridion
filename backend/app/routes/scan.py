"""app/routes/scan.py: POST /api/scan and GET /api/scan/{scan_id}"""
from __future__ import annotations

import asyncio
import logging
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, Request

from app.errors import AppError
from app.middleware import scan_rate_limit
from app.models.errors import ErrorResponse
from app.models.scan import ScanReport, ScanRequest
from app.modules import get_modules
from app.services.scan_orchestrator import run_scan
from app.services.supabase_service import SupabaseUnavailable

log = logging.getLogger("veridion.routes.scan")
router = APIRouter(prefix="/api", tags=["scan"])

_ERRORS = {422: {"model": ErrorResponse}, 429: {"model": ErrorResponse},
           503: {"model": ErrorResponse}, 504: {"model": ErrorResponse}}


async def _persist(request_app, report: ScanReport) -> None:
    """Background, best-effort: a database hiccup must never fail a finished scan."""
    try:
        await request_app.state.supabase.save_scan(report)
    except Exception:  # noqa: BLE001
        log.warning("could not persist scan %s", report.scan_id, exc_info=True)


@router.post("/scan", response_model=ScanReport, responses=_ERRORS, dependencies=[Depends(scan_rate_limit)])
async def create_scan(body: ScanRequest, request: Request, background: BackgroundTasks) -> ScanReport:
    """Synchronous scan (MVP). Returns the finished report."""
    st = request.app.state
    # Load shedding: wait briefly for a slot, otherwise tell the client to retry.
    try:
        await asyncio.wait_for(st.scan_semaphore.acquire(), timeout=2.0)
    except TimeoutError:
        raise AppError("SERVICE_UNAVAILABLE", "We're busy right now. Please try again in a few seconds.", 503,
                       {"retry_after_seconds": 5}, {"Retry-After": "5"}) from None
    try:
        report = await run_scan(body.url, settings=st.settings, http=st.http, modules=get_modules(),
                                community_lookup=st.supabase.community_intel)
    finally:
        st.scan_semaphore.release()

    st.scan_store.put(report)
    background.add_task(_persist, request.app, report)
    return report


@router.get("/scan/{scan_id}", response_model=ScanReport, responses={404: {"model": ErrorResponse}})
async def get_scan(scan_id: str, request: Request) -> ScanReport:
    st = request.app.state
    not_found = AppError("SCAN_NOT_FOUND", "We couldn't find that scan.", 404)
    try:
        uuid.UUID(scan_id)
    except ValueError:
        raise not_found from None

    report = st.scan_store.get(scan_id)
    if report is None:
        try:
            report = await st.supabase.get_scan(scan_id)
        except SupabaseUnavailable:
            raise AppError("SERVICE_UNAVAILABLE", "Scan history is temporarily unavailable.", 503) from None
    if report is None:
        raise not_found
    return report
