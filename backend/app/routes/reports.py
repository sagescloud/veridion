"""app/routes/reports.py: POST /api/report and GET /api/reports (community intelligence)"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from app.errors import AppError
from app.middleware import client_ip, report_rate_limit
from app.models.errors import ErrorResponse
from app.models.report import ReportCreated, ReportList, ReportRequest
from app.services.supabase_service import DuplicateReport, SupabaseUnavailable
from app.utils.url_tools import parse_url

router = APIRouter(prefix="/api", tags=["reports"])

_UNAVAILABLE = AppError("SERVICE_UNAVAILABLE", "Community reports are temporarily unavailable.", 503)


@router.post("/report", response_model=ReportCreated, status_code=201,
             responses={409: {"model": ErrorResponse}, 422: {"model": ErrorResponse},
                        429: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
             dependencies=[Depends(report_rate_limit)])
async def submit_report(body: ReportRequest, request: Request) -> ReportCreated:
    st = request.app.state
    # Syntax-only validation: reporting never fetches the URL, and dead domains are valid reports.
    parsed = parse_url(body.url)
    reporter = st.supabase.hash_reporter(client_ip(request, st.settings))
    try:
        return await st.supabase.add_report(normalized_url=parsed.normalized, category=body.category,
                                            description=body.description, reporter_hash=reporter)
    except DuplicateReport:
        summary = None
        try:
            summary = await st.supabase.get_summary(parsed.normalized)
        except SupabaseUnavailable:
            pass
        raise AppError("DUPLICATE_REPORT", "You've already reported this website. Thank you!", 409,
                       {"report_count": summary.report_count if summary else None}) from None
    except SupabaseUnavailable:
        raise _UNAVAILABLE from None


@router.get("/reports", response_model=ReportList,
            responses={422: {"model": ErrorResponse}, 503: {"model": ErrorResponse}})
async def list_reports(request: Request,
                       limit: int = Query(20, ge=1, le=100),
                       offset: int = Query(0, ge=0),
                       url: str | None = Query(None, max_length=2048, description="Only reports for this URL")) -> ReportList:
    st = request.app.state
    normalized = parse_url(url).normalized if url else None
    try:
        return await st.supabase.list_summaries(limit=limit, offset=offset, normalized_url=normalized)
    except SupabaseUnavailable:
        raise _UNAVAILABLE from None
