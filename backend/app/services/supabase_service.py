"""
app/services/supabase_service.py
All database access (community reports + scan persistence) lives here.

* Uses the supabase-py SYNC client inside `asyncio.to_thread`, so the event loop is never blocked.
* Uses the SERVICE ROLE key (server only). RLS is enabled with no policies, so the public
  anon key can read/write nothing. See supabase/schema.sql.
* If Supabase isn't configured the app still boots: scans work, report endpoints answer 503.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
from typing import Any

from app.config import Settings
from app.models.report import CommunityIntel, ReportCreated, ReportList, ReportSummary
from app.models.scan import ScanReport

log = logging.getLogger("veridion.supabase")


class DuplicateReport(Exception):
    """This reporter already reported this URL."""


class SupabaseUnavailable(Exception):
    """Not configured, or the database could not be reached."""


def _is_unique_violation(exc: Exception) -> bool:
    return getattr(exc, "code", None) == "23505" or "23505" in str(exc) or "duplicate key" in str(exc).lower()


class SupabaseService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: Any = None

    @property
    def configured(self) -> bool:
        return self._settings.supabase_configured

    def _db(self) -> Any:
        if not self.configured:
            raise SupabaseUnavailable("Supabase is not configured")
        if self._client is None:
            from supabase import create_client  # imported lazily so the app boots without it
            self._client = create_client(self._settings.supabase_url, self._settings.supabase_service_role_key)
        return self._client

    # ----- helpers --------------------------------------------------------
    def hash_reporter(self, client_ip: str) -> str:
        """HMAC of the reporter IP: lets us de-duplicate without storing personal data."""
        return hmac.new(self._settings.report_hash_salt.encode(), client_ip.encode(), hashlib.sha256).hexdigest()

    async def _run(self, fn):
        try:
            return await asyncio.to_thread(fn)
        except SupabaseUnavailable:
            raise
        except Exception as exc:
            if _is_unique_violation(exc):
                raise
            log.exception("supabase call failed")
            raise SupabaseUnavailable(str(exc)) from exc

    # ----- community reports ---------------------------------------------
    async def add_report(self, *, normalized_url: str, category: str, description: str | None,
                         reporter_hash: str) -> ReportCreated:
        row = {"normalized_url": normalized_url, "category": category,
               "description": description, "reporter_hash": reporter_hash}

        def insert() -> dict:
            return self._db().table("community_reports").insert(row).execute().data[0]

        try:
            created = await self._run(insert)
        except SupabaseUnavailable:
            raise
        except Exception as exc:  # unique violation re-raised by _run
            if _is_unique_violation(exc):
                raise DuplicateReport() from exc
            raise

        summary = await self.get_summary(normalized_url)
        return ReportCreated(report_id=str(created["id"]), normalized_url=normalized_url,
                             report_count=summary.report_count if summary else 1,
                             created_at=created["created_at"])

    async def get_summary(self, normalized_url: str) -> ReportSummary | None:
        def query() -> list[dict]:
            return (self._db().table("community_report_summary").select("*")
                    .eq("normalized_url", normalized_url).limit(1).execute().data)
        rows = await self._run(query)
        return ReportSummary(**rows[0]) if rows else None

    async def community_intel(self, normalized_url: str) -> CommunityIntel | None:
        """Used by the scan orchestrator. None means 'could not check' (not 'not reported')."""
        if not self.configured:
            return None
        summary = await self.get_summary(normalized_url)
        if summary is None:
            return CommunityIntel(reported=False)
        return CommunityIntel(reported=True, report_count=summary.report_count,
                              first_reported_at=summary.first_reported_at,
                              last_reported_at=summary.last_reported_at, categories=summary.categories)

    async def list_summaries(self, *, limit: int, offset: int, normalized_url: str | None = None) -> ReportList:
        def query() -> tuple[list[dict], int]:
            q = self._db().table("community_report_summary").select("*", count="exact")
            if normalized_url:
                q = q.eq("normalized_url", normalized_url)
            res = q.order("last_reported_at", desc=True).range(offset, offset + limit - 1).execute()
            return res.data, (res.count if res.count is not None else len(res.data))
        rows, total = await self._run(query)
        return ReportList(reports=[ReportSummary(**r) for r in rows], total=total, limit=limit, offset=offset)

    # ----- scan persistence (best effort) ---------------------------------
    async def save_scan(self, report: ScanReport) -> None:
        if not self.configured:
            return
        row = {"scan_id": report.scan_id, "normalized_url": report.normalized_url,
               "risk_score": report.overall.risk_score, "classification": report.overall.classification,
               "report": report.model_dump(mode="json")}
        await self._run(lambda: self._db().table("scans").upsert(row).execute())

    async def get_scan(self, scan_id: str) -> ScanReport | None:
        if not self.configured:
            return None
        rows = await self._run(lambda: self._db().table("scans").select("report")
                               .eq("scan_id", scan_id).limit(1).execute().data)
        return ScanReport.model_validate(rows[0]["report"]) if rows else None

    # ----- health ---------------------------------------------------------
    async def ping(self) -> bool:
        await self._run(lambda: self._db().table("community_reports").select("id").limit(1).execute())
        return True
