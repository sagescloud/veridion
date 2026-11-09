"""app/routes/health.py: GET /api/health"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
async def health(request: Request, deep: bool = False):
    """Shallow by default (cheap, for platform health checks). `?deep=true` also pings Supabase."""
    st = request.app.state
    body = {"status": "ok", "version": st.settings.app_version,
            "time": datetime.now(timezone.utc).replace(microsecond=0).isoformat()}
    if deep:
        if not st.supabase.configured:
            body["supabase"] = "unconfigured"
        else:
            try:
                await asyncio.wait_for(st.supabase.ping(), timeout=3)
                body["supabase"] = "ok"
            except Exception:  # noqa: BLE001
                body["supabase"] = "unavailable"
                body["status"] = "degraded"
    return body
