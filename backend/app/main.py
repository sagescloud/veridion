"""
app/main.py
Application factory + lifecycle. Run with:  uvicorn app.main:app --reload
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import Settings, get_settings
from app.errors import register_exception_handlers
from app.middleware import request_context_middleware
from app.routes import health, reports, scan
from app.services.scan_store import ScanStore
from app.services.supabase_service import SupabaseService
from app.utils.ssrf_guard import build_guarded_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("veridion")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # One shared, SSRF-guarded HTTP client for the whole process (connection reuse).
        app.state.settings = settings
        app.state.http = build_guarded_client(settings, verify_tls=True)
        app.state.supabase = SupabaseService(settings)
        app.state.scan_store = ScanStore()
        app.state.scan_semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
        if not settings.supabase_configured:
            log.warning("Supabase not configured: community reports disabled, scans are not persisted")
        yield
        await app.state.http.aclose()

    app = FastAPI(
        title="Veridion API", version=settings.app_version, lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None, openapi_url=None if settings.is_production else "/openapi.json",
    )

    # Order matters: the LAST middleware added is the OUTERMOST. CORS must wrap
    # the request-context middleware so error responses still get CORS headers.
    app.middleware("http")(request_context_middleware)
    app.add_middleware(
        CORSMiddleware, allow_origins=settings.cors_origin_list, allow_credentials=False,
        allow_methods=["GET", "POST"], allow_headers=["Content-Type"], expose_headers=["X-Request-ID", "Retry-After"],
    )

    register_exception_handlers(app)
    app.include_router(health.router)
    app.include_router(scan.router)
    app.include_router(reports.router)
    return app


app = create_app()
