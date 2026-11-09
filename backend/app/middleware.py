"""
app/middleware.py
* request-id middleware (ties client errors to server logs)
* in-memory sliding-window rate limiter (per client IP) used as a route dependency

The limiter is per-process: fine for a hackathon single instance. For several
instances, move it to Redis or the platform's edge rate limiting.
"""
from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict, deque

from fastapi import Request
from starlette.responses import Response

from app.config import Settings
from app.errors import AppError, error_response

log = logging.getLogger("veridion.http")


async def request_context_middleware(request: Request, call_next) -> Response:
    request.state.request_id = f"req_{uuid.uuid4().hex[:12]}"
    try:
        response = await call_next(request)
    except Exception:  # noqa: BLE001
        # Handled here (inside CORS) so even 500s carry CORS headers and the envelope.
        log.exception("Unhandled error request_id=%s path=%s", request.state.request_id, request.url.path)
        response = error_response(request, "INTERNAL_ERROR",
                                  "Something went wrong on our side. Please try again.", 500)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


def client_ip(request: Request, settings: Settings) -> str:
    if settings.trust_proxy_headers:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            # The RIGHTMOST entry is the one appended by our own proxy; earlier ones are client-controlled.
            return xff.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


class SlidingWindowLimiter:
    def __init__(self, limit_attr: str, window_s: int = 60) -> None:
        self._limit_attr = limit_attr
        self._window = window_s
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def __call__(self, request: Request) -> None:
        settings: Settings = request.app.state.settings
        limit = getattr(settings, self._limit_attr)
        ip = client_ip(request, settings)
        now = time.monotonic()
        hits = self._hits[ip]
        while hits and now - hits[0] > self._window:
            hits.popleft()
        if len(hits) >= limit:
            retry = max(1, int(self._window - (now - hits[0])) + 1)
            raise AppError("RATE_LIMITED", "Too many requests. Please wait a moment and try again.", 429,
                           {"retry_after_seconds": retry}, {"Retry-After": str(retry)})
        hits.append(now)
        if len(self._hits) > 10_000:  # opportunistic cleanup so the dict can't grow without bound
            for key in [k for k, v in self._hits.items() if not v or now - v[-1] > self._window]:
                del self._hits[key]


scan_rate_limit = SlidingWindowLimiter("rate_limit_scan_per_min")
report_rate_limit = SlidingWindowLimiter("rate_limit_report_per_min")
