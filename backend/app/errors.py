"""
app/errors.py
One error envelope for the whole API:
  {"error": {"code", "message", "details", "request_id"}}

FastAPI's defaults ({"detail": ...}) are replaced by the handlers below.
Rule: `message` is user-safe. Internal detail goes to the logs, never the client.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.utils.ssrf_guard import SSRFBlocked
from app.utils.url_tools import UrlError

log = logging.getLogger("veridion.errors")


class AppError(Exception):
    """Raise anywhere in a route/service to produce a clean envelope."""

    def __init__(self, code: str, message: str, status_code: int,
                 details: dict[str, Any] | None = None, headers: dict[str, str] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        self.headers = headers or {}


def request_id_of(request: Request) -> str:
    return getattr(request.state, "request_id", "req_unknown")


def error_response(request: Request, code: str, message: str, status_code: int,
                   details: dict[str, Any] | None = None,
                   headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        headers=headers,
        content={"error": {"code": code, "message": message, "details": details or {},
                           "request_id": request_id_of(request)}},
    )


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError):
        return error_response(request, exc.code, exc.message, exc.status_code, exc.details, exc.headers)

    @app.exception_handler(UrlError)
    async def _url_error(request: Request, exc: UrlError):
        return error_response(request, exc.code, exc.message, 422, {"field": "url"})

    @app.exception_handler(SSRFBlocked)
    async def _ssrf(request: Request, exc: SSRFBlocked):
        # The reason stays in the logs (ssrf_guard already logged it). The client
        # must learn nothing about our network or why the address was refused.
        return error_response(request, "BLOCKED_DESTINATION", "This address can't be scanned.", 422,
                              {"field": "url"})

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        fields = sorted({str(e["loc"][-1]) for e in exc.errors() if e.get("loc")})
        # Never echo user input back (exc.errors() contains it); only field names.
        if "url" in fields:
            return error_response(request, "INVALID_URL", "That doesn't look like a valid website address.",
                                  422, {"field": "url"})
        return error_response(request, "VALIDATION_ERROR", "Some of the information sent was not valid.",
                              422, {"fields": fields})

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        mapping = {404: ("NOT_FOUND", "That resource doesn't exist."),
                   405: ("METHOD_NOT_ALLOWED", "That method isn't supported here.")}
        if exc.status_code in mapping:
            code, msg = mapping[exc.status_code]
        elif exc.status_code >= 500:
            code, msg = "INTERNAL_ERROR", "Something went wrong on our side. Please try again."
        else:
            code, msg = "VALIDATION_ERROR", "The request could not be processed."
        return error_response(request, code, msg, exc.status_code)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        log.exception("Unhandled error request_id=%s", request_id_of(request))
        return error_response(request, "INTERNAL_ERROR",
                              "Something went wrong on our side. Please try again.", 500)
