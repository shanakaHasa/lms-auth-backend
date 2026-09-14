"""Cross-cutting HTTP middleware: request correlation, access logs, security headers."""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.logging import clear_request_context, get_logger, request_id_ctx

log = get_logger("http")

# Health checks would otherwise dominate log volume and the CloudWatch bill.
QUIET_PATHS = frozenset({"/healthz", "/readyz", "/metrics"})

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    # This service returns JSON only; it never needs to load anything.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Honour an upstream ALB/X-Ray id so traces join up across services.
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        request_id_ctx.set(request_id)

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.exception(
                "request_failed",
                method=request.method,
                path=request.url.path,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            raise
        finally:
            # Clear on the way out, including on the error path: contextvars
            # outlive the request on a reused worker task, so a stale tenant_id
            # would otherwise attach itself to the next request's log lines.
            clear_request_context()

        # request_id was cleared above, so use the local we captured.
        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["x-request-id"] = request_id
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if settings.cookie_secure:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains; preload",
            )
        # Nothing this service returns is cacheable, and tokens least of all --
        # with one exception. The discovery endpoints publish public key
        # material and set their own `Cache-Control`, and a consumer that cannot
        # cache JWKS refetches on every unknown `kid`. Plain assignment here
        # would overwrite that, and the key-rotation rule ("publish for twice
        # the cache TTL before signing") would rest on a header nobody received.
        if not request.url.path.startswith("/.well-known/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"

        if request.url.path not in QUIET_PATHS:
            log.info(
                "request",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=round(elapsed_ms, 2),
            )
        return response


def install_middleware(app: FastAPI) -> None:
    app.add_middleware(RequestContextMiddleware)
