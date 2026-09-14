"""Typed application errors, mapped to HTTP responses in one place.

Two rules specific to an identity provider:

* `InvalidCredentials` carries a `reason` that goes to the audit log and
  **never** to the client. Unknown user, wrong password, disabled account and
  unknown tenant must be indistinguishable from outside, or the endpoint
  becomes a user-enumeration oracle.
* Every auth response is `Cache-Control: no-store`, applied in middleware, so a
  token can never sit in a proxy or the browser's back-forward cache.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.logging import get_logger, request_id_ctx

log = get_logger(__name__)


class AppError(Exception):
    status_code = 500
    code = "internal_error"

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


class NotFound(AppError):
    status_code = 404
    code = "not_found"


class Unauthorized(AppError):
    status_code = 401
    code = "unauthorized"


class Forbidden(AppError):
    status_code = 403
    code = "forbidden"


class Conflict(AppError):
    status_code = 409
    code = "conflict"


class ValidationFailed(AppError):
    status_code = 422
    code = "validation_failed"


class RateLimited(AppError):
    status_code = 429
    code = "rate_limited"

    def __init__(self, message: str, *, retry_after: int) -> None:
        super().__init__(message, detail={"retry_after": retry_after})
        self.retry_after = retry_after


class InvalidCredentials(AppError):
    """Deliberately opaque. `reason` is for the audit log only.

    Constructing this with a specific reason and then returning a generic body
    is the whole point: the distinction is recorded, never disclosed.
    """

    status_code = 401
    code = "invalid_credentials"
    PUBLIC_MESSAGE = "Invalid credentials."

    def __init__(self, reason: str) -> None:
        super().__init__(self.PUBLIC_MESSAGE)
        self.reason = reason


class InvalidGrant(AppError):
    """OAuth2 `invalid_grant` — a bad or replayed refresh token.

    The frontend treats this, and only this, as "clear the session". A 5xx must
    not log the user out, or a brief auth blip signs everyone out at once.
    """

    status_code = 401
    code = "invalid_grant"


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(InvalidCredentials)
    async def _invalid_credentials(_r: Request, exc: InvalidCredentials) -> JSONResponse:
        # The reason is logged; the response body is identical every time.
        log.info("login_failed", reason=exc.reason)
        return JSONResponse(
            status_code=401,
            content={
                "error": {"code": exc.code, "message": exc.PUBLIC_MESSAGE},
                "request_id": request_id_ctx.get(),
            },
        )

    @app.exception_handler(RateLimited)
    async def _rate_limited(_r: Request, exc: RateLimited) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(exc.retry_after)},
            content={
                "error": {"code": exc.code, "message": exc.message},
                "request_id": request_id_ctx.get(),
            },
        )

    @app.exception_handler(AppError)
    async def _app_error(_r: Request, exc: AppError) -> JSONResponse:
        log.warning("app_error", code=exc.code, message=exc.message, **exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {"code": exc.code, "message": exc.message, **exc.detail},
                "request_id": request_id_ctx.get(),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> Any:
        # Pydantic echoes the offending input by default, which for a login body
        # means the password ends up in the response and the access log.
        log.info("request_validation_failed", path=request.url.path)
        if request.url.path.startswith("/api/v1/auth") or request.url.path.startswith(
            "/api/v1/oauth"
        ):
            return JSONResponse(
                status_code=422,
                content={
                    "error": {"code": "validation_failed", "message": "Invalid request."},
                    "request_id": request_id_ctx.get(),
                },
            )
        return await request_validation_exception_handler(request, exc)

    @app.exception_handler(Exception)
    async def _unhandled(_r: Request, exc: Exception) -> JSONResponse:
        # Never leak internals. The request_id ties this to the stack trace.
        log.exception("unhandled_exception", error=str(exc))
        return JSONResponse(
            status_code=500,
            content={
                "error": {"code": "internal_error", "message": "Internal server error"},
                "request_id": request_id_ctx.get(),
            },
        )
