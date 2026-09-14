"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import health
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.db import engine
from app.core.errors import install_error_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import install_middleware

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    configure_logging(settings.log_level, json_output=not settings.is_local)
    log.info(
        "starting",
        service=settings.service_name,
        env=settings.app_env,
        issuer=settings.issuer,
        signer=settings.signer_backend,
    )
    yield
    await engine.dispose()
    log.info("stopped")


def create_app() -> FastAPI:
    app = FastAPI(
        title="TeachAssist Auth",
        version="0.1.0",
        description="Identity provider: users, tenants, roles, RS256 tokens, JWKS",
        lifespan=lifespan,
        # The schema names every credential-bearing route; don't publish it in prod.
        docs_url=None if settings.app_env == "prod" else "/docs",
        redoc_url=None,
        openapi_url=None if settings.app_env == "prod" else "/openapi.json",
    )

    # Exact origins, never a regex. An over-broad origin pattern combined with
    # allow_credentials is the classic CORS hole.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["authorization", "content-type", "x-request-id", "x-csrf-token"],
        expose_headers=["x-request-id"],
    )
    install_middleware(app)
    install_error_handlers(app)

    app.include_router(health.router)
    app.include_router(api_router)
    return app


app = create_app()
