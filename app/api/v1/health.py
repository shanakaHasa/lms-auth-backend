"""Liveness and readiness.

The split matters. `/healthz` answers "is this process alive" and must never
touch a dependency — otherwise a brief database blip makes the load balancer
kill containers that were about to recover. `/readyz` answers "can this process
serve traffic" and does check dependencies.
"""

from __future__ import annotations

from fastapi import APIRouter, Response
from pydantic import BaseModel
from sqlalchemy import text

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.logging import get_logger

router = APIRouter(tags=["health"])
log = get_logger(__name__)

VERSION = "0.1.0"


class HealthResponse(BaseModel):
    status: str
    version: str
    service: str
    checks: dict[str, str] = {}


@router.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    return HealthResponse(status="ok", version=VERSION, service=settings.service_name)


@router.get("/readyz", response_model=HealthResponse)
async def readyz(response: Response) -> HealthResponse:
    checks: dict[str, str] = {}

    try:
        async with SessionLocal() as session:
            await session.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as exc:
        log.warning("readiness_check_failed", dependency="postgres", error=str(exc))
        checks["postgres"] = "error"

    # Signing keys are checked here from Step 4 onward: without usable key
    # material this service cannot issue a token, so it is not ready.
    checks["signer"] = settings.signer_backend

    healthy = checks["postgres"] == "ok"
    if not healthy:
        response.status_code = 503
    return HealthResponse(
        status="ok" if healthy else "degraded",
        version=VERSION,
        service=settings.service_name,
        checks=checks,
    )
