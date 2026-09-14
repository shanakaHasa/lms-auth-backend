"""FastAPI dependencies: the seam between HTTP and the service layer.

Routers depend on these; services depend on nothing from FastAPI. That split is
what lets the CLI drive exactly the same code the HTTP API does — `seed-dev`
already does.

One asymmetry worth naming. Most services here will eventually be built from a
verified principal's tenant. **Login cannot be**, because it resolves a tenant
*slug* from an unauthenticated request — it is the thing that creates a
principal, so there is none to build from. `get_login_service` therefore takes
the session and resolves the tenant itself.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal, get_session
from app.core.logging import get_logger
from app.crypto.keywrap import resolve_kek
from app.repositories.refresh_token import SqlRefreshTokenRepository
from app.repositories.role import SqlRoleRepository
from app.repositories.signing_key import SqlSigningKeyRepository
from app.repositories.tenant import SqlTenantRepository
from app.repositories.user import SqlUserRepository
from app.services.audit import SqlAuditSink
from app.services.audit_independent import IndependentAuditSink
from app.services.key_service import KeyService
from app.services.login_service import LoginService
from app.services.password_service import get_password_service
from app.services.refresh_service import RefreshService
from app.services.token_service import TokenService

log = get_logger(__name__)

DbSession = Annotated[AsyncSession, Depends(get_session)]


def get_key_service(session: DbSession) -> KeyService:
    return KeyService(
        SqlSigningKeyRepository(session),
        SqlAuditSink(session),
        kek=resolve_kek(),
        # Twice the JWKS cache TTL: a consumer may have fetched one microsecond
        # before a key was published and will serve that copy for a full TTL.
        min_publish_delay_seconds=max(
            settings.key_min_publish_delay_seconds, settings.jwks_cache_ttl_seconds * 2
        ),
    )


KeyServiceDep = Annotated[KeyService, Depends(get_key_service)]


async def get_login_service(session: DbSession) -> LoginService:
    """Built from the session, not from a principal — login has none.

    The signer is loaded per request rather than cached, so promoting a new key
    takes effect on the next login rather than on the next restart. At one
    database read per login that is a fair price for not needing a deploy to
    finish a rotation.
    """
    keys = get_key_service(session)
    tokens = TokenService(
        await keys.active_signer(),
        issuer=settings.issuer,
        audience=settings.audience,
        ttl_seconds=settings.access_token_ttl_seconds,
    )
    return LoginService(
        SqlTenantRepository(session),
        lambda tenant_id: SqlUserRepository(session, tenant_id),
        lambda tenant_id: SqlRoleRepository(session, tenant_id),
        get_password_service(),
        tokens,
        SqlAuditSink(session),
        IndependentAuditSink(SessionLocal),
    )


LoginServiceDep = Annotated[LoginService, Depends(get_login_service)]


async def get_refresh_service(session: DbSession) -> RefreshService:
    """Shares the request's session, so rotation and its audit row commit together.

    A refresh that issued a new token but lost the row recording the old one as
    used would silently disable reuse detection for that family.
    """
    keys = get_key_service(session)
    tokens = TokenService(
        await keys.active_signer(),
        issuer=settings.issuer,
        audience=settings.audience,
        ttl_seconds=settings.access_token_ttl_seconds,
    )
    return RefreshService(
        SqlRefreshTokenRepository(session),
        SqlTenantRepository(session),
        lambda tenant_id: SqlUserRepository(session, tenant_id),
        lambda tenant_id: SqlRoleRepository(session, tenant_id),
        tokens,
        SqlAuditSink(session),
        SessionLocal,
        idle_ttl_seconds=settings.refresh_idle_ttl_seconds,
        absolute_ttl_seconds=settings.refresh_absolute_ttl_seconds,
        grace_seconds=settings.refresh_grace_seconds,
    )


RefreshServiceDep = Annotated[RefreshService, Depends(get_refresh_service)]
