"""Login, refresh and logout.

None of these check a scope, and that is not an omission. Login and refresh have
no principal — they are the things that *create* one — so their gate is the
credential itself. Saying so here, because a missing `require()` in a service is
otherwise exactly the kind of thing someone later "fixes".

The access token comes back in the body; the refresh token only ever goes into
an httpOnly cookie. That split is the whole session design: the short-lived
credential lives in memory where a reload loses it, the long-lived one lives
where script cannot reach it at all.
"""

from __future__ import annotations

from fastapi import APIRouter, Cookie, Request, Response, status

from app.api.cookies import clear_refresh_cookie, set_refresh_cookie
from app.core.config import settings
from app.core.deps import LoginServiceDep, RefreshServiceDep
from app.core.errors import InvalidGrant
from app.schemas.token import LoginRequest, MePreview, TokenResponse
from app.services.refresh_service import RefreshContext

router = APIRouter(prefix="/auth", tags=["auth"])


def _context(request: Request) -> RefreshContext:
    # Soft binding only: a changed network raises suspicion, never rejects.
    # Hard binding causes mass false logouts the moment anyone moves between
    # wifi and mobile data.
    return RefreshContext(
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


@router.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="Exchange an email, password and institution for a session",
    description=(
        "Every failure returns an identical 401 — unknown institution, unknown "
        "user, wrong password, never activated and disabled are deliberately "
        "indistinguishable, because a client that could tell them apart could "
        "enumerate which addresses are registered. The real reason goes to the "
        "audit log and is never returned.\n\n"
        "Sets an httpOnly refresh cookie; the access token is in the body."
    ),
    responses={401: {"description": "invalid credentials"}},
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    service: LoginServiceDep,
    refresh: RefreshServiceDep,
) -> dict:
    result = await service.login(payload)

    refresh_token, _family = await refresh.issue_first(
        user_id=result.user.id,
        tenant_id=result.tenant_id,
        context=_context(request),
    )
    set_refresh_cookie(response, refresh_token, settings.refresh_absolute_ttl_seconds)

    return {
        "token": TokenResponse(
            access_token=result.token,
            expires_in=result.expires_in,
            scope=" ".join(sorted(result.scopes)),
        ).model_dump(),
        "user": MePreview(
            user_id=result.user.id,
            email=result.user.email,
            full_name=result.user.full_name,
            tenant_slug=payload.tenant_slug,
            scopes=sorted(result.scopes),
        ).model_dump(mode="json"),
    }


@router.post(
    "/refresh",
    status_code=status.HTTP_200_OK,
    summary="Rotate the session",
    description=(
        "Single-use: the presented token is consumed and a new one issued in "
        "the same family. Presenting an already-used token revokes the ENTIRE "
        "family and bumps `token_version`, because there is no way to tell "
        "which of the two holders is legitimate — so both are signed out.\n\n"
        "A re-presentation within the grace window from the same context is "
        "treated as two tabs racing rather than theft, and leaves the family "
        "intact."
    ),
    responses={401: {"description": "invalid or reused refresh token"}},
)
async def refresh_session(
    request: Request,
    response: Response,
    service: RefreshServiceDep,
    refresh_token: str | None = Cookie(default=None, alias=settings.refresh_cookie_name),
) -> dict:
    if not refresh_token:
        raise InvalidGrant("no refresh token")

    result = await service.rotate(refresh_token, _context(request))
    set_refresh_cookie(response, result.refresh_token, settings.refresh_absolute_ttl_seconds)

    return {
        "token": TokenResponse(
            access_token=result.access_token,
            expires_in=result.expires_in,
            scope=" ".join(sorted(result.scopes)),
        ).model_dump()
    }


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="End the session on this device",
    description=(
        "Revokes the whole rotation family and clears the cookie. Idempotent: "
        "a client that has already lost its token still gets a 204, because "
        "failing here would leave a cookie nobody can clear."
    ),
)
async def logout(
    response: Response,
    service: RefreshServiceDep,
    refresh_token: str | None = Cookie(default=None, alias=settings.refresh_cookie_name),
) -> Response:
    if refresh_token:
        await service.logout(refresh_token)
    clear_refresh_cookie(response)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
