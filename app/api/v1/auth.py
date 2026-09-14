"""Login.

There is no scope check here, and that is not an omission: this endpoint has no
principal, because it is the thing that creates one. Its gate is the credential
check itself. Saying so explicitly, because a missing `require()` in a service
is otherwise the kind of thing someone later "fixes".
"""

from __future__ import annotations

from fastapi import APIRouter, status

from app.core.deps import LoginServiceDep
from app.schemas.token import LoginRequest, MePreview, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/login",
    response_model=dict,
    status_code=status.HTTP_200_OK,
    summary="Exchange an email, password and institution for an access token",
    description=(
        "Every failure returns an identical 401 — unknown institution, unknown "
        "user, wrong password, never activated and disabled are deliberately "
        "indistinguishable, because a client that could tell them apart could "
        "enumerate which addresses are registered. The real reason is written "
        "to the audit log and never returned."
    ),
    responses={401: {"description": "invalid email, password, or institution"}},
)
async def login(payload: LoginRequest, service: LoginServiceDep) -> dict:
    result = await service.login(payload)
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
