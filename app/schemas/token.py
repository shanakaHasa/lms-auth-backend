"""The access-token claim set, and the one encoding that must not drift.

`scope` is a **space-delimited string**, singular. Not a list, not `scopes`, not
`scp`. The consumer does exactly this, at `backend/app/core/security.py:219`:

    frozenset(str(claims.get("scope", "")).split())

If this service ever emitted a JSON array, `str(["a","b"])` is `"['a', 'b']"`
and `.split()` yields `["['a',", "'b']"]` — a **non-empty** frozenset of
garbage. So `require()` raises "missing required scope" and every teacher gets a
403 that reads like a permissions bug rather than a format bug. Nothing errors.
Nothing logs. It just quietly does not work.

That failure mode is why the encoding lives in one function, why `AccessClaims`
types `scope` as `str` so mypy refuses a list before any test runs, and why
`test_token_service.py` copies the consumer's expression verbatim rather than
round-tripping through our own decoder.

`tid` is the tenant **UUID**, never the slug. Backend puts it straight into
`Principal.tenant_id` and keys every row it writes on it — a renameable value
there would be unrecoverable.
"""

from __future__ import annotations

import uuid
from typing import Literal, TypedDict

from pydantic import BaseModel, ConfigDict, EmailStr, Field

__all__ = [
    "AccessClaims",
    "LoginRequest",
    "TokenResponse",
    "decode_scope",
    "encode_scope",
]


def encode_scope(scopes: frozenset[str] | set[str] | list[str]) -> str:
    """The only place a `scope` claim is built.

    Sorted and deduplicated, which is not cosmetic: it makes the claim
    deterministic, which is what lets the contract fixtures be byte-stable —
    and a fixture pack that produced a spurious diff on every regeneration
    would simply stop being regenerated.
    """
    return " ".join(sorted(set(scopes)))


def decode_scope(scope: str) -> frozenset[str]:
    return frozenset(scope.split())


class AccessClaims(TypedDict):
    """Every claim in an access token.

    Typed so `scope: str` is enforced by mypy — the earliest and cheapest place
    to catch the drift described above.
    """

    iss: str
    aud: str
    sub: str
    tid: str
    tsl: str
    scope: str
    token_use: Literal["access"]
    sid: str
    tv: int
    jti: str
    iat: int
    nbf: int
    exp: int
    email: str
    ver: int


class LoginRequest(BaseModel):
    """Email, password and the institution.

    The tenant slug is required rather than inferred. The same address can
    legitimately exist at two institutions — `uq_users_tenant_email` is per
    tenant precisely so a tutor can work at both — so without it the service
    would have to guess which account is meant.
    """

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)
    tenant_slug: str = Field(min_length=1, max_length=64)


class TokenResponse(BaseModel):
    """OAuth2-shaped, so ordinary clients understand it without special-casing."""

    access_token: str
    # S105: "Bearer" is RFC 6750's token type, not a credential.
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105
    expires_in: int
    scope: str


class MePreview(BaseModel):
    """Who the token belongs to, returned alongside it as a convenience.

    Saves the frontend an immediate second call just to render a name. It is
    *not* authorization — the token is.
    """

    model_config = ConfigDict(from_attributes=True)

    user_id: uuid.UUID
    email: str
    full_name: str | None
    tenant_slug: str
    scopes: list[str]
