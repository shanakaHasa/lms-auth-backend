"""Minting access tokens.

Split into a pure claim builder and a thin signer wrapper, deliberately. Every
contract risk lives in `build_access_claims` — the claim names, the `scope`
encoding, the `tid` being a UUID — and that function needs no key, no database
and no clock it does not receive. So the part that can silently break the
consumer is the part that is completely testable.

The signer arrives at construction as a `Signer` **protocol instance**, never a
module global. That is what stops a temporary "just sign with this key" path
outliving its temporariness, and it is what lets Azure Key Vault drop in later
without this file changing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.crypto.signer import Signer, encode_jws
from app.schemas.token import AccessClaims, encode_scope

__all__ = ["TokenService", "build_access_claims"]


def build_access_claims(
    *,
    issuer: str,
    audience: str,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    tenant_slug: str,
    email: str,
    scopes: frozenset[str],
    token_version: int,
    session_id: str,
    ttl_seconds: int,
    now: datetime | None = None,
) -> AccessClaims:
    """Pure. No key, no database, no ambient clock.

    `now` is injectable so the expiry arithmetic is testable at a boundary
    rather than approximately.
    """
    issued = now or datetime.now(UTC)
    iat = int(issued.timestamp())

    return AccessClaims(
        # Compared byte-for-byte by the consumer, so it must not carry a
        # trailing slash. `settings.issuer` is normalised for exactly this.
        iss=issuer,
        aud=audience,
        sub=str(user_id),
        # The tenant UUID, never the slug: backend keys every row on this.
        tid=str(tenant_id),
        # The slug rides along for display. It is renameable, so nothing may
        # key on it — which is why it is a separate claim rather than `tid`.
        tsl=tenant_slug,
        scope=encode_scope(scopes),
        # Checked by the consumer. A refresh or M2M token reaching a user-facing
        # endpoint must be rejected on this alone.
        token_use="access",  # noqa: S106 -- a claim value, not a credential
        sid=session_id,
        # The revocation predicate that does not need clock agreement: a
        # consumer rejects any token whose `tv` is behind the user's current
        # value. Nothing consumes it yet -- see Step 10.
        tv=token_version,
        jti=str(uuid.uuid4()),
        iat=iat,
        nbf=iat,
        exp=iat + ttl_seconds,
        email=email,
        ver=1,
    )


class TokenService:
    def __init__(
        self,
        signer: Signer,
        *,
        issuer: str,
        audience: str,
        ttl_seconds: int,
    ) -> None:
        self.signer = signer
        self.issuer = issuer
        self.audience = audience
        self.ttl_seconds = ttl_seconds

    def issue_access_token(
        self,
        *,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        tenant_slug: str,
        email: str,
        scopes: frozenset[str],
        token_version: int,
        session_id: str,
        now: datetime | None = None,
    ) -> tuple[str, AccessClaims]:
        claims = build_access_claims(
            issuer=self.issuer,
            audience=self.audience,
            user_id=user_id,
            tenant_id=tenant_id,
            tenant_slug=tenant_slug,
            email=email,
            scopes=scopes,
            token_version=token_version,
            session_id=session_id,
            ttl_seconds=self.ttl_seconds,
            now=now,
        )
        return encode_jws(dict(claims), self.signer), claims
