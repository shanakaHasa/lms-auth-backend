"""Signing-key persistence. Global — keys belong to the service, not a tenant.

The state machine lives in the `status` column: `pending` → `active` →
`retiring` → `revoked`. Two queries matter and they are deliberately different:

* `stmt_active_key` finds the **one** key that may sign. A partial unique index
  guarantees there is at most one, so this cannot silently pick between two.
* `stmt_published_keys` finds everything that goes in JWKS — which is *wider*,
  because a key must be published before it signs and must stay published after
  it stops. A consumer holding a cached JWKS needs the old key to verify tokens
  already in flight, and the new key to be there before the first token signed
  with it arrives.

Getting that wider set wrong is the classic rotation outage: publish only the
active key and every token minted in the previous window fails to verify.
"""

from __future__ import annotations

from typing import Protocol

from sqlalchemy import ColumnElement, Select, select

from app.models.signing_key import SigningKey
from app.repositories.base import GlobalRepository

__all__ = [
    "PUBLISHED_STATUSES",
    "SigningKeyRepository",
    "SqlSigningKeyRepository",
    "stmt_active_key",
    "stmt_key_by_kid",
    "stmt_published_keys",
]

# Everything a consumer might legitimately need to verify a token it holds.
# `revoked` is absent: that is the state for a key believed compromised, and
# continuing to publish it would defeat the point of revoking it.
PUBLISHED_STATUSES = ("pending", "active", "retiring")


def stmt_active_key() -> Select[tuple[SigningKey]]:
    return select(SigningKey).where(SigningKey.status == "active")


def stmt_published_keys() -> Select[tuple[SigningKey]]:
    clauses: list[ColumnElement[bool]] = [SigningKey.status.in_(PUBLISHED_STATUSES)]
    return (
        select(SigningKey)
        .where(*clauses)
        # Active first, so a consumer that takes the first usable key meets the
        # one currently signing. Backend looks up by `kid`, so this is a
        # courtesy — but other clients are less careful.
        .order_by(SigningKey.status.desc(), SigningKey.created_at.desc())
    )


def stmt_key_by_kid(kid: str) -> Select[tuple[SigningKey]]:
    return select(SigningKey).where(SigningKey.kid == kid)


class SigningKeyRepository(Protocol):
    async def active(self) -> SigningKey | None: ...

    async def published(self) -> list[SigningKey]: ...

    async def by_kid(self, kid: str) -> SigningKey | None: ...

    async def add(self, key: SigningKey) -> SigningKey: ...

    async def touch(self, key: SigningKey) -> SigningKey: ...


class SqlSigningKeyRepository(GlobalRepository):
    async def active(self) -> SigningKey | None:
        result = await self.session.execute(stmt_active_key())
        return result.scalar_one_or_none()

    async def published(self) -> list[SigningKey]:
        result = await self.session.execute(stmt_published_keys())
        return list(result.scalars())

    async def by_kid(self, kid: str) -> SigningKey | None:
        result = await self.session.execute(stmt_key_by_kid(kid))
        return result.scalar_one_or_none()

    async def add(self, key: SigningKey) -> SigningKey:
        return await self.flush(key)  # type: ignore[return-value]

    async def touch(self, key: SigningKey) -> SigningKey:
        return await self.flush(key)  # type: ignore[return-value]
