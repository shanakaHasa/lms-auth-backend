"""Refresh-token persistence, and the one statement that decides a race.

`stmt_redeem` is the whole of reuse detection:

    UPDATE refresh_tokens SET used_at = :now
     WHERE id = :id AND used_at IS NULL
    RETURNING *

**The row count is the outcome.** One row back means this caller redeemed the
token; zero rows means somebody else already did, or it never existed. Postgres
decides, under a row lock, and there is no window between the check and the
write for a second caller to slip into.

The tempting alternative — `SELECT`, look at `used_at`, then `UPDATE` — races.
And the race is indistinguishable from theft: two callers both see `used_at IS
NULL`, both proceed, and the second redemption looks exactly like an attacker
replaying a stolen token. Since the response to theft is revoking the whole
family, the bug does not present as a race. It presents as users being
spontaneously logged out, which is very hard to trace back to a missing lock.

**There is deliberately no `get_by_hash` and no `get_by_id` for the happy
path.** Not an oversight: if this module offered one, check-then-update becomes
writable, and the guarantee above becomes a convention. The only lookup
provided, `stmt_find_used`, is reachable *after* redemption has already failed,
where there is no longer a race to lose.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from sqlalchemy import Select, Update, select, update

from app.models.refresh_token import RefreshToken
from app.repositories.base import GlobalRepository

__all__ = [
    "RefreshTokenRepository",
    "SqlRefreshTokenRepository",
    "stmt_find_used",
    "stmt_redeem",
    "stmt_revoke_family",
]


def stmt_redeem(token_id: uuid.UUID, now: datetime) -> Update:
    """Claim a token. At most one caller can win."""
    return (
        update(RefreshToken)
        .where(
            RefreshToken.id == token_id,
            # The entire race condition, in one predicate.
            RefreshToken.used_at.is_(None),
            RefreshToken.revoked_at.is_(None),
        )
        .values(used_at=now)
        .returning(RefreshToken)
    )


def stmt_find_used(token_id: uuid.UUID) -> Select[tuple[RefreshToken]]:
    """Only reachable once redemption has already failed.

    At that point the row is settled — used or revoked — so reading it cannot
    lose a race it has already lost.
    """
    return select(RefreshToken).where(RefreshToken.id == token_id)


def stmt_revoke_family(family_id: uuid.UUID, now: datetime, reason: str) -> Update:
    """Kill every token in a rotation chain.

    Reuse means one token in the family is in someone else's hands, and there is
    no way to tell which of the two presenters is the legitimate one. Revoking
    the family logs both out, which is the correct response: the real user can
    sign in again, the attacker cannot.
    """
    return (
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now, revoked_reason=reason)
    )


def stmt_revoke_family_for_user(user_id: uuid.UUID, now: datetime, reason: str) -> Update:
    """Every live token for a user — logout-everywhere, and disable."""
    return (
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now, revoked_reason=reason)
    )


class RefreshTokenRepository(Protocol):
    async def redeem(self, token_id: uuid.UUID, now: datetime) -> RefreshToken | None: ...

    async def find_used(self, token_id: uuid.UUID) -> RefreshToken | None: ...

    async def revoke_family(self, family_id: uuid.UUID, now: datetime, reason: str) -> int: ...

    async def revoke_for_user(self, user_id: uuid.UUID, now: datetime, reason: str) -> int: ...

    async def add(self, token: RefreshToken) -> RefreshToken: ...


class SqlRefreshTokenRepository(GlobalRepository):
    async def redeem(self, token_id: uuid.UUID, now: datetime) -> RefreshToken | None:
        result = await self.session.execute(stmt_redeem(token_id, now))
        return result.scalar_one_or_none()

    async def find_used(self, token_id: uuid.UUID) -> RefreshToken | None:
        result = await self.session.execute(stmt_find_used(token_id))
        return result.scalar_one_or_none()

    async def revoke_family(self, family_id: uuid.UUID, now: datetime, reason: str) -> int:
        result = await self.session.execute(stmt_revoke_family(family_id, now, reason))
        return int(getattr(result, "rowcount", 0) or 0)

    async def revoke_for_user(self, user_id: uuid.UUID, now: datetime, reason: str) -> int:
        result = await self.session.execute(stmt_revoke_family_for_user(user_id, now, reason))
        return int(getattr(result, "rowcount", 0) or 0)

    async def add(self, token: RefreshToken) -> RefreshToken:
        return await self.flush(token)  # type: ignore[return-value]
