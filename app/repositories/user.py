"""User persistence.

Every statement carries `tenant_id` and `deleted_at IS NULL`. The second is what
makes the partial unique index meaningful: a query that ignored `deleted_at`
would find the row the index deliberately excludes, and the two would disagree
about whether an address is in use.

One lookup here is unusual and deliberate: `stmt_user_for_login` does **not**
filter on status. Login must load a disabled or never-activated user and then
fail *after* doing the same work it would have done for an active one —
filtering them out in SQL would make the unknown-user and disabled-user paths
measurably different, which is the enumeration leak the whole login design
exists to avoid.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import ColumnElement, Select, func, or_, select

from app.models.user import User
from app.repositories.base import TenantScopedRepository

__all__ = [
    "SqlUserRepository",
    "UserRepository",
    "stmt_count_users",
    "stmt_get_user",
    "stmt_list_users",
    "stmt_user_by_email",
    "stmt_user_for_login",
]


def _live(tenant_id: uuid.UUID) -> list[ColumnElement[bool]]:
    return [User.tenant_id == tenant_id, User.deleted_at.is_(None)]


def stmt_get_user(tenant_id: uuid.UUID, user_id: uuid.UUID) -> Select[tuple[User]]:
    return select(User).where(*_live(tenant_id), User.id == user_id)


def stmt_user_by_email(tenant_id: uuid.UUID, email_normalized: str) -> Select[tuple[User]]:
    return select(User).where(*_live(tenant_id), User.email_normalized == email_normalized)


def stmt_user_for_login(tenant_id: uuid.UUID, email_normalized: str) -> Select[tuple[User]]:
    """The login lookup. Identical to `by_email` today, and named separately.

    The name exists so that nobody later "optimises" login by adding
    `status == 'active'` here. That would turn a disabled account into a faster
    401 than a wrong password, and response time alone would then reveal which
    addresses are real and which are still enabled.
    """
    return select(User).where(*_live(tenant_id), User.email_normalized == email_normalized)


def _filtered(
    tenant_id: uuid.UUID, status: str | None, query: str | None
) -> list[ColumnElement[bool]]:
    clauses = _live(tenant_id)
    if status:
        clauses.append(User.status == status)
    if query:
        pattern = f"%{query.strip()}%"
        clauses.append(or_(User.email_normalized.ilike(pattern), User.full_name.ilike(pattern)))
    return clauses


def stmt_list_users(
    tenant_id: uuid.UUID,
    *,
    limit: int,
    offset: int,
    status: str | None = None,
    query: str | None = None,
) -> Select[tuple[User]]:
    return (
        select(User)
        .where(*_filtered(tenant_id, status, query))
        # Total order, so two requests for the same offset cannot disagree.
        .order_by(User.email_normalized, User.id)
        .limit(limit)
        .offset(offset)
    )


def stmt_count_users(
    tenant_id: uuid.UUID, *, status: str | None = None, query: str | None = None
) -> Select[tuple[int]]:
    return select(func.count(User.id)).where(*_filtered(tenant_id, status, query))


class UserRepository(Protocol):
    tenant_id: uuid.UUID

    async def get(self, user_id: uuid.UUID) -> User | None: ...

    async def by_email(self, email_normalized: str) -> User | None: ...

    async def for_login(self, email_normalized: str) -> User | None: ...

    async def list(
        self,
        *,
        limit: int,
        offset: int,
        status: str | None = None,
        query: str | None = None,
    ) -> tuple[list[User], int]: ...

    async def add(self, user: User) -> User: ...

    async def touch(self, user: User) -> User: ...


class SqlUserRepository(TenantScopedRepository):
    async def get(self, user_id: uuid.UUID) -> User | None:
        result = await self.session.execute(stmt_get_user(self.tenant_id, user_id))
        return result.scalar_one_or_none()

    async def by_email(self, email_normalized: str) -> User | None:
        result = await self.session.execute(stmt_user_by_email(self.tenant_id, email_normalized))
        return result.scalar_one_or_none()

    async def for_login(self, email_normalized: str) -> User | None:
        result = await self.session.execute(stmt_user_for_login(self.tenant_id, email_normalized))
        return result.scalar_one_or_none()

    async def list(
        self,
        *,
        limit: int,
        offset: int,
        status: str | None = None,
        query: str | None = None,
    ) -> tuple[list[User], int]:
        rows = await self.session.execute(
            stmt_list_users(self.tenant_id, limit=limit, offset=offset, status=status, query=query)
        )
        total = await self.session.execute(
            stmt_count_users(self.tenant_id, status=status, query=query)
        )
        return list(rows.scalars()), int(total.scalar_one())

    async def add(self, user: User) -> User:
        return await self.flush(user)  # type: ignore[return-value]

    async def touch(self, user: User) -> User:
        return await self.flush(user)  # type: ignore[return-value]
