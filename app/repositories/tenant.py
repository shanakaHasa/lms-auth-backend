"""Tenant lookup — global, and necessarily so.

This is the table you read *before* you know which tenant you are in. Login
receives a slug from an unauthenticated caller and must resolve it to an id
before any tenant-scoped repository can be constructed, so a tenant-scoped
repository here would be circular.

That has a consequence worth stating plainly, because it shapes the login
service: **login cannot use a FastAPI repository dependency.** Every other
endpoint builds its repositories from `principal.tenant_id`; login has no
principal, because it is the thing that creates one.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import ColumnElement, Select, select

from app.models.tenant import Tenant
from app.repositories.base import GlobalRepository

__all__ = [
    "SqlTenantRepository",
    "TenantRepository",
    "stmt_tenant_by_id",
    "stmt_tenant_by_slug",
]


def _active(clause: ColumnElement[bool]) -> list[ColumnElement[bool]]:
    # A suspended institution must not be able to log anyone in, and a deleted
    # one must behave as if it never existed.
    return [clause, Tenant.status == "active"]


def stmt_tenant_by_slug(slug: str) -> Select[tuple[Tenant]]:
    return select(Tenant).where(*_active(Tenant.slug == slug))


def stmt_tenant_by_id(tenant_id: uuid.UUID) -> Select[tuple[Tenant]]:
    return select(Tenant).where(*_active(Tenant.id == tenant_id))


class TenantRepository(Protocol):
    async def by_slug(self, slug: str) -> Tenant | None: ...

    async def get(self, tenant_id: uuid.UUID) -> Tenant | None: ...

    async def add(self, tenant: Tenant) -> Tenant: ...


class SqlTenantRepository(GlobalRepository):
    async def by_slug(self, slug: str) -> Tenant | None:
        result = await self.session.execute(stmt_tenant_by_slug(slug))
        return result.scalar_one_or_none()

    async def get(self, tenant_id: uuid.UUID) -> Tenant | None:
        result = await self.session.execute(stmt_tenant_by_id(tenant_id))
        return result.scalar_one_or_none()

    async def add(self, tenant: Tenant) -> Tenant:
        return await self.flush(tenant)  # type: ignore[return-value]
