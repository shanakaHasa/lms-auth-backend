"""Roles, grants, and the scope resolution that login depends on.

`stmt_scopes_for_user` is the most important statement in this service: it is
what turns "who is this person" into "what may they do", and it runs on every
login. Three things about it are deliberate.

**It is one query.** Loading roles, then scopes per role, is the N+1 that puts a
round trip per role on the login path.

**It filters `user_roles.tenant_id`, not `roles.tenant_id`.** Those are equal
today only because of the composite foreign key. Filtering the grant rather than
the role means the query stays correct even if that constraint is ever relaxed —
and it is the grant, not the role, that authorises.

**It returns scope keys, not roles.** Roles never enter a token. Scopes are the
authorization currency; putting role names in a token invites consumers to make
policy decisions that belong here.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import Select, select

from app.models.role import Role
from app.models.role_scope import RoleScope
from app.models.user_role import UserRole
from app.repositories.base import TenantScopedRepository

__all__ = [
    "RoleRepository",
    "SqlRoleRepository",
    "stmt_grants_for_user",
    "stmt_role_by_key",
    "stmt_roles_for_tenant",
    "stmt_scopes_for_user",
]


def stmt_scopes_for_user(tenant_id: uuid.UUID, user_id: uuid.UUID) -> Select[tuple[str]]:
    """Every scope a user holds, as a flat distinct set, in one query."""
    return (
        select(RoleScope.scope_key)
        .join(UserRole, UserRole.role_id == RoleScope.role_id)
        .where(
            # The grant carries the tenant, and the grant is what authorises.
            UserRole.tenant_id == tenant_id,
            UserRole.user_id == user_id,
        )
        .distinct()
    )


def stmt_grants_for_user(tenant_id: uuid.UUID, user_id: uuid.UUID) -> Select[tuple[Role]]:
    return (
        select(Role)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.tenant_id == tenant_id, UserRole.user_id == user_id)
        .order_by(Role.key)
    )


def stmt_role_by_key(tenant_id: uuid.UUID, key: str) -> Select[tuple[Role]]:
    return select(Role).where(Role.tenant_id == tenant_id, Role.key == key)


def stmt_roles_for_tenant(tenant_id: uuid.UUID) -> Select[tuple[Role]]:
    return select(Role).where(Role.tenant_id == tenant_id).order_by(Role.key)


class RoleRepository(Protocol):
    tenant_id: uuid.UUID

    async def scopes_for_user(self, user_id: uuid.UUID) -> frozenset[str]: ...

    async def roles_for_user(self, user_id: uuid.UUID) -> list[Role]: ...

    async def by_key(self, key: str) -> Role | None: ...

    async def list(self) -> list[Role]: ...

    async def add(self, role: Role) -> Role: ...

    async def grant(self, user_role: UserRole) -> UserRole: ...

    async def add_scope(self, role_scope: RoleScope) -> RoleScope: ...


class SqlRoleRepository(TenantScopedRepository):
    async def scopes_for_user(self, user_id: uuid.UUID) -> frozenset[str]:
        result = await self.session.execute(stmt_scopes_for_user(self.tenant_id, user_id))
        return frozenset(result.scalars())

    async def roles_for_user(self, user_id: uuid.UUID) -> list[Role]:
        result = await self.session.execute(stmt_grants_for_user(self.tenant_id, user_id))
        return list(result.scalars())

    async def by_key(self, key: str) -> Role | None:
        result = await self.session.execute(stmt_role_by_key(self.tenant_id, key))
        return result.scalar_one_or_none()

    async def list(self) -> list[Role]:
        result = await self.session.execute(stmt_roles_for_tenant(self.tenant_id))
        return list(result.scalars())

    async def add(self, role: Role) -> Role:
        return await self.flush(role)  # type: ignore[return-value]

    async def grant(self, user_role: UserRole) -> UserRole:
        return await self.flush(user_role)  # type: ignore[return-value]

    async def add_scope(self, role_scope: RoleScope) -> RoleScope:
        return await self.flush(role_scope)  # type: ignore[return-value]
