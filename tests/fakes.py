"""In-memory stand-ins for storage.

The whole of this service is built before a migration is ever applied, so
without these nothing in the service layer could be tested until the very end.

Two properties make them worth trusting, and one of them is specific to auth:

**One store, shared across tenants.** Every fake repository reads the same dicts
and filters by the tenant it was constructed with. A tenant filter that went
missing therefore returns the *other* tenant's rows and the isolation tests fail
— which would not happen if each tenant had its own store.

**The email uniqueness fake is keyed on `(tenant_id, email_normalized)`, not on
the address alone.** This is the single most likely thing to be mis-implemented
as global, and a fake that enforced it globally would make a *correct* service
fail: a tutor genuinely works at two institutions with one address. A test
asserts the fake itself permits that, which sounds odd until you notice the
fake's strictness is load-bearing for every claim made through it.

What these deliberately do not model is SQL — that is covered separately, by
compiling each real statement against the Postgres dialect.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.errors import Conflict
from app.models.role import Role
from app.models.role_scope import RoleScope
from app.models.tenant import Tenant
from app.models.user import User
from app.models.user_role import UserRole

__all__ = [
    "FakeAuditSink",
    "FakeRoleRepository",
    "FakeTenantRepository",
    "FakeUserRepository",
    "Store",
    "make_tenant",
    "make_user",
    "seed_roles",
]


@dataclass
class Store:
    """One shared store, holding every tenant's rows."""

    tenants: dict[uuid.UUID, Tenant] = field(default_factory=dict)
    users: dict[uuid.UUID, User] = field(default_factory=dict)
    roles: dict[uuid.UUID, Role] = field(default_factory=dict)
    role_scopes: list[RoleScope] = field(default_factory=list)
    user_roles: list[UserRole] = field(default_factory=list)


@dataclass
class AuditRecord:
    action: str
    outcome: str
    actor_type: str
    actor_id: str | None
    tenant_id: uuid.UUID | None
    subject_user_id: uuid.UUID | None
    reason: str | None
    metadata: dict[str, Any]


class FakeAuditSink:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def record(
        self,
        action: str,
        *,
        outcome: str,
        actor_type: str = "user",
        actor_id: str | None = None,
        tenant_id: uuid.UUID | None = None,
        subject_user_id: uuid.UUID | None = None,
        reason: str | None = None,
        client_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.records.append(
            AuditRecord(
                action=action,
                outcome=outcome,
                actor_type=actor_type,
                actor_id=actor_id,
                tenant_id=tenant_id,
                subject_user_id=subject_user_id,
                reason=reason,
                metadata=metadata or {},
            )
        )

    def actions(self) -> list[str]:
        return [record.action for record in self.records]

    def reasons(self) -> list[str | None]:
        return [record.reason for record in self.records]


def _stamp(instance: Any) -> Any:
    """What the INSERT would populate.

    `created_at` and `updated_at` are server defaults, so a freshly constructed
    instance has neither. Response models require both, so the fake flush has to
    supply them or tests would pass against a shape production never produces.
    """
    now = datetime.now(UTC)
    if getattr(instance, "created_at", None) is None:
        instance.created_at = now
    instance.updated_at = now
    if getattr(instance, "id", None) is None:
        instance.id = uuid.uuid4()
    return instance


class FakeTenantRepository:
    """Global: no `tenant_id` attribute, matching `GlobalRepository`."""

    def __init__(self, store: Store) -> None:
        self.store = store

    async def by_slug(self, slug: str) -> Tenant | None:
        return next(
            (t for t in self.store.tenants.values() if t.slug == slug and t.status == "active"),
            None,
        )

    async def get(self, tenant_id: uuid.UUID) -> Tenant | None:
        tenant = self.store.tenants.get(tenant_id)
        return tenant if tenant is not None and tenant.status == "active" else None

    async def add(self, tenant: Tenant) -> Tenant:
        if any(t.slug == tenant.slug for t in self.store.tenants.values()):
            raise Conflict("that institution slug is already taken")
        self.store.tenants[tenant.id] = _stamp(tenant)
        return tenant


class _Scoped:
    def __init__(self, store: Store, tenant_id: uuid.UUID) -> None:
        if tenant_id is None:
            raise ValueError("tenant_id is required to build a tenant-scoped repository")
        self.store = store
        self.tenant_id = tenant_id


class FakeUserRepository(_Scoped):
    def _live(self) -> list[User]:
        return [
            u
            for u in self.store.users.values()
            if u.tenant_id == self.tenant_id and u.deleted_at is None
        ]

    async def get(self, user_id: uuid.UUID) -> User | None:
        return next((u for u in self._live() if u.id == user_id), None)

    async def by_email(self, email_normalized: str) -> User | None:
        return next((u for u in self._live() if u.email_normalized == email_normalized), None)

    async def for_login(self, email_normalized: str) -> User | None:
        # Deliberately identical to `by_email`, including NOT filtering status.
        return await self.by_email(email_normalized)

    async def list(
        self,
        *,
        limit: int,
        offset: int,
        status: str | None = None,
        query: str | None = None,
    ) -> tuple[list[User], int]:
        rows = self._live()
        if status:
            rows = [u for u in rows if u.status == status]
        if query:
            needle = query.strip().lower()
            rows = [
                u
                for u in rows
                if needle in u.email_normalized
                or (u.full_name is not None and needle in u.full_name.lower())
            ]
        rows.sort(key=lambda u: (u.email_normalized, str(u.id)))
        return rows[offset : offset + limit], len(rows)

    async def add(self, user: User) -> User:
        self._assert_unique(user)
        self.store.users[user.id] = _stamp(user)
        return user

    async def touch(self, user: User) -> User:
        self._assert_unique(user)
        self.store.users[user.id] = _stamp(user)
        return user

    def _assert_unique(self, user: User) -> None:
        # `uq_users_tenant_email`: PER TENANT, and partial on deleted_at IS NULL.
        # Keyed on the pair on purpose — see the module docstring.
        if user.deleted_at is not None:
            return
        for other in self.store.users.values():
            if other.id == user.id or other.deleted_at is not None:
                continue
            if (
                other.tenant_id == user.tenant_id
                and other.email_normalized == user.email_normalized
            ):
                raise Conflict("a user with that email already exists")


class FakeRoleRepository(_Scoped):
    def _rows(self) -> list[Role]:
        return [r for r in self.store.roles.values() if r.tenant_id == self.tenant_id]

    async def by_key(self, key: str) -> Role | None:
        return next((r for r in self._rows() if r.key == key), None)

    async def list(self) -> list[Role]:
        return sorted(self._rows(), key=lambda r: str(r.key))

    async def roles_for_user(self, user_id: uuid.UUID) -> list[Role]:
        granted = {
            ur.role_id
            for ur in self.store.user_roles
            if ur.user_id == user_id and ur.tenant_id == self.tenant_id
        }
        return sorted((r for r in self._rows() if r.id in granted), key=lambda r: str(r.key))

    async def scopes_for_user(self, user_id: uuid.UUID) -> frozenset[str]:
        granted = {
            ur.role_id
            for ur in self.store.user_roles
            if ur.user_id == user_id and ur.tenant_id == self.tenant_id
        }
        return frozenset(
            str(rs.scope_key) for rs in self.store.role_scopes if rs.role_id in granted
        )

    async def add(self, role: Role) -> Role:
        if any(r.key == role.key for r in self._rows()):
            raise Conflict("a role with that key already exists")
        self.store.roles[role.id] = _stamp(role)
        return role

    async def grant(self, user_role: UserRole) -> UserRole:
        # `pk_user_roles (user_id, role_id)`.
        for existing in self.store.user_roles:
            if existing.user_id == user_role.user_id and existing.role_id == user_role.role_id:
                raise Conflict("that user already holds that role")
        self.store.user_roles.append(user_role)
        return user_role

    async def add_scope(self, role_scope: RoleScope) -> RoleScope:
        # `pk_role_scopes (role_id, scope_key)` — the key a duplicated template
        # entry would violate.
        for existing in self.store.role_scopes:
            if (
                existing.role_id == role_scope.role_id
                and existing.scope_key == role_scope.scope_key
            ):
                raise Conflict("that role already grants that scope")
        self.store.role_scopes.append(role_scope)
        return role_scope


# ── Builders ────────────────────────────────────────────────────────────────


def make_tenant(
    *, slug: str = "northgate", name: str = "Northgate College", status: str = "active"
) -> Tenant:
    return _stamp(Tenant(id=uuid.uuid4(), slug=slug, name=name, status=status, settings={}))


def make_user(
    tenant_id: uuid.UUID,
    *,
    email: str = "ada@example.com",
    full_name: str | None = "Ada Lovelace",
    status: str = "active",
    password_hash: str | None = "$argon2id$fake",
    user_id: uuid.UUID | None = None,
) -> User:
    return _stamp(
        User(
            id=user_id or uuid.uuid4(),
            tenant_id=tenant_id,
            email=email,
            email_normalized=email.strip().lower(),
            password_hash=password_hash,
            full_name=full_name,
            status=status,
            failed_login_count=0,
            token_version=0,
        )
    )


async def seed_roles(store: Store, tenant_id: uuid.UUID) -> None:
    """Materialise the role templates into a fake store, via the real planner."""
    from app.services.provisioning import plan_tenant_roles

    repo = FakeRoleRepository(store, tenant_id)
    for role_plan in plan_tenant_roles(tenant_id).roles:
        await repo.add(role_plan.role)
        for role_scope in role_plan.scopes:
            await repo.add_scope(role_scope)
