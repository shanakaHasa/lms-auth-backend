"""User lifecycle: create, invite, activate, disable.

One behaviour here matters more than the rest and is easy to miss.

**Disabling a user, and changing a password, both bump `token_version`.** Access
tokens are verified offline against cached JWKS, so nothing this service does
can reach out and cancel one — a token already issued stays cryptographically
valid until it expires. `token_version` is the compensating control: it rides in
the token as `tv`, and a consumer rejects any token whose `tv` is behind the
user's current value. Without the bump, disabling an account leaves the person
logged in for the remainder of the access-token lifetime, which is exactly the
window an offboarding is trying to close.

Note honestly what that costs today: **`backend` does not yet check `tv`.** The
bump is recorded correctly, and nothing consumes it until the revocation feed at
Step 10. Until then, disabling is eventually-consistent at the access-token TTL
— ten minutes — and that is the real, stated guarantee rather than "instant".
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.core.errors import Conflict, NotFound
from app.models.role import Role
from app.models.user import User
from app.models.user_role import UserRole
from app.repositories.role import RoleRepository
from app.repositories.user import UserRepository
from app.schemas.user import UserCreate, UserInvite, normalise_email
from app.services.audit import AuditSink
from app.services.base import assert_same_tenant
from app.services.password_service import PasswordService

__all__ = ["UserService"]


class UserService:
    def __init__(
        self,
        users: UserRepository,
        roles: RoleRepository,
        passwords: PasswordService,
        audit: AuditSink,
        tenant_id: uuid.UUID,
        *,
        actor_id: str | None = None,
    ) -> None:
        assert_same_tenant(tenant_id, users, roles)
        self.users = users
        self.roles = roles
        self.passwords = passwords
        self.audit = audit
        self.tenant_id = tenant_id
        # None when the actor is the system — `seed-dev`, or a CLI command.
        self.actor_id = actor_id

    # ── Creation ────────────────────────────────────────────────────────────

    async def create(self, payload: UserCreate) -> User:
        """A user who can log in immediately."""
        email_normalized = normalise_email(payload.email)
        await self._assert_email_free(email_normalized)
        # Validate before hashing: a rejected password should not cost 64 MiB.
        self.passwords.validate(payload.password)

        user = User(
            id=uuid.uuid4(),
            tenant_id=self.tenant_id,
            email=payload.email.strip(),
            email_normalized=email_normalized,
            password_hash=await self.passwords.hash(payload.password),
            password_updated_at=datetime.now(UTC),
            full_name=payload.full_name,
            status="active",
            failed_login_count=0,
            token_version=0,
        )
        await self.users.add(user)
        await self._grant_all(user, payload.role_keys)

        self.audit.record(
            "user.create",
            outcome="success",
            actor_type="user" if self.actor_id else "system",
            actor_id=self.actor_id,
            tenant_id=self.tenant_id,
            subject_user_id=user.id,
            metadata={"roles": sorted(payload.role_keys)},
        )
        return user

    async def invite(self, payload: UserInvite) -> User:
        """A user with no password yet.

        `password_hash` stays NULL. Login must treat that as a failure
        indistinguishable from a wrong password — an invited account that failed
        differently would confirm the address exists.
        """
        email_normalized = normalise_email(payload.email)
        await self._assert_email_free(email_normalized)

        user = User(
            id=uuid.uuid4(),
            tenant_id=self.tenant_id,
            email=payload.email.strip(),
            email_normalized=email_normalized,
            password_hash=None,
            full_name=payload.full_name,
            status="invited",
            failed_login_count=0,
            token_version=0,
        )
        await self.users.add(user)
        await self._grant_all(user, payload.role_keys)

        self.audit.record(
            "user.invite",
            outcome="success",
            actor_type="user" if self.actor_id else "system",
            actor_id=self.actor_id,
            tenant_id=self.tenant_id,
            subject_user_id=user.id,
            metadata={"roles": sorted(payload.role_keys)},
        )
        return user

    # ── Lifecycle ───────────────────────────────────────────────────────────

    async def activate(self, user_id: uuid.UUID, password: str) -> User:
        """Set the first password and open the account."""
        user = await self._get(user_id)
        if user.password_hash is not None:
            raise Conflict("that account already has a password")

        self.passwords.validate(password)
        user.password_hash = await self.passwords.hash(password)
        user.password_updated_at = datetime.now(UTC)
        user.status = "active"
        await self.users.touch(user)

        self.audit.record(
            "user.activate",
            outcome="success",
            actor_type="user",
            actor_id=str(user.id),
            tenant_id=self.tenant_id,
            subject_user_id=user.id,
        )
        return user

    async def set_password(self, user_id: uuid.UUID, password: str) -> User:
        user = await self._get(user_id)
        self.passwords.validate(password)

        user.password_hash = await self.passwords.hash(password)
        user.password_updated_at = datetime.now(UTC)
        # A password change is a revocation event: whoever knew the old one must
        # not keep a live session.
        user.token_version += 1
        # Changing a password clears a lockout — the person has proven control.
        user.failed_login_count = 0
        user.locked_until = None
        await self.users.touch(user)

        self.audit.record(
            "user.password_change",
            outcome="success",
            actor_type="user",
            actor_id=self.actor_id or str(user.id),
            tenant_id=self.tenant_id,
            subject_user_id=user.id,
            metadata={"token_version": user.token_version},
        )
        return user

    async def disable(self, user_id: uuid.UUID) -> User:
        user = await self._get(user_id)
        if user.status == "disabled":
            return user  # Idempotent: disabling twice is not an error.

        user.status = "disabled"
        # The whole point. Without this, an offboarded person keeps working
        # access for the remainder of their access token's life.
        user.token_version += 1
        await self.users.touch(user)

        self.audit.record(
            "user.disable",
            outcome="success",
            actor_type="user" if self.actor_id else "system",
            actor_id=self.actor_id,
            tenant_id=self.tenant_id,
            subject_user_id=user.id,
            metadata={"token_version": user.token_version},
        )
        return user

    async def enable(self, user_id: uuid.UUID) -> User:
        user = await self._get(user_id)
        if user.status == "active":
            return user
        if user.password_hash is None:
            raise Conflict("that account has never been activated")

        user.status = "active"
        user.failed_login_count = 0
        user.locked_until = None
        await self.users.touch(user)

        self.audit.record(
            "user.enable",
            outcome="success",
            actor_type="user" if self.actor_id else "system",
            actor_id=self.actor_id,
            tenant_id=self.tenant_id,
            subject_user_id=user.id,
        )
        return user

    # ── Roles ───────────────────────────────────────────────────────────────

    async def grant_role(self, user: User, role_key: str) -> Role:
        role = await self.roles.by_key(role_key)
        if role is None:
            raise NotFound(f"no role {role_key!r} in this institution")

        await self.roles.grant(
            UserRole(
                user_id=user.id,
                role_id=role.id,
                # Carried explicitly: the composite foreign keys validate the
                # user AND the role against this same tenant, which is what
                # makes a cross-tenant grant a database error.
                tenant_id=self.tenant_id,
                granted_by=uuid.UUID(self.actor_id) if self.actor_id else None,
            )
        )
        self.audit.record(
            "user.role_grant",
            outcome="success",
            actor_type="user" if self.actor_id else "system",
            actor_id=self.actor_id,
            tenant_id=self.tenant_id,
            subject_user_id=user.id,
            metadata={"role": role_key},
        )
        return role

    async def scopes_for(self, user_id: uuid.UUID) -> frozenset[str]:
        """What a token for this user would carry. One query."""
        return await self.roles.scopes_for_user(user_id)

    # ── Internals ───────────────────────────────────────────────────────────

    async def _get(self, user_id: uuid.UUID) -> User:
        user = await self.users.get(user_id)
        if user is None:
            # A user in another tenant arrives here as None, so a cross-tenant
            # probe gets exactly what a missing id gets.
            raise NotFound("user not found")
        return user

    async def _assert_email_free(self, email_normalized: str) -> None:
        # The partial unique index is the real guarantee; this exists so the
        # ordinary case gets a precise 409 rather than a constraint message.
        if await self.users.by_email(email_normalized) is not None:
            raise Conflict("a user with that email already exists", detail={"field": "email"})

    async def _grant_all(self, user: User, role_keys: list[str]) -> None:
        for key in role_keys:
            await self.grant_role(user, key)
