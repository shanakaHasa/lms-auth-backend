"""Login, and the enumeration defence that shapes all of it.

Five things can go wrong: the tenant is unknown, the user is unknown, the
password is wrong, the account was never activated, or the account is disabled.
**All five return an identical 401.** Not similar — identical, down to the
message, because a client that can tell them apart can enumerate which addresses
are registered at an institution and which of those are still enabled.

Two consequences run through this file and neither is optional.

**Every failing path still runs a real Argon2 verification.** Returning early on
an unknown user would make that case measurably faster than a wrong password,
and response time alone would leak the same information the identical message
was hiding. So `verify_dummy()` burns the same work against a real hash.

**The real reason goes to the audit log.** It has to go somewhere, or operating
this service becomes impossible — you could never answer "why can this person
not log in". `auth_audit_events.reason` is that somewhere, and it is never
returned to a caller.

`tenant_id` is nullable on the audit row for the same reason: an unknown tenant
must not force a lookup that would itself become an oracle.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import NoReturn

from app.core.errors import InvalidCredentials
from app.core.logging import get_logger
from app.models.user import User
from app.repositories.role import RoleRepository
from app.repositories.tenant import TenantRepository
from app.repositories.user import UserRepository
from app.schemas.token import LoginRequest
from app.schemas.user import normalise_email
from app.services.audit import AuditSink
from app.services.audit_independent import IndependentAuditSink
from app.services.password_service import PasswordService
from app.services.token_service import TokenService

__all__ = ["LoginResult", "LoginService"]

log = get_logger(__name__)


class LoginResult:
    def __init__(
        self,
        token: str,
        expires_in: int,
        scopes: frozenset[str],
        user: User,
        tenant_id: uuid.UUID,
    ) -> None:
        self.token = token
        self.expires_in = expires_in
        self.scopes = scopes
        self.user = user
        # Carried out so the caller can start a refresh family without
        # resolving the slug a second time.
        self.tenant_id = tenant_id


class LoginService:
    """Takes repository *factories*, not repositories.

    Every other service in this codebase is handed repositories already scoped
    to a tenant. Login cannot be: it receives a slug from an unauthenticated
    caller and must resolve it before a tenant-scoped repository can exist.
    """

    def __init__(
        self,
        tenants: TenantRepository,
        user_repo_factory: Callable[[uuid.UUID], UserRepository],
        role_repo_factory: Callable[[uuid.UUID], RoleRepository],
        passwords: PasswordService,
        tokens: TokenService,
        audit: AuditSink,
        failure_audit: IndependentAuditSink,
    ) -> None:
        self.tenants = tenants
        self._users = user_repo_factory
        self._roles = role_repo_factory
        self.passwords = passwords
        self.tokens = tokens
        self.audit = audit
        # Failures are recorded OUT OF BAND. The request transaction is
        # about to be rolled back by the raise, taking any row written
        # inside it with it -- see audit_independent.py.
        self.failure_audit = failure_audit

    async def login(self, payload: LoginRequest) -> LoginResult:
        email = normalise_email(payload.email)
        slug = payload.tenant_slug.strip().lower()

        tenant = await self.tenants.by_slug(slug)
        if tenant is None:
            # No tenant to record, deliberately: resolving one here would be the
            # oracle this is avoiding.
            await self.passwords.verify_dummy()
            await self._deny("unknown_tenant", tenant_id=None, email=email)

        users = self._users(tenant.id)
        user = await users.for_login(email)

        if user is None:
            await self.passwords.verify_dummy()
            await self._deny("unknown_user", tenant_id=tenant.id, email=email)

        if user.password_hash is None:
            # Invited but never activated. Must cost the same as a wrong
            # password, or an invite that was never accepted is detectable.
            await self.passwords.verify_dummy()
            await self._deny("never_activated", tenant_id=tenant.id, email=email, user=user)

        # The real verification. Reached for active, disabled and locked
        # accounts alike -- the status checks come *after*, so they cannot be
        # distinguished by timing.
        correct = await self.passwords.verify(user.password_hash, payload.password)

        if not correct:
            user.failed_login_count += 1
            await users.touch(user)
            await self._deny("bad_password", tenant_id=tenant.id, email=email, user=user)

        if user.status != "active":
            await self._deny(f"status_{user.status}", tenant_id=tenant.id, email=email, user=user)

        if user.locked_until is not None and user.locked_until > datetime.now(UTC):
            await self._deny("locked", tenant_id=tenant.id, email=email, user=user)

        # ── Success ─────────────────────────────────────────────────────────
        roles = self._roles(tenant.id)
        scopes = await roles.scopes_for_user(user.id)

        # Free parameter upgrades: if the stored hash predates the current
        # Argon2 settings, re-hash now that we hold the plaintext.
        if self.passwords.needs_rehash(user.password_hash):
            user.password_hash = await self.passwords.hash(payload.password)
            log.info("password_rehashed", user_id=str(user.id))

        user.failed_login_count = 0
        user.last_login_at = datetime.now(UTC)
        await users.touch(user)

        token, claims = self.tokens.issue_access_token(
            user_id=user.id,
            tenant_id=tenant.id,
            tenant_slug=tenant.slug,
            email=user.email,
            scopes=scopes,
            token_version=user.token_version,
            # A session id ties an access token to the refresh family that will
            # exist at Step 6. Generated now so the claim is never absent.
            session_id=str(uuid.uuid4()),
        )

        self.audit.record(
            "auth.login",
            outcome="success",
            actor_type="user",
            actor_id=str(user.id),
            tenant_id=tenant.id,
            subject_user_id=user.id,
            metadata={"jti": claims["jti"], "sid": claims["sid"], "scopes": len(scopes)},
        )
        return LoginResult(token, claims["exp"] - claims["iat"], scopes, user, tenant.id)

    async def _deny(
        self,
        reason: str,
        *,
        tenant_id: uuid.UUID | None,
        email: str,
        user: User | None = None,
    ) -> NoReturn:
        """Record the truth, return nothing useful.

        `NoReturn` rather than `None`: this always raises, and saying so lets a
        type checker see that the code after each call site is unreachable —
        which is what makes the narrowing of `tenant` and `user` correct.
        """
        await self.failure_audit.record(
            "auth.login",
            outcome="failure",
            actor_type="anonymous",
            tenant_id=tenant_id,
            subject_user_id=user.id if user is not None else None,
            # The one place the real cause is written down.
            reason=reason,
            metadata={"email": email},
        )
        # The class takes the SPECIFIC reason and always renders a generic
        # public message, so the distinction is recorded on the exception
        # and in the audit row while never reaching the client.
        raise InvalidCredentials(reason)
