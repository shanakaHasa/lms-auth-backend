"""Refresh rotation, reuse detection, and logout.

Rotation is single-use: every refresh consumes a token and issues a new one in
the same family. That is what makes theft detectable — a stolen token is only
useful until the real user refreshes, and after that one of the two presents an
already-used token.

Three things here are easy to get subtly wrong.

**Redemption is one atomic UPDATE.** See `repositories/refresh_token.py`; the
row count is the race outcome, and this service never reads before writing.

**Reuse revokes the whole family, not just the token.** When a used token is
presented there is no way to know which of the two holders is legitimate, so
both are logged out and `token_version` is bumped to invalidate outstanding
access tokens. The real user signs in again; the attacker cannot.

**There is a grace window, and without it the feature is worse than useless.**
Two browser tabs refreshing within milliseconds of each other look *exactly*
like theft: same token, presented twice. Treating that as an attack means
ordinary users get logged out at random, an operator sees a stream of
`reuse_detected` in the audit log, and the signal that was supposed to catch
real theft becomes noise everybody learns to ignore. So a re-presentation
within `refresh_grace_seconds`, from the same context, is treated as a retry:
the family survives, and the caller gets a soft failure telling it to use the
token it already has.

That grace is a real, deliberate hole — for ten seconds a stolen token can be
replayed without tripping detection. It is the right trade, and it is narrow
and stated rather than accidental.

**Revocation on reuse runs in its own transaction.** This one is subtle enough
to be worth spelling out: detecting reuse ends in `raise InvalidGrant`, and the
raise makes `get_session` roll the request back. A revocation written in that
transaction is rolled back *by the very exception that reports it* — so the
family survives, the audit row vanishes, and the feature silently does nothing
while appearing to work. The failure path therefore commits separately, exactly
as failed-login auditing does.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import InvalidGrant
from app.core.logging import get_logger
from app.crypto.tokens import new_refresh_token, parse_refresh_token, secret_matches
from app.models.refresh_token import RefreshToken
from app.repositories.refresh_token import RefreshTokenRepository
from app.repositories.role import RoleRepository
from app.repositories.tenant import TenantRepository
from app.repositories.user import UserRepository
from app.services.audit import AuditSink
from app.services.token_service import TokenService

__all__ = ["RefreshContext", "RefreshResult", "RefreshService"]

log = get_logger(__name__)


def ip_prefix(ip: str | None) -> str | None:
    """A /24 or /48, never the full address.

    An IP is personal information, and the only use here is an anomaly signal
    that does not need the host bits. Storing the whole address would mean
    retaining more than the feature justifies.
    """
    if not ip:
        return None
    if ":" in ip:  # IPv6 -> /48
        return ":".join(ip.split(":")[:3]) + "::/48"
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else None


def ua_hash(user_agent: str | None) -> bytes | None:
    return hashlib.sha256(user_agent.encode("utf-8")).digest() if user_agent else None


class RefreshContext:
    """Where a refresh came from. Used for *soft* binding only."""

    def __init__(self, ip: str | None = None, user_agent: str | None = None) -> None:
        self.ip_prefix = ip_prefix(ip)
        self.ua_hash = ua_hash(user_agent)

    def matches(self, token: RefreshToken) -> bool:
        # Both sides may be unknown; an unknown context is not a mismatch.
        ip_ok = (
            token.ip_prefix is None or self.ip_prefix is None or token.ip_prefix == self.ip_prefix
        )
        ua_ok = token.ua_hash is None or self.ua_hash is None or token.ua_hash == self.ua_hash
        return ip_ok and ua_ok


class RefreshResult:
    def __init__(
        self,
        access_token: str,
        refresh_token: str,
        expires_in: int,
        scopes: frozenset[str],
    ) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_in = expires_in
        self.scopes = scopes


class RefreshService:
    def __init__(
        self,
        tokens: RefreshTokenRepository,
        tenants: TenantRepository,
        user_repo_factory: Callable[[uuid.UUID], UserRepository],
        role_repo_factory: Callable[[uuid.UUID], RoleRepository],
        access_tokens: TokenService,
        audit: AuditSink,
        session_factory: Callable[[], AsyncSession],
        *,
        idle_ttl_seconds: int,
        absolute_ttl_seconds: int,
        grace_seconds: int,
    ) -> None:
        self.tokens = tokens
        self.tenants = tenants
        self._users = user_repo_factory
        self._roles = role_repo_factory
        self.access_tokens = access_tokens
        self.audit = audit
        # Used only on failure paths, which end in a raise and therefore in a
        # rollback of the request's transaction.
        self._session_factory = session_factory
        self.idle_ttl_seconds = idle_ttl_seconds
        self.absolute_ttl_seconds = absolute_ttl_seconds
        self.grace_seconds = grace_seconds

    # ── Issuing ─────────────────────────────────────────────────────────────

    async def issue_first(
        self,
        *,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        context: RefreshContext,
        now: datetime | None = None,
    ) -> tuple[str, uuid.UUID]:
        """The token handed out at login. Starts a new family."""
        now = now or datetime.now(UTC)
        family_id = uuid.uuid4()
        presented, token_id, token_hash = new_refresh_token()

        await self.tokens.add(
            RefreshToken(
                id=token_id,
                family_id=family_id,
                user_id=user_id,
                tenant_id=tenant_id,
                token_hash=token_hash,
                issued_at=now,
                expires_at=now + timedelta(seconds=self.idle_ttl_seconds),
                ip_prefix=context.ip_prefix,
                ua_hash=context.ua_hash,
            )
        )
        return presented, family_id

    # ── Rotation ────────────────────────────────────────────────────────────

    async def rotate(
        self,
        presented: str,
        context: RefreshContext,
        *,
        now: datetime | None = None,
    ) -> RefreshResult:
        now = now or datetime.now(UTC)

        parsed = parse_refresh_token(presented)
        if parsed is None:
            self._audit_failure("malformed", None)
            raise InvalidGrant("invalid refresh token")
        token_id, secret = parsed

        # The atomic claim. One winner, decided by Postgres.
        token = await self.tokens.redeem(token_id, now)

        if token is None:
            # Lost the claim, or it never existed. Now — and only now, with the
            # race already settled — it is safe to read the row.
            await self._handle_failed_redemption(token_id, context, now)
            raise InvalidGrant("invalid refresh token")

        # The id half is only a lookup key; the secret is what proves holding.
        if not secret_matches(secret, token.token_hash):
            # Someone guessed an id. Treat as theft: the family is compromised
            # enough that the id is known to an attacker.
            await self._revoke_family(token.family_id, now, "reuse_detected")
            self._audit_failure("bad_secret", token.user_id, family_id=token.family_id)
            raise InvalidGrant("invalid refresh token")

        if token.expires_at <= now:
            self._audit_failure("expired", token.user_id, family_id=token.family_id)
            raise InvalidGrant("refresh token has expired")

        return await self._issue_next(token, context, now)

    async def _issue_next(
        self, parent: RefreshToken, context: RefreshContext, now: datetime
    ) -> RefreshResult:
        tenant = await self.tenants.get(parent.tenant_id)
        users = self._users(parent.tenant_id)
        user = await users.get(parent.user_id)

        if tenant is None or user is None or user.status != "active":
            # The world moved since the token was issued. Revoke rather than
            # silently refusing, so a disabled account cannot keep a live family
            # sitting there waiting to be retried.
            await self._revoke_family(parent.family_id, now, "user_disabled")
            self._audit_failure("user_not_active", parent.user_id, family_id=parent.family_id)
            raise InvalidGrant("invalid refresh token")

        # The absolute cap is measured from the family, not from this token --
        # otherwise rotating every ten minutes would extend a session forever.
        family_age = now - parent.issued_at.replace(tzinfo=UTC)
        idle_expiry = now + timedelta(seconds=self.idle_ttl_seconds)
        absolute_expiry = parent.issued_at.replace(tzinfo=UTC) + timedelta(
            seconds=self.absolute_ttl_seconds
        )
        if absolute_expiry <= now:
            await self._revoke_family(parent.family_id, now, "rotated")
            self._audit_failure("absolute_expiry", parent.user_id, family_id=parent.family_id)
            raise InvalidGrant("session has reached its maximum age")

        presented, token_id, token_hash = new_refresh_token()
        await self.tokens.add(
            RefreshToken(
                id=token_id,
                family_id=parent.family_id,
                user_id=parent.user_id,
                tenant_id=parent.tenant_id,
                token_hash=token_hash,
                parent_id=parent.id,
                issued_at=now,
                expires_at=min(idle_expiry, absolute_expiry),
                ip_prefix=context.ip_prefix or parent.ip_prefix,
                ua_hash=context.ua_hash or parent.ua_hash,
            )
        )
        parent.revoked_at = now
        parent.revoked_reason = "rotated"

        roles = self._roles(parent.tenant_id)
        scopes = await roles.scopes_for_user(user.id)

        access, claims = self.access_tokens.issue_access_token(
            user_id=user.id,
            tenant_id=tenant.id,
            tenant_slug=tenant.slug,
            email=user.email,
            scopes=scopes,
            token_version=user.token_version,
            # The family id IS the session id, so "log out this device" and
            # "which login produced this token" are the same query.
            session_id=str(parent.family_id),
            now=now,
        )

        self.audit.record(
            "auth.refresh",
            outcome="success",
            actor_type="user",
            actor_id=str(user.id),
            tenant_id=tenant.id,
            subject_user_id=user.id,
            metadata={
                "family": str(parent.family_id),
                "family_age_s": int(family_age.total_seconds()),
            },
        )
        return RefreshResult(access, presented, claims["exp"] - claims["iat"], scopes)

    # ── Failure paths ───────────────────────────────────────────────────────

    async def _handle_failed_redemption(
        self, token_id: uuid.UUID, context: RefreshContext, now: datetime
    ) -> None:
        token = await self.tokens.find_used(token_id)
        if token is None:
            self._audit_failure("unknown_token", None)
            return

        if token.revoked_at is not None and token.revoked_reason != "rotated":
            # The family is already dead for some other reason -- logout, a
            # password change, an earlier reuse. Nothing further to revoke and
            # no new signal.
            #
            # `rotated` is excluded deliberately, and getting this wrong
            # disables the entire feature: a normal rotation marks the parent
            # `rotated`, so treating that as "already dead" means every
            # legitimately spent token -- which is all of them -- takes this
            # branch and reuse is never detected. It reads as correct and
            # silently does nothing.
            self._audit_failure("revoked", token.user_id, family_id=token.family_id)
            return

        used_at = token.used_at.replace(tzinfo=UTC) if token.used_at else now
        within_grace = (now - used_at) <= timedelta(seconds=self.grace_seconds)

        if within_grace and context.matches(token):
            # Two tabs, not an attacker. See the module docstring: treating this
            # as theft is how the whole mechanism becomes noise.
            self._audit_failure("grace_retry", token.user_id, family_id=token.family_id)
            log.info("refresh_grace_retry", family=str(token.family_id))
            return

        await self._revoke_family(token.family_id, now, "reuse_detected")
        self._audit_failure("reuse_detected", token.user_id, family_id=token.family_id)
        log.warning(
            "refresh_token_reuse_detected",
            family=str(token.family_id),
            user_id=str(token.user_id),
            detail="whole family revoked; both holders are now signed out",
        )

    async def _revoke_family(self, family_id: uuid.UUID, now: datetime, reason: str) -> None:
        """Commit the revocation in its own transaction.

        Every caller of this is about to raise, and the raise rolls the request
        back. Writing here would undo the revocation -- see the module
        docstring.
        """
        from app.models.auth_audit_event import AuthAuditEvent
        from app.repositories.refresh_token import SqlRefreshTokenRepository

        try:
            async with self._session_factory() as session:
                await SqlRefreshTokenRepository(session).revoke_family(family_id, now, reason)
                session.add(
                    AuthAuditEvent(
                        actor_type="anonymous",
                        action="auth.refresh",
                        outcome="failure",
                        reason=reason,
                        event_metadata={"family": str(family_id)},
                    )
                )
                await session.commit()
        except Exception as exc:
            # Losing the revocation is the serious outcome, so it is logged
            # loudly rather than swallowed silently.
            log.error("refresh_revocation_failed", family=str(family_id), error=str(exc))

    def _audit_failure(
        self, reason: str, user_id: uuid.UUID | None, *, family_id: uuid.UUID | None = None
    ) -> None:
        self.audit.record(
            "auth.refresh",
            outcome="failure",
            actor_type="anonymous",
            subject_user_id=user_id,
            reason=reason,
            metadata={"family": str(family_id)} if family_id else {},
        )

    # ── Logout ──────────────────────────────────────────────────────────────

    async def logout(self, presented: str, *, now: datetime | None = None) -> None:
        """Revoke the family this token belongs to.

        Never raises on an unknown token: logging out is idempotent, and a
        client that has lost its token should still be able to clear its cookie
        without seeing an error.
        """
        now = now or datetime.now(UTC)
        parsed = parse_refresh_token(presented)
        if parsed is None:
            return

        token = await self.tokens.find_used(parsed[0])
        if token is None:
            return

        await self._revoke_family(token.family_id, now, "logout")
        self.audit.record(
            "auth.logout",
            outcome="success",
            actor_type="user",
            actor_id=str(token.user_id),
            tenant_id=token.tenant_id,
            subject_user_id=token.user_id,
            metadata={"family": str(token.family_id)},
        )
