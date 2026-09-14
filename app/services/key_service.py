"""The signing-key lifecycle, as a state machine the database enforces.

Rotation is where identity services break, and always the same way: a new key
starts signing before consumers have seen it, and every token minted in that
window fails to verify. The window is exactly one JWKS cache TTL wide, so the
rule is simple and the enforcement is not optional —

    generate  -> pending   (published in JWKS immediately, signs nothing)
    promote   -> active    (ONLY after >= 2x the JWKS cache TTL has passed)
    retire    -> retiring  (still published, no longer signs)
    revoke    -> revoked   (removed from JWKS; for a key believed compromised)

**`promote` refuses if asked too early.** That is the whole design: a runbook
step saying "wait ten minutes" is a step someone skips at 2am during an
incident. Here it is a precondition, and `can_promote` is pure, so the clock
arithmetic is testable without a database or a key.

Why twice the TTL rather than once: a consumer may have fetched JWKS one
microsecond before the new key was published, and will then serve that cached
copy for a full TTL. One TTL is the worst case before it *starts* refreshing;
two gives it the whole window to finish.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.errors import Conflict, NotFound
from app.core.logging import get_logger
from app.crypto.jwks import jwks_document
from app.crypto.keywrap import unwrap, wrap
from app.crypto.signer import LocalSigner, generate_rsa_keypair
from app.models.signing_key import SigningKey
from app.repositories.signing_key import SigningKeyRepository
from app.services.audit import AuditSink

__all__ = ["KeyService", "can_promote"]

log = get_logger(__name__)


def can_promote(created_at: datetime, now: datetime, min_publish_delay: int) -> bool:
    """Pure, so the rule is testable without a database, a key, or a clock.

    `min_publish_delay` is already twice the JWKS cache TTL by configuration;
    this function only compares.
    """
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return now - created_at >= timedelta(seconds=min_publish_delay)


class KeyService:
    def __init__(
        self,
        repo: SigningKeyRepository,
        audit: AuditSink,
        *,
        kek: str,
        min_publish_delay_seconds: int,
    ) -> None:
        self.repo = repo
        self.audit = audit
        self.kek = kek
        self.min_publish_delay_seconds = min_publish_delay_seconds

    # ── Lifecycle ───────────────────────────────────────────────────────────

    async def generate(self, *, activate_immediately: bool = False) -> SigningKey:
        """Create a key and publish it as `pending`.

        `activate_immediately` exists for one situation: the very first key,
        when there is nothing to rotate away from and no consumer holding a
        cached JWKS that lacks it. Using it at any other time is the outage
        described at the top of this module, so it is not the default and the
        caller has to ask for it by name.
        """
        signer = LocalSigner(generate_rsa_keypair())
        jwk = signer.public_jwk()

        if activate_immediately and await self.repo.active() is not None:
            # The partial unique index would refuse this anyway; failing here
            # gives a message that names the cause.
            raise Conflict("another key is already active; promote instead")

        key = SigningKey(
            kid=signer.kid,
            alg="RS256",
            public_jwk=jwk,
            private_key_encrypted=wrap(signer.private_pem(), self.kek),
            status="active" if activate_immediately else "pending",
            created_at=datetime.now(UTC),
            promoted_at=datetime.now(UTC) if activate_immediately else None,
        )
        await self.repo.add(key)

        self.audit.record(
            "key.generate",
            outcome="success",
            actor_type="system",
            metadata={"kid": signer.kid, "status": key.status},
        )
        log.info("signing_key_generated", kid=signer.kid, status=key.status)
        return key

    async def promote(self, kid: str, *, now: datetime | None = None) -> SigningKey:
        """Make a pending key the signing key. Refuses if it is too new."""
        now = now or datetime.now(UTC)
        key = await self.repo.by_kid(kid)
        if key is None:
            raise NotFound(f"no signing key {kid!r}")
        if key.status != "pending":
            raise Conflict(f"key {kid!r} is {key.status}, not pending")

        if not can_promote(key.created_at, now, self.min_publish_delay_seconds):
            waited = int((now - key.created_at.replace(tzinfo=UTC)).total_seconds())
            raise Conflict(
                f"key {kid!r} has only been published for {waited}s; consumers "
                f"cache JWKS and need {self.min_publish_delay_seconds}s",
                detail={"published_for_seconds": waited},
            )

        # Retire the incumbent first: the partial unique index permits only one
        # active key, so promoting before retiring would violate it.
        current = await self.repo.active()
        if current is not None:
            current.status = "retiring"
            current.retire_after = now + timedelta(hours=24)
            await self.repo.touch(current)

        key.status = "active"
        key.promoted_at = now
        await self.repo.touch(key)

        self.audit.record(
            "key.promote",
            outcome="success",
            actor_type="system",
            metadata={"kid": kid, "replaced": current.kid if current else None},
        )
        log.info("signing_key_promoted", kid=kid, replaced=current.kid if current else None)
        return key

    async def revoke(self, kid: str) -> SigningKey:
        """Remove a key from JWKS entirely. For a key believed compromised.

        Every token it signed becomes unverifiable the moment consumers refresh,
        which is the intent — and the reason this is separate from retiring.
        """
        key = await self.repo.by_kid(kid)
        if key is None:
            raise NotFound(f"no signing key {kid!r}")

        key.status = "revoked"
        await self.repo.touch(key)
        self.audit.record(
            "key.revoke", outcome="success", actor_type="system", metadata={"kid": kid}
        )
        log.warning("signing_key_revoked", kid=kid)
        return key

    # ── Use ─────────────────────────────────────────────────────────────────

    async def active_signer(self) -> LocalSigner:
        """The signer the token service uses. Raises if there is none."""
        key = await self.repo.active()
        if key is None:
            raise NotFound("no active signing key; run `rotate-key --first`")
        return LocalSigner.from_pem(unwrap(key.private_key_encrypted or b"", self.kek))

    async def jwks(self) -> dict[str, object]:
        """The published key set — wider than the active key. See the repository."""
        return jwks_document([dict(k.public_jwk) for k in await self.repo.published()])
