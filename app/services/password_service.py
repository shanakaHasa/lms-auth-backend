"""Password hashing.

Argon2id, with three operational properties that matter more than the algorithm
choice and are easy to leave out:

**Hashing runs in a thread, behind a semaphore.** Argon2 at 64 MiB is designed
to be slow and memory-hungry — that is the point. Run it on the event loop and
one login stalls every other request in the process; run it unbounded and 50
concurrent logins ask for 3.2 GB and the container is killed. `to_thread` plus
`Semaphore(8)` bounds both. 64 MiB x 8 = 512 MiB worst case, which is a number
you can size a container against.

**The length cap is enforced before hashing, not after.** Argon2's cost is
driven by its parameters rather than input length, but the memory to hold the
input is not — and a 10 MB password is a free denial of service if it reaches
the hasher. The check therefore happens first, and a test asserts the hasher
was never called.

**There is a dummy hash, and it is a real one.** Login must do the same work for
an unknown user as for a known one, or response time alone reveals which
addresses are registered. It is computed once, with the production parameters,
from the same hasher.

The hasher and the semaphore live together on purpose. Splitting the primitive
into its own module reads more cleanly and creates a second, unguarded path to
`hash()` — and the semaphore exists precisely so that no unguarded path exists.
"""

from __future__ import annotations

import asyncio
import functools
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import settings
from app.core.errors import ValidationFailed
from app.core.logging import get_logger

__all__ = ["PasswordService", "get_password_service"]

log = get_logger(__name__)


class PasswordService:
    """Stateless apart from its tuning. Construct once, share it.

    Constructing one computes a dummy hash, which at production parameters costs
    real milliseconds — so this must never be built per request. `get_password_service()`
    below is the cached accessor everything should use.
    """

    def __init__(
        self,
        *,
        time_cost: int,
        memory_cost_kib: int,
        parallelism: int,
        max_concurrency: int,
        min_length: int,
        max_bytes: int,
    ) -> None:
        self._hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
        )
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self.min_length = min_length
        self.max_bytes = max_bytes
        # A real hash of a value nobody knows, so `verify_dummy` costs exactly
        # what a genuine verification costs.
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(32))

    # ── Policy ──────────────────────────────────────────────────────────────

    def validate(self, password: str) -> None:
        """NIST SP 800-63B: length, and nothing else.

        No composition rules and no expiry, both deliberately. Character-class
        requirements push people towards `Password1!` and expiry pushes them
        towards `Password1!`, then `Password2!` — each measurably worse than the
        passphrase they would otherwise have chosen.
        """
        encoded = password.encode("utf-8")
        if len(encoded) > self.max_bytes:
            # First, before anything expensive touches it.
            raise ValidationFailed(
                f"password must be at most {self.max_bytes} bytes",
                detail={"field": "password"},
            )
        if len(password) < self.min_length:
            raise ValidationFailed(
                f"password must be at least {self.min_length} characters",
                detail={"field": "password"},
            )

    # ── Hashing ─────────────────────────────────────────────────────────────

    async def hash(self, password: str) -> str:
        self.validate(password)
        return await self._run(self._hasher.hash, password)

    async def verify(self, stored_hash: str, password: str) -> bool:
        """Check a password. Never raises on a wrong one — returns False.

        The byte cap applies here too: an attacker controls this input directly,
        and the cheapest way to make us do expensive work is to send a huge one.
        """
        if len(password.encode("utf-8")) > self.max_bytes:
            return False
        try:
            await self._run(self._hasher.verify, stored_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
        return True

    async def verify_dummy(self) -> None:
        """Burn the same work a real verification would.

        Called when the user does not exist, is disabled, or the tenant is
        unknown — so that all four outcomes cost the same. Without this, an
        unknown address returns visibly faster than a known one and the login
        endpoint becomes a user-enumeration oracle.
        """
        try:
            await self._run(self._hasher.verify, self._dummy_hash, "not-the-password")
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return

    def needs_rehash(self, stored_hash: str) -> bool:
        """Whether this hash predates the current parameters.

        Checked on every successful login, so raising the cost later upgrades
        everyone who logs in rather than requiring a reset. A malformed hash is
        reported as needing a rehash: the caller has just verified the password
        successfully, so re-hashing repairs the row.
        """
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except InvalidHashError:
            return True

    # ── Internals ───────────────────────────────────────────────────────────

    async def _run(self, fn, *args):  # type: ignore[no-untyped-def]
        # The semaphore bounds memory; the thread keeps the event loop free.
        # Both are needed: either alone leaves one of the two failure modes.
        async with self._semaphore:
            return await asyncio.to_thread(fn, *args)


@functools.lru_cache(maxsize=1)
def get_password_service() -> PasswordService:
    return PasswordService(
        time_cost=settings.argon2_time_cost,
        memory_cost_kib=settings.argon2_memory_cost_kib,
        parallelism=settings.argon2_parallelism,
        max_concurrency=settings.argon2_max_concurrency,
        min_length=settings.password_min_length,
        max_bytes=settings.password_max_bytes,
    )
