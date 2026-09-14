"""Password hashing — all of it verifiable with no database.

Two tests here are worth more than the rest, because they cover the properties
that are easy to claim in a docstring and never actually check: that the length
cap runs *before* the hasher, and that the semaphore really bounds concurrency.
Both are asserted against instrumented hashers rather than against wall-clock
time, which is flaky in CI, gets muted, and is then worse than no test.
"""

from __future__ import annotations

import asyncio

import pytest
from argon2 import PasswordHasher

from app.core.errors import ValidationFailed
from app.services.password_service import PasswordService

# Cheap parameters: these tests are about behaviour, not cost. The production
# parameters get their own test at the bottom.
CHEAP = {
    "time_cost": 1,
    "memory_cost_kib": 8,
    "parallelism": 1,
    "max_concurrency": 8,
    "min_length": 12,
    "max_bytes": 1024,
}

PASSWORD = "correct horse battery staple"


@pytest.fixture
def service() -> PasswordService:
    return PasswordService(**CHEAP)  # type: ignore[arg-type]


# ── Round trip ──────────────────────────────────────────────────────────────


async def test_a_password_verifies_against_its_own_hash(service: PasswordService) -> None:
    stored = await service.hash(PASSWORD)
    assert await service.verify(stored, PASSWORD) is True


async def test_a_wrong_password_returns_false_rather_than_raising(
    service: PasswordService,
) -> None:
    # Callers branch on the result; an exception here would make the login path
    # need a try/except around its most ordinary outcome.
    stored = await service.hash(PASSWORD)
    assert await service.verify(stored, "wrong password entirely") is False


async def test_two_hashes_of_one_password_differ(service: PasswordService) -> None:
    # Per-hash salt. Without it, identical passwords are visibly identical in a
    # database dump, which hands an attacker the most-common-password list.
    assert await service.hash(PASSWORD) != await service.hash(PASSWORD)


async def test_a_malformed_stored_hash_is_a_failed_verification(
    service: PasswordService,
) -> None:
    # A corrupted row must not 500 the login endpoint.
    assert await service.verify("not-a-hash", PASSWORD) is False
    assert await service.verify("", PASSWORD) is False


async def test_the_algorithm_is_argon2id(service: PasswordService) -> None:
    # argon2i and argon2d each defend against only one of side-channel and
    # GPU attacks; id is the hybrid, and the only one worth using here.
    assert (await service.hash(PASSWORD)).startswith("$argon2id$")


# ── The length cap runs before the hasher ───────────────────────────────────


class SpyHasher(PasswordHasher):
    """Records whether the expensive path was reached."""

    def __init__(self) -> None:
        super().__init__(time_cost=1, memory_cost=8, parallelism=1)
        self.hash_calls = 0
        self.verify_calls = 0

    def hash(self, password, *, salt=None):  # type: ignore[no-untyped-def, override]
        self.hash_calls += 1
        return super().hash(password)

    def verify(self, hash, password):  # type: ignore[no-untyped-def, override]
        self.verify_calls += 1
        return super().verify(hash, password)


@pytest.fixture
def spied() -> tuple[PasswordService, SpyHasher]:
    service = PasswordService(**CHEAP)  # type: ignore[arg-type]
    spy = SpyHasher()
    service._hasher = spy
    return service, spy


async def test_an_oversized_password_never_reaches_the_hasher(
    spied: tuple[PasswordService, SpyHasher],
) -> None:
    """The cap is a denial-of-service control, so ordering is the whole point.

    Rejecting a 10 MB password *after* hashing it costs exactly as much as
    accepting it. A test that only asserts the error would pass either way,
    which is why this one asserts the hasher was never called.
    """
    service, spy = spied
    with pytest.raises(ValidationFailed, match="bytes"):
        await service.hash("x" * 2000)
    assert spy.hash_calls == 0


async def test_an_oversized_password_never_reaches_the_verifier(
    spied: tuple[PasswordService, SpyHasher],
) -> None:
    # Same control on the path an unauthenticated attacker can actually reach.
    service, spy = spied
    assert await service.verify("$argon2id$whatever", "x" * 2000) is False
    assert spy.verify_calls == 0


async def test_the_cap_counts_bytes_not_characters(
    spied: tuple[PasswordService, SpyHasher],
) -> None:
    # "£" is two bytes in UTF-8, so a 600-character password can exceed a
    # 1024-byte cap. Counting characters would let it through.
    service, spy = spied
    with pytest.raises(ValidationFailed):
        await service.hash("£" * 600)
    assert spy.hash_calls == 0


# ── Policy ──────────────────────────────────────────────────────────────────


async def test_a_short_password_is_rejected(service: PasswordService) -> None:
    with pytest.raises(ValidationFailed, match="12 characters"):
        await service.hash("short")


def test_there_are_no_composition_rules(service: PasswordService) -> None:
    """NIST SP 800-63B, and a deliberate absence worth pinning.

    Character-class rules push people towards `Password1!`. A long passphrase of
    one character class must be accepted, or the policy is making things worse.
    """
    service.validate("aaaaaaaaaaaaaaaaaaaaaaaa")
    service.validate("correct horse battery staple")
    service.validate("🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑")


def test_the_minimum_is_measured_in_characters(service: PasswordService) -> None:
    # 12 characters, not 12 bytes: "🔑" is 4 bytes, and a 12-emoji passphrase is
    # strong. Measuring the minimum in bytes would accept a 3-emoji one.
    with pytest.raises(ValidationFailed):
        service.validate("🔑" * 11)
    service.validate("🔑" * 12)


# ── Enumeration defence ─────────────────────────────────────────────────────


async def test_the_dummy_verification_does_the_same_work_as_a_real_one(
    spied: tuple[PasswordService, SpyHasher],
) -> None:
    """Asserted with a spy, never with a clock.

    Timing assertions are flaky in CI, get muted, and are then worse than no
    test at all. What actually needs to be true is that the verifier ran — so
    that is what is asserted.
    """
    service, spy = spied
    await service.verify_dummy()
    assert spy.verify_calls == 1


async def test_the_dummy_verification_never_raises(service: PasswordService) -> None:
    # It is called on the failure path of login. An exception here would turn a
    # wrong password into a 500 and leak the branch through the status code.
    await service.verify_dummy()


async def test_the_dummy_hash_is_a_real_argon2_hash(service: PasswordService) -> None:
    # If it were a constant string, verification against it would fail fast on
    # a parse error instead of doing the work, and the defence would be a
    # comment rather than a control.
    assert service._dummy_hash.startswith("$argon2id$")
    assert await service.verify(service._dummy_hash, "not-the-password") is False


# ── Concurrency ─────────────────────────────────────────────────────────────


class ConcurrencyProbe(PasswordHasher):
    """Records the high-water mark of callers inside `hash` at once.

    A subclass rather than a monkeypatch: `PasswordHasher.hash` is read-only.
    The counter needs no lock — it is mutated from worker threads, but only
    under the semaphore this test exists to measure, and `+=` on an int under
    the GIL is atomic enough for a high-water mark.
    """

    def __init__(self) -> None:
        super().__init__(time_cost=1, memory_cost=8, parallelism=1)
        self.inside = 0
        self.peak = 0

    def hash(self, password, *, salt=None):  # type: ignore[no-untyped-def, override]
        self.inside += 1
        self.peak = max(self.peak, self.inside)
        try:
            return super().hash(password)
        finally:
            self.inside -= 1


async def test_the_semaphore_bounds_concurrent_hashing() -> None:
    """64 MiB x unbounded concurrency is how the container gets OOM-killed.

    Measured by instrumenting the hasher to record how many callers are inside
    it at once, rather than by timing — the assertion is about the bound, and
    the bound is exactly what the semaphore promises.
    """
    service = PasswordService(**{**CHEAP, "max_concurrency": 4})  # type: ignore[arg-type]
    probe = ConcurrencyProbe()
    service._hasher = probe

    await asyncio.gather(*(service.hash(f"{PASSWORD} {n}") for n in range(32)))

    assert probe.peak <= 4, f"{probe.peak} concurrent hashes, the cap was 4"
    assert probe.peak > 1, "nothing overlapped — the thread offload is not working"


async def test_hashing_does_not_block_the_event_loop() -> None:
    """`to_thread`, not a bare call.

    Argon2 is deliberately slow. On the event loop, one login stalls every other
    request in the process — including the health check, which is how a busy
    deploy turns into a recycling loop.
    """
    service = PasswordService(**CHEAP)  # type: ignore[arg-type]
    ticks = 0

    async def heartbeat() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0)

    beat = asyncio.create_task(heartbeat())
    await service.hash(PASSWORD)
    beat.cancel()

    # If hashing ran inline, the loop could never have advanced the heartbeat.
    assert ticks > 0


# ── Rehashing ───────────────────────────────────────────────────────────────


async def test_a_hash_at_current_parameters_does_not_need_rehashing(
    service: PasswordService,
) -> None:
    assert service.needs_rehash(await service.hash(PASSWORD)) is False


async def test_a_hash_at_weaker_parameters_is_upgraded_on_next_login() -> None:
    """Raising the cost later must not require a password reset.

    This is the whole reason `check_needs_rehash` is called on every successful
    login: the fleet upgrades itself as people sign in.
    """
    weak = PasswordService(**{**CHEAP, "time_cost": 1})  # type: ignore[arg-type]
    strong = PasswordService(**{**CHEAP, "time_cost": 3})  # type: ignore[arg-type]

    old = await weak.hash(PASSWORD)
    assert await strong.verify(old, PASSWORD) is True
    assert strong.needs_rehash(old) is True


def test_a_corrupt_hash_is_reported_as_needing_a_rehash(
    service: PasswordService,
) -> None:
    # The caller only asks after a successful verification, so re-hashing is
    # the repair. Raising here would fail a login that has already succeeded.
    assert service.needs_rehash("not-a-hash") is True


# ── The production parameters ───────────────────────────────────────────────


async def test_the_production_parameters_produce_the_expected_cost() -> None:
    """The suite runs at ARGON2_TIME_COST=1 and 8 MiB, so nothing else checks this.

    Without this test the real parameters are exercised by no code path at all,
    and a typo that dropped memory to 64 KiB would pass every other test here.
    Built from explicit values rather than `settings`, so an environment
    override cannot quietly weaken it.
    """
    production = PasswordService(
        time_cost=3,
        memory_cost_kib=65_536,
        parallelism=1,
        max_concurrency=8,
        min_length=12,
        max_bytes=1024,
    )
    encoded = await production.hash(PASSWORD)
    assert "$m=65536,t=3,p=1$" in encoded, encoded
