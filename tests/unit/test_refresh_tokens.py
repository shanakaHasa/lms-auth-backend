"""Refresh tokens: format, and the SQL that decides the race.

The most important assertion in this file is a string match on compiled SQL.
That looks weak until you notice what it is protecting: the entire reuse-
detection guarantee rests on redemption being one atomic UPDATE with
`used_at IS NULL` in its WHERE clause. A fake cannot prove that — a dict is
single-threaded, and `asyncio.gather` over it only interleaves where someone
happened to put an `await`. The compiled statement is the only thing Phase 1
can check, and the real race is deferred to a serial integration test.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.dialects import postgresql

from app.crypto.tokens import (
    PREFIX,
    hash_secret,
    new_refresh_token,
    parse_refresh_token,
    secret_matches,
)
from app.repositories.refresh_token import stmt_redeem, stmt_revoke_family

NOW = datetime(2026, 1, 1, tzinfo=UTC)
TOKEN_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
FAMILY = uuid.UUID("22222222-2222-4222-8222-222222222222")


def sql(statement) -> str:  # type: ignore[no-untyped-def]
    return str(
        statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    )


# ── The statement that is the guarantee ─────────────────────────────────────


def test_redemption_is_a_single_update_guarded_on_unused() -> None:
    """`used_at IS NULL` in the WHERE clause IS reuse detection.

    Without it the statement claims a token unconditionally and a replay
    succeeds. With a separate SELECT first, two callers both see NULL and both
    proceed — and that race is indistinguishable from theft, so the bug shows up
    as users being randomly signed out rather than as a race.
    """
    rendered = sql(stmt_redeem(TOKEN_ID, NOW))
    assert rendered.startswith("UPDATE refresh_tokens SET used_at")
    assert "used_at IS NULL" in rendered
    assert "revoked_at IS NULL" in rendered
    assert str(TOKEN_ID) in rendered


def test_redemption_returns_the_row_so_the_caller_knows_it_won() -> None:
    # RETURNING is what makes the row count the outcome: one row means this
    # caller claimed it, zero means somebody else did.
    assert "RETURNING" in sql(stmt_redeem(TOKEN_ID, NOW))


def test_the_repository_offers_no_lookup_that_would_permit_check_then_update() -> None:
    """A deliberate absence, asserted so it stays deliberate.

    If the repository exposed `get_by_id` for the happy path, someone would
    reasonably write SELECT-then-UPDATE and the atomicity above would quietly
    become a convention. The only lookup is `find_used`, reachable after
    redemption has already failed.
    """
    from app.repositories import refresh_token as module

    lookups = {name for name in module.__all__ if name.startswith("stmt_")}
    assert lookups == {"stmt_find_used", "stmt_redeem", "stmt_revoke_family"}


def test_revocation_covers_the_family_not_one_token() -> None:
    """Reuse means one token is in someone else's hands.

    There is no way to tell which of the two presenters is legitimate, so both
    are signed out. Revoking only the presented token would leave the attacker
    holding a live one.
    """
    rendered = sql(stmt_revoke_family(FAMILY, NOW, "reuse_detected"))
    assert "UPDATE refresh_tokens" in rendered
    assert f"family_id = '{FAMILY}'" in rendered
    assert "reuse_detected" in rendered
    # Already-revoked rows are skipped, so a second reuse does not rewrite
    # timestamps and lose when the family actually died.
    assert "revoked_at IS NULL" in rendered


# ── Token format ────────────────────────────────────────────────────────────


def test_a_new_token_round_trips() -> None:
    presented, token_id, stored = new_refresh_token()
    parsed = parse_refresh_token(presented)
    assert parsed is not None
    assert parsed[0] == token_id
    assert secret_matches(parsed[1], stored)


def test_the_token_carries_a_version_prefix() -> None:
    # Changing the scheme later is then a new prefix rather than guessing what
    # an unrecognised string might be.
    assert new_refresh_token()[0].startswith(PREFIX)


def test_the_id_is_recoverable_so_redemption_is_a_primary_key_lookup() -> None:
    # The alternative is scanning a hash column on the hot path.
    presented, token_id, _ = new_refresh_token()
    assert str(token_id) in presented


def test_only_the_hash_is_stored_and_the_secret_is_not_recoverable() -> None:
    presented, _, stored = new_refresh_token()
    secret = presented.split(".", 1)[1]
    assert isinstance(stored, bytes)
    assert len(stored) == 32  # SHA-256
    assert secret.encode() not in stored


def test_a_thousand_tokens_are_all_distinct() -> None:
    assert len({new_refresh_token()[0] for _ in range(1000)}) == 1000


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "rt2_" + str(TOKEN_ID) + ".secret",  # wrong version
        "rt1_not-a-uuid.secret",
        f"rt1_{TOKEN_ID}",  # no separator
        f"rt1_{TOKEN_ID}.",  # empty secret
        f"rt1_{TOKEN_ID}.a.b",  # two separators
        f"{TOKEN_ID}.secret",  # no prefix
    ],
)
def test_a_malformed_token_is_refused_without_raising(bad: str) -> None:
    # None rather than an exception: the caller treats "not a token" and "not a
    # valid token" identically, and distinguishing them would leak whether an id
    # exists.
    assert parse_refresh_token(bad) is None


def test_the_secret_comparison_is_constant_time() -> None:
    """`hmac.compare_digest`, not `==`.

    The id half is a lookup key an attacker can hold; the secret is what proves
    possession. Comparing with `==` leaks how much of a guess was right, one
    byte at a time.
    """
    import inspect

    from app.crypto import tokens

    assert "compare_digest" in inspect.getsource(tokens.secret_matches)


def test_a_wrong_secret_does_not_match() -> None:
    _, _, stored = new_refresh_token()
    assert not secret_matches("not-the-secret", stored)


def test_hashing_is_stable() -> None:
    assert hash_secret("abc") == hash_secret("abc")
    assert hash_secret("abc") != hash_secret("abd")
