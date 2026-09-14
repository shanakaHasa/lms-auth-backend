"""What only a real Postgres can prove about this schema.

The unit suite asserts against `Base.metadata` — that the *models* declare what
their docstrings claim. That is a statement about Python objects, and it stays
true even if the migration spells a constraint differently, omits a `WHERE`
clause, or was never applied at all.

These tests ask the database itself. Each one targets a guarantee the model
modules claim in prose and that **only the database can enforce** — a partial
index that silently became a full one, a composite foreign key that became two
single-column ones, a `RESTRICT` that became a `CASCADE`. Every one of those
still passes the metadata tests while being wrong in production.

This is also the first test in this directory, and it exists partly so the
`migrations` CI job runs something: an empty directory makes pytest exit 5, and
a job that is always red is worse than no job.

Run with `pytest -m integration` after `alembic upgrade head`.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = pytest.mark.integration


async def _index_def(session: AsyncSession, name: str) -> str | None:
    row = await session.execute(
        text("SELECT indexdef FROM pg_indexes WHERE indexname = :name"), {"name": name}
    )
    return row.scalar_one_or_none()


def _normalise(sql: str) -> str:
    """Strip what Postgres adds when it echoes a predicate back.

    `WHERE status = 'active'` comes back as `WHERE ((status)::text =
    'active'::text)` — the casts and the parentheses are Postgres's, not ours.
    Comparing raw text would make this test about pg_get_expr's formatting
    rather than about the index.
    """
    return " ".join(sql.replace("::text", "").replace("(", " ").replace(")", " ").split())


async def _constraint(session: AsyncSession, name: str) -> str | None:
    row = await session.execute(
        text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = :name"),
        {"name": name},
    )
    return row.scalar_one_or_none()


# ── The migration actually ran ──────────────────────────────────────────────


async def test_every_table_exists(session: AsyncSession) -> None:
    rows = await session.execute(
        text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    )
    tables = set(rows.scalars())
    expected = {
        "tenants",
        "users",
        "scopes",
        "role_templates",
        "roles",
        "role_scopes",
        "user_roles",
        "signing_keys",
        "refresh_tokens",
        "oauth_clients",
        "oauth_client_secrets",
        "revocation_events",
        "verification_tokens",
        "throttle_buckets",
        "auth_audit_events",
    }
    assert expected <= tables, f"missing: {sorted(expected - tables)}"


# ── Partial indexes: the WHERE clause is the whole point ────────────────────


async def test_an_email_is_unique_per_tenant_among_live_users_only(
    session: AsyncSession,
) -> None:
    """`uq_users_tenant_email`.

    Two properties, and losing either is silent. Without `tenant_id` it becomes
    global, and a tutor genuinely working at two institutions cannot be created.
    Without `WHERE deleted_at IS NULL` an address is poisoned forever once a
    user is removed.
    """
    definition = await _index_def(session, "uq_users_tenant_email")
    assert definition is not None, "the index was never created"
    assert "UNIQUE" in definition
    assert "tenant_id" in definition and "email_normalized" in definition
    assert "deleted_at IS NULL" in definition, definition


async def test_only_one_signing_key_can_be_active(session: AsyncSession) -> None:
    """`uq_signing_keys_one_active` — the rotation invariant.

    Two active keys means tokens signed by either, and a consumer that cached
    the JWKS before the second appeared rejects half of them. The database is
    the only thing that can make that unrepresentable.
    """
    definition = await _index_def(session, "uq_signing_keys_one_active")
    assert definition is not None, "the index was never created"
    assert "UNIQUE" in definition
    assert "status = 'active'" in _normalise(definition), definition


# ── Composite foreign keys: the cross-tenant escalation guard ───────────────


@pytest.mark.parametrize(
    ("name", "columns", "referenced"),
    [
        ("fk_user_roles_user_tenant", ("user_id", "tenant_id"), "users"),
        ("fk_user_roles_role_tenant", ("role_id", "tenant_id"), "roles"),
    ],
)
async def test_a_role_grant_is_validated_against_one_tenant(
    session: AsyncSession, name: str, columns: tuple[str, str], referenced: str
) -> None:
    """The highest-value constraint in this schema.

    If these degraded into two single-column foreign keys, granting a user in
    tenant A a role belonging to tenant B would become a valid row — privilege
    escalation across institutions, caused by a missing WHERE clause rather
    than by an attack.
    """
    definition = await _constraint(session, name)
    assert definition is not None, f"{name} was never created"
    assert definition.startswith("FOREIGN KEY")
    for column in columns:
        assert column in definition, definition
    assert referenced in definition, definition


async def test_a_role_cannot_grant_an_uncatalogued_scope(session: AsyncSession) -> None:
    # RESTRICT, not CASCADE: deleting a scope that roles still grant must fail
    # loudly rather than silently stripping permissions from every role holding
    # it.
    definition = await _constraint(session, "fk_role_scopes_scope_key_scopes")
    assert definition is not None
    assert "scopes" in definition
    assert "CASCADE" not in definition, definition


# ── Seed data: reference data, not fixtures ─────────────────────────────────


async def test_the_scope_catalogue_was_seeded(session: AsyncSession) -> None:
    from app.core.scopes import SCOPE_KEYS

    rows = await session.execute(text("SELECT key FROM scopes"))
    assert set(rows.scalars()) == SCOPE_KEYS


async def test_the_role_templates_were_seeded(session: AsyncSession) -> None:
    from app.core.scopes import ROLE_TEMPLATE_SCOPES

    rows = await session.execute(
        text("SELECT key, default_scopes FROM role_templates ORDER BY key")
    )
    seeded = {key: set(scopes) for key, scopes in rows.all()}
    assert seeded == {k: set(v) for k, v in ROLE_TEMPLATE_SCOPES.items()}


async def test_no_template_grants_a_scope_outside_the_catalogue(
    session: AsyncSession,
) -> None:
    """Would otherwise surface as a foreign-key violation at first provisioning.

    `role_scopes` has a foreign key into `scopes.key`, so a typo in a template
    does not fail here — it fails much later, when a tenant is created.
    """
    rows = await session.execute(
        text(
            "SELECT t.key, s FROM role_templates t, unnest(t.default_scopes) s "
            "WHERE s NOT IN (SELECT key FROM scopes)"
        )
    )
    assert rows.all() == []
