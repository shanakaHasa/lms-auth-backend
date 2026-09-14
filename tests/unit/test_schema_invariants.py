"""Schema invariants.

The comments in the model modules claim the database enforces certain security
properties. These tests hold those claims to account, and they run against the
metadata so they need no database.

Each one corresponds to a way multi-tenant identity systems actually break.
"""

from __future__ import annotations

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, UniqueConstraint

import app.models  # noqa: F401  -- importing registers every table
from app.core.db import Base

TABLES = Base.metadata.tables

EXPECTED_TABLES = {
    "tenants",
    "users",
    "role_templates",
    "roles",
    "scopes",
    "role_scopes",
    "user_roles",
    "refresh_tokens",
    "oauth_clients",
    "oauth_client_secrets",
    "signing_keys",
    "revocation_events",
    "verification_tokens",
    "throttle_buckets",
    "auth_audit_events",
}


def test_every_expected_table_exists() -> None:
    assert set(TABLES) == EXPECTED_TABLES


# ── Cross-tenant isolation ──────────────────────────────────────────────────


def test_users_has_the_composite_unique_that_makes_tenant_scoped_fks_possible() -> None:
    # Postgres will not accept a foreign key into (id, tenant_id) unless a
    # matching unique constraint exists. Without this, the guarantee below is
    # not merely weaker -- it is impossible to declare.
    uniques = {
        tuple(c.name for c in constraint.columns)
        for constraint in TABLES["users"].constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("id", "tenant_id") in uniques


def test_user_roles_validates_both_sides_against_the_same_tenant() -> None:
    """The single most important constraint in this schema.

    A grant is only valid if the user AND the role both belong to the tenant on
    the row. That makes cross-tenant privilege escalation a foreign-key
    violation rather than something a missing WHERE clause can cause.
    """
    fks = [fk for fk in TABLES["user_roles"].constraints if isinstance(fk, ForeignKeyConstraint)]
    composite = [fk for fk in fks if len(fk.columns) == 2]
    assert len(composite) == 2, "expected composite FKs to both users and roles"

    for fk in composite:
        local = {c.name for c in fk.columns}
        assert "tenant_id" in local, f"{fk.name} does not carry tenant_id"
        referred = {element.target_fullname for element in fk.elements}
        assert any(name.endswith(".tenant_id") for name in referred)


def test_roles_are_materialised_per_tenant() -> None:
    # Roles shared across tenants would make the composite FK above impossible,
    # and would mean editing one tenant's role changed another's permissions.
    role_columns = set(TABLES["roles"].columns.keys())
    assert "tenant_id" in role_columns

    uniques = {
        tuple(c.name for c in constraint.columns)
        for constraint in TABLES["roles"].constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("tenant_id", "key") in uniques
    assert ("id", "tenant_id") in uniques


# ── Users ───────────────────────────────────────────────────────────────────


def test_email_is_unique_per_tenant_and_only_among_live_rows() -> None:
    """Not globally unique, and not counting deleted rows.

    Per tenant, because a tutor genuinely works at two institutions and a global
    constraint forces email aliasing forever. Live rows only, so an address
    becomes reusable after the user is deleted.
    """
    index = next(ix for ix in TABLES["users"].indexes if ix.name == "uq_users_tenant_email")
    assert index.unique
    assert [c.name for c in index.columns] == ["tenant_id", "email_normalized"]

    where = str(index.dialect_options["postgresql"]["where"])
    assert "deleted_at IS NULL" in where


def test_password_hash_is_nullable_for_invited_users() -> None:
    # An invited user has no password yet. Login must treat that as a failure
    # indistinguishable from a wrong password, never as a bypass.
    assert TABLES["users"].columns["password_hash"].nullable


def test_users_carry_a_token_version_for_mass_revocation() -> None:
    column = TABLES["users"].columns["token_version"]
    assert not column.nullable


# ── Signing keys ────────────────────────────────────────────────────────────


def test_only_one_signing_key_can_be_active() -> None:
    """Enforced by a partial unique index, not by application discipline.

    A repeated or concurrent rotation then fails as a constraint violation
    instead of leaving two active keys and a fleet that disagrees about which
    one is current.
    """
    index = next(
        ix for ix in TABLES["signing_keys"].indexes if ix.name == "uq_signing_keys_one_active"
    )
    assert index.unique
    assert "status = 'active'" in str(index.dialect_options["postgresql"]["where"])


def test_signing_key_status_is_constrained_to_the_state_machine() -> None:
    checks = [
        str(c.sqltext) for c in TABLES["signing_keys"].constraints if isinstance(c, CheckConstraint)
    ]
    assert any("pending" in c and "active" in c and "revoked" in c for c in checks)


# ── Scopes ──────────────────────────────────────────────────────────────────


def test_scopes_are_a_catalogue_so_a_typo_cannot_be_granted() -> None:
    assert "scopes" in TABLES
    fk = next(
        fk
        for fk in TABLES["role_scopes"].constraints
        if isinstance(fk, ForeignKeyConstraint) and "scope_key" in {c.name for c in fk.columns}
    )
    assert fk.elements[0].target_fullname == "scopes.key"


def test_removing_a_scope_in_use_is_restricted_not_cascaded() -> None:
    # CASCADE here would silently de-authorise every role granting the scope.
    fk = next(
        fk
        for fk in TABLES["role_scopes"].constraints
        if isinstance(fk, ForeignKeyConstraint) and "scope_key" in {c.name for c in fk.columns}
    )
    assert fk.ondelete == "RESTRICT"


# ── Audit ───────────────────────────────────────────────────────────────────


def test_audit_tenant_is_nullable() -> None:
    """Deliberate, and load-bearing.

    A failed login against an unknown email must not have to resolve a tenant
    before it can be recorded -- that resolution would itself be a user
    enumeration oracle.
    """
    assert TABLES["auth_audit_events"].columns["tenant_id"].nullable


def test_audit_records_the_real_reason_separately_from_the_response() -> None:
    # `reason` is what the client is never told. Its existence is what lets the
    # login endpoint return an identical 401 for every failure mode.
    assert "reason" in TABLES["auth_audit_events"].columns


# ── Sessions ────────────────────────────────────────────────────────────────


def test_refresh_tokens_are_unique_by_hash() -> None:
    column = TABLES["refresh_tokens"].columns["token_hash"]
    assert not column.nullable
    uniques = {
        tuple(c.name for c in constraint.columns)
        for constraint in TABLES["refresh_tokens"].constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("token_hash",) in uniques


def test_refresh_tokens_track_a_family_and_a_parent() -> None:
    # family_id is the `sid` claim and the unit of revocation; parent_id is what
    # makes a rotation chain reconstructable during a theft investigation.
    columns = TABLES["refresh_tokens"].columns
    assert not columns["family_id"].nullable
    assert columns["parent_id"].nullable


def test_client_secrets_live_in_their_own_table() -> None:
    # One row per secret, so two can be valid at once -- which is the entire
    # mechanism behind zero-downtime credential rotation.
    assert "oauth_client_secrets" in TABLES
    assert "secret_hash" not in TABLES["oauth_clients"].columns


# ── Tenancy coverage ────────────────────────────────────────────────────────


def test_every_tenant_scoped_table_carries_tenant_id() -> None:
    must_be_scoped = {
        "users",
        "roles",
        "user_roles",
        "refresh_tokens",
        "verification_tokens",
    }
    for name in must_be_scoped:
        assert "tenant_id" in TABLES[name].columns, f"{name} is missing tenant_id"
