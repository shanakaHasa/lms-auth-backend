"""The SQL, verified without a database.

This service is built end to end before a migration is ever applied, so the
fakes cover the logic but model dictionaries — nothing in them would notice a
column that does not exist, a join to the wrong table, or a tenant predicate
that quietly went missing.

Compiling each statement against the Postgres dialect closes most of that gap:
SQLAlchemy resolves every column against the mapped model and emits real
Postgres, so a typo raises here rather than in Phase 2.

The meta-test at the bottom is what keeps this file honest. Every `stmt_*` in
`app/repositories/` must be classified as tenant-scoped or global, and a new one
that is neither fails the suite — so "I added a query and forgot the tenant
filter" is not something review has to catch.
"""

from __future__ import annotations

import importlib
import pkgutil
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql import Select

import app.repositories as repositories_pkg
from app.repositories import refresh_token as refresh_repo
from app.repositories import role as role_repo
from app.repositories import signing_key as key_repo
from app.repositories import tenant as tenant_repo
from app.repositories import user as user_repo

TENANT = uuid.UUID("11111111-1111-4111-8111-111111111111")
TOKEN_ID = uuid.UUID("33333333-3333-4333-8333-333333333333")
FAMILY_ID = uuid.UUID("44444444-4444-4444-8444-444444444444")
NOW = datetime(2026, 1, 1, tzinfo=UTC)
USER = uuid.UUID("22222222-2222-4222-8222-222222222222")


def sql(statement: Select) -> str:  # type: ignore[type-arg]
    return str(
        statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    )


# Statements whose every query MUST carry the tenant.
TENANT_SCOPED = {
    "user.stmt_get_user": user_repo.stmt_get_user(TENANT, USER),
    "user.stmt_user_by_email": user_repo.stmt_user_by_email(TENANT, "ada@example.com"),
    "user.stmt_user_for_login": user_repo.stmt_user_for_login(TENANT, "ada@example.com"),
    "user.stmt_list_users": user_repo.stmt_list_users(TENANT, limit=10, offset=0),
    "user.stmt_list_users filtered": user_repo.stmt_list_users(
        TENANT, limit=10, offset=0, status="active", query="ada"
    ),
    "user.stmt_count_users": user_repo.stmt_count_users(TENANT),
    "user.stmt_count_users filtered": user_repo.stmt_count_users(
        TENANT, status="active", query="ada"
    ),
    "role.stmt_scopes_for_user": role_repo.stmt_scopes_for_user(TENANT, USER),
    "role.stmt_grants_for_user": role_repo.stmt_grants_for_user(TENANT, USER),
    "role.stmt_role_by_key": role_repo.stmt_role_by_key(TENANT, "teacher"),
    "role.stmt_roles_for_tenant": role_repo.stmt_roles_for_tenant(TENANT),
}

# Statements that MUST NOT carry one. `tenants` is the table you read before you
# know which tenant you are in, so a tenant filter here would be circular.
GLOBAL = {
    "tenant.stmt_tenant_by_slug": tenant_repo.stmt_tenant_by_slug("northgate"),
    "tenant.stmt_tenant_by_id": tenant_repo.stmt_tenant_by_id(TENANT),
    # Signing keys belong to the service, not to an institution. A tenant
    # filter here would make key lookup return nothing.
    "signing_key.stmt_active_key": key_repo.stmt_active_key(),
    "signing_key.stmt_published_keys": key_repo.stmt_published_keys(),
    "signing_key.stmt_key_by_kid": key_repo.stmt_key_by_kid("abc"),
    # Refresh tokens are addressed by their own id and family, never by a
    # tenant -- the token IS the credential, and scoping the lookup by
    # tenant would mean trusting a tenant the caller has not yet proven.
    "refresh_token.stmt_redeem": refresh_repo.stmt_redeem(TOKEN_ID, NOW),
    "refresh_token.stmt_find_used": refresh_repo.stmt_find_used(TOKEN_ID),
    "refresh_token.stmt_revoke_family": refresh_repo.stmt_revoke_family(
        FAMILY_ID, NOW, "reuse_detected"
    ),
}


# ── Properties every statement must hold ────────────────────────────────────


@pytest.mark.parametrize("name", sorted(TENANT_SCOPED | GLOBAL))
def test_every_statement_compiles_to_postgres(name: str) -> None:
    # Compilation resolves every column against the mapped model, so a renamed
    # or misspelled attribute fails here instead of in Phase 2.
    assert sql((TENANT_SCOPED | GLOBAL)[name]).strip()


@pytest.mark.parametrize("name", sorted(TENANT_SCOPED))
def test_tenant_scoped_statements_carry_the_tenant(name: str) -> None:
    """The single most important assertion in this file.

    Tenant scoping is structural — the repository is built with a tenant and no
    method accepts one — but "structural" is a claim about Python that has to be
    checked against the SQL actually emitted.
    """
    rendered = sql(TENANT_SCOPED[name])
    assert f"tenant_id = '{TENANT}'" in rendered, rendered


@pytest.mark.parametrize("name", sorted(GLOBAL))
def test_global_statements_carry_no_tenant(name: str) -> None:
    """Asserting an absence, which is the half people forget.

    A tenant filter added to a global query does not fail loudly — it returns
    nothing, and the symptom is "login says my institution does not exist".

    Checked against the WHERE clause alone: `tenant_id` appears in the selected
    and RETURNING columns of several of these, which is fine. What must not
    appear is a tenant *predicate*.
    """
    assert "tenant_id" not in _where(sql(GLOBAL[name]))


# ── Soft deletion ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    [
        "user.stmt_get_user",
        "user.stmt_user_by_email",
        "user.stmt_user_for_login",
        "user.stmt_list_users",
        "user.stmt_count_users",
    ],
)
def test_no_user_query_can_see_a_deleted_row(name: str) -> None:
    # The partial unique index is `WHERE deleted_at IS NULL`. A query that
    # ignored it would disagree with the index about whether an address is free.
    assert "deleted_at IS NULL" in sql(TENANT_SCOPED[name])


def test_the_login_lookup_does_not_filter_on_status() -> None:
    """Load the disabled user, then fail — do not filter them out in SQL.

    Filtering here would make a disabled account return faster than a wrong
    password, and response time alone would then reveal which addresses are real
    and which are still enabled. The status check belongs after the Argon2
    verify, not before it.
    """
    # The WHERE clause only: `status` is naturally in the SELECT list, because
    # the login service needs to read it in order to fail on it afterwards.
    predicate = _where(sql(TENANT_SCOPED["user.stmt_user_for_login"]))
    assert "status" not in predicate, predicate
    # And it must be identical to the ordinary lookup, so the two cannot drift.
    assert predicate == _where(sql(TENANT_SCOPED["user.stmt_user_by_email"]))


# ── Scope resolution: the query login runs every time ───────────────────────


def test_scope_resolution_is_one_query() -> None:
    # Loading roles then scopes per role puts a round trip per role on the
    # login path.
    rendered = sql(TENANT_SCOPED["role.stmt_scopes_for_user"])
    assert rendered.count("SELECT") == 1, rendered
    assert "JOIN user_roles" in rendered


def test_scope_resolution_filters_the_grant_not_the_role() -> None:
    """`user_roles.tenant_id`, not `roles.tenant_id`.

    Those are equal today only because of the composite foreign key. Filtering
    the grant keeps the query correct if that constraint is ever relaxed — and
    it is the grant, not the role, that authorises.
    """
    rendered = sql(TENANT_SCOPED["role.stmt_scopes_for_user"])
    assert f"user_roles.tenant_id = '{TENANT}'" in rendered, rendered


def test_scope_resolution_deduplicates() -> None:
    # Two roles granting the same scope must not produce it twice, or the
    # space-delimited `scope` claim carries duplicates.
    assert "DISTINCT" in sql(TENANT_SCOPED["role.stmt_scopes_for_user"])


def test_scope_resolution_returns_scope_keys_not_roles() -> None:
    # Roles never enter a token. Putting role names in one invites consumers to
    # make policy decisions that belong in this service.
    rendered = sql(TENANT_SCOPED["role.stmt_scopes_for_user"])
    assert "role_scopes.scope_key" in rendered
    assert "FROM role_scopes" in rendered


# ── Counts agree with their lists ───────────────────────────────────────────


def _where(rendered: str) -> str:
    body = rendered.split("WHERE ", 1)[1]
    for tail in (" ORDER BY ", " LIMIT ", " OFFSET ", " RETURNING "):
        body = body.split(tail, 1)[0]
    return " ".join(body.split())


@pytest.mark.parametrize(
    ("listed", "counted"),
    [
        ("user.stmt_list_users", "user.stmt_count_users"),
        ("user.stmt_list_users filtered", "user.stmt_count_users filtered"),
    ],
)
def test_a_count_filters_exactly_as_its_list_does(listed: str, counted: str) -> None:
    # If they diverged, every pager would offer pages that do not exist.
    assert _where(sql(TENANT_SCOPED[listed])) == _where(sql(TENANT_SCOPED[counted]))


def test_listing_users_has_a_total_order() -> None:
    assert "ORDER BY users.email_normalized, users.id" in sql(TENANT_SCOPED["user.stmt_list_users"])


# ── Tenants ─────────────────────────────────────────────────────────────────


def test_a_suspended_institution_cannot_be_resolved() -> None:
    # Login resolves a slug before it does anything else. A suspended tenant
    # must not be able to log anyone in, and the cheapest place to enforce that
    # is the lookup itself.
    assert "status = 'active'" in sql(GLOBAL["tenant.stmt_tenant_by_slug"])


# ── The meta-test ───────────────────────────────────────────────────────────


def discovered_statements() -> set[str]:
    """Every `stmt_*` exported by every repository module."""
    found: set[str] = set()
    for module in pkgutil.iter_modules(repositories_pkg.__path__):
        if module.name == "base":
            continue
        imported = importlib.import_module(f"app.repositories.{module.name}")
        found |= {
            f"{module.name}.{name}"
            for name in getattr(imported, "__all__", [])
            if name.startswith("stmt_")
        }
    return found


def test_every_exported_statement_is_compiled_here() -> None:
    """A new query must be classified as tenant-scoped or global — never neither.

    This is what keeps the file honest once it stops being new. Without it,
    someone adds `stmt_users_by_something` six months from now, nobody adds it
    here, and the tenant filter it forgot is checked by nothing.

    Keyed on the statement function names rather than on counts: an earlier
    version of this test compared how many entries each module had against how
    many it exported, which passed happily when a module had more variants than
    functions — that is, it could not fail.
    """
    compiled = {key.split(" ", 1)[0] for key in TENANT_SCOPED | GLOBAL}
    missing = discovered_statements() - compiled
    assert not missing, (
        "these statements are exported by a repository but compiled by no test "
        f"in this file: {sorted(missing)}"
    )


def test_the_buckets_name_only_real_statements() -> None:
    # The other direction: a renamed function would otherwise leave an entry
    # that passes by testing something that no longer exists.
    compiled = {key.split(" ", 1)[0] for key in TENANT_SCOPED | GLOBAL}
    assert not compiled - discovered_statements()


def test_no_statement_is_in_both_buckets() -> None:
    # Tenant-scoped and global are contradictory claims: one asserts the tenant
    # is present, the other that it is absent.
    assert not set(TENANT_SCOPED) & set(GLOBAL)


# ── Key publication: wider than the active key, deliberately ────────────────


def test_the_published_key_set_is_wider_than_the_active_key() -> None:
    """The classic rotation outage is publishing only the active key.

    A consumer holding a cached JWKS needs the OLD key to verify tokens already
    in flight, and the NEW one to be there before the first token signed with it
    arrives. Publishing only `active` breaks both ends of the window.
    """
    published = sql(GLOBAL["signing_key.stmt_published_keys"])
    for status in ("pending", "active", "retiring"):
        assert f"'{status}'" in published, status


def test_a_revoked_key_is_never_published() -> None:
    # `revoked` is the state for a key believed compromised. Continuing to
    # publish it would defeat revoking it.
    assert "'revoked'" not in sql(GLOBAL["signing_key.stmt_published_keys"])


def test_only_one_key_can_be_selected_as_active() -> None:
    assert "status = 'active'" in sql(GLOBAL["signing_key.stmt_active_key"])
