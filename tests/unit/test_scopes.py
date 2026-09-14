"""The scope catalogue, and the one duplication this codebase tolerates.

`app/core/scopes.py` and migration `0001` both define the catalogue and the role
templates. That duplication is deliberate and unavoidable: a migration must
never import application code, or a later refactor silently changes what an old
migration does to a database that already ran it.

What makes the duplication safe is this file. It imports the migration **by
path** — never as a package — and diffs the two. Change one without the other
and the suite says so.
"""

from __future__ import annotations

import importlib.util
from collections import Counter
from pathlib import Path
from types import ModuleType

import pytest

from app.core import scopes as app_scopes

MIGRATION = (
    Path(__file__).resolve().parents[2] / "alembic" / "versions" / "20260101_0900_initial_schema.py"
)


def _load_migration() -> ModuleType:
    """Load `0001` as a standalone module.

    By path, because `alembic/versions/` is not an importable package and must
    not become one — the file names are revision identifiers, not module names.
    """
    spec = importlib.util.spec_from_file_location("initial_schema", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


migration = _load_migration()


# ── The two definitions agree ───────────────────────────────────────────────


def test_the_seeded_catalogue_matches_the_application_constant() -> None:
    assert migration.SCOPE_CATALOGUE == app_scopes.SCOPE_CATALOGUE


def test_the_seeded_role_templates_match_the_application_constant() -> None:
    assert migration.ROLE_TEMPLATE_SCOPES == app_scopes.ROLE_TEMPLATE_SCOPES


def test_the_audiences_agree() -> None:
    assert migration.API_AUDIENCE == app_scopes.API_AUDIENCE
    assert migration.AUTH_AUDIENCE == app_scopes.AUTH_AUDIENCE


# ── Properties the catalogue must hold ──────────────────────────────────────


@pytest.mark.parametrize("role", sorted(app_scopes.ROLE_TEMPLATE_SCOPES))
def test_no_template_grants_a_scope_twice(role: str) -> None:
    """`default_scopes` is `text[]`, which has no uniqueness constraint.

    Provisioning inserts `role_scopes` straight from this array, and that table
    has a primary key on `(role_id, scope_key)`. A duplicate here is therefore
    silent at migration time and fails at the first `create-tenant` — in
    another phase, a long way from the cause.
    """
    scopes = app_scopes.ROLE_TEMPLATE_SCOPES[role]
    duplicates = [scope for scope, count in Counter(scopes).items() if count > 1]
    assert not duplicates, f"{role} grants {duplicates} more than once"


@pytest.mark.parametrize("role", sorted(app_scopes.ROLE_TEMPLATE_SCOPES))
def test_every_template_scope_is_catalogued(role: str) -> None:
    # `role_scopes` has a foreign key into `scopes.key`, so a typo here does not
    # fail at migration time — it fails when a tenant is provisioned.
    unknown = set(app_scopes.ROLE_TEMPLATE_SCOPES[role]) - app_scopes.SCOPE_KEYS
    assert not unknown, f"{role} grants uncatalogued {sorted(unknown)}"


def test_every_scope_is_audienced_to_a_real_service() -> None:
    """The property that stops a scope crossing a service boundary.

    `backend` verifies `aud`, so an auth-admin scope in an LMS token is
    unusable — but only if every scope is audienced deliberately.
    """
    for key, (_, audience, _) in app_scopes.SCOPE_CATALOGUE.items():
        assert audience in (app_scopes.API_AUDIENCE, app_scopes.AUTH_AUDIENCE), key


def test_admin_scopes_are_audienced_to_auth_and_nothing_else() -> None:
    for key, (_, audience, _) in app_scopes.SCOPE_CATALOGUE.items():
        expected = app_scopes.AUTH_AUDIENCE if key.startswith("admin:") else app_scopes.API_AUDIENCE
        assert audience == expected, f"{key} is audienced to {audience}"


def test_every_scope_reaching_student_data_is_flagged_sensitive() -> None:
    # What makes "who can read student PII" answerable without reading every
    # role definition.
    for key in ("students:read", "students:write", "enrolments:write"):
        assert key in app_scopes.SENSITIVE_SCOPES, key


# ── The role hierarchy ──────────────────────────────────────────────────────


def test_an_admin_can_do_everything_a_teacher_can() -> None:
    assert set(app_scopes.ROLE_TEMPLATE_SCOPES["teacher"]) <= set(
        app_scopes.ROLE_TEMPLATE_SCOPES["admin"]
    )


def test_a_tutor_can_propose_but_never_approve() -> None:
    """The separation the whole approval gate rests on.

    `proposals:approve` is deliberately not `students:write`: a tutor may ask
    the assistant to prepare a change, and only a teacher may commit it.
    """
    tutor = set(app_scopes.ROLE_TEMPLATE_SCOPES["tutor"])
    assert "chat:use" in tutor
    assert "proposals:approve" not in tutor
    assert not {s for s in tutor if s.endswith(":write")}


def test_a_teacher_can_create_a_course() -> None:
    # An explicit decision, and the reason `courses:write` moved into the
    # teacher template: otherwise a teacher cannot set up their own class.
    assert "courses:write" in app_scopes.ROLE_TEMPLATE_SCOPES["teacher"]


def test_no_template_grants_auth_admin_scopes_except_admin() -> None:
    for role in ("teacher", "tutor"):
        granted = set(app_scopes.ROLE_TEMPLATE_SCOPES[role])
        assert not {s for s in granted if s.startswith("admin:")}, role


# ── Agreement with the consumer ─────────────────────────────────────────────


def test_the_catalogue_covers_every_scope_the_lms_enforces() -> None:
    """The scopes `backend` actually gates on must all be issuable here.

    A scope backend requires but auth cannot grant is a permanently 403'd
    endpoint, and the failure looks like a permissions bug rather than a
    missing catalogue entry.
    """
    enforced_by_backend = {
        "students:read",
        "students:write",
        "courses:read",
        "courses:write",
        "enrolments:write",
        "materials:read",
        "materials:write",
        "chat:use",
        "proposals:approve",
    }
    assert enforced_by_backend <= app_scopes.SCOPE_KEYS
