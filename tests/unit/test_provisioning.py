"""Turning role templates into a tenant's roles — entirely pure, entirely tested.

The planner is where a bad template stops being cheap to fix. `role_scopes` has
a primary key on `(role_id, scope_key)` and a foreign key into `scopes.key`, so
a duplicate or a typo in a template does not fail when the template is written —
it fails at the INSERT, during provisioning, in another phase.
"""

from __future__ import annotations

import uuid
from collections import Counter

import pytest

from app.core.scopes import ROLE_TEMPLATE_SCOPES, SCOPE_KEYS
from app.services.provisioning import plan_tenant_roles

TENANT = uuid.UUID("11111111-1111-4111-8111-111111111111")


def test_every_template_becomes_a_role() -> None:
    plan = plan_tenant_roles(TENANT)
    assert {p.key for p in plan.roles} == set(ROLE_TEMPLATE_SCOPES)


def test_every_role_belongs_to_the_requested_tenant() -> None:
    # The composite foreign key on user_roles validates the role against the
    # same tenant as the user, so a role planned for the wrong one would make
    # every grant fail at the database.
    plan = plan_tenant_roles(TENANT)
    assert all(p.role.tenant_id == TENANT for p in plan.roles)


def test_roles_carry_the_scopes_their_template_declares() -> None:
    plan = plan_tenant_roles(TENANT)
    for key, expected in ROLE_TEMPLATE_SCOPES.items():
        assert plan.scope_keys(key) == frozenset(expected)


def test_a_teacher_can_create_a_course() -> None:
    # The decision that moved courses:write into the teacher template.
    assert "courses:write" in plan_tenant_roles(TENANT).scope_keys("teacher")


def test_a_tutor_gets_no_write_scope_at_all() -> None:
    tutor = plan_tenant_roles(TENANT).scope_keys("tutor")
    assert not {s for s in tutor if s.endswith(":write")}
    assert "proposals:approve" not in tutor


@pytest.mark.parametrize("role_key", sorted(ROLE_TEMPLATE_SCOPES))
def test_no_role_grants_the_same_scope_twice(role_key: str) -> None:
    """`pk_role_scopes (role_id, scope_key)` would reject the second row.

    `default_scopes` is a `text[]` with no uniqueness constraint, so a template
    listing a scope twice is silent until provisioning runs.
    """
    scopes = [str(rs.scope_key) for rs in plan_tenant_roles(TENANT).role(role_key).scopes]
    duplicates = [s for s, n in Counter(scopes).items() if n > 1]
    assert not duplicates, duplicates


def test_every_planned_scope_exists_in_the_catalogue() -> None:
    # `role_scopes.scope_key` is a foreign key into `scopes`, so a typo fails at
    # the INSERT rather than where it was written.
    plan = plan_tenant_roles(TENANT)
    for role_plan in plan.roles:
        assert {str(rs.scope_key) for rs in role_plan.scopes} <= SCOPE_KEYS


def test_an_uncatalogued_scope_is_refused_by_the_planner(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Caught here, with a message naming the template.

    Without this the failure is a foreign-key violation at provisioning time,
    whose message names a constraint rather than the template that is wrong.
    """
    monkeypatch.setattr(
        "app.services.provisioning.ROLE_TEMPLATE_SCOPES",
        {"teacher": ("students:read", "not:a:real:scope")},
    )
    with pytest.raises(ValueError, match="not:a:real:scope"):
        plan_tenant_roles(TENANT)


def test_two_tenants_get_different_role_ids() -> None:
    # Roles are per tenant. Sharing an id would let a grant in one institution
    # authorise in another.
    first = plan_tenant_roles(TENANT)
    second = plan_tenant_roles(uuid.uuid4())
    assert {p.role.id for p in first.roles}.isdisjoint(p.role.id for p in second.roles)


def test_ids_are_generated_before_anything_is_written() -> None:
    # What makes `seed-dev --dry-run` show the real plan rather than an
    # approximation of it.
    plan = plan_tenant_roles(TENANT)
    for role_plan in plan.roles:
        assert role_plan.role.id is not None
        assert all(rs.role_id == role_plan.role.id for rs in role_plan.scopes)


def test_roles_are_marked_as_system() -> None:
    # Materialised from a template, so deleting one by hand would leave a tenant
    # unable to grant a standard role.
    assert all(p.role.is_system for p in plan_tenant_roles(TENANT).roles)
    assert all(p.role.template_key == p.key for p in plan_tenant_roles(TENANT).roles)


def test_the_plan_describes_itself_for_a_dry_run() -> None:
    lines = plan_tenant_roles(TENANT).describe()
    assert len(lines) == len(ROLE_TEMPLATE_SCOPES)
    assert any("teacher" in line and "courses:write" in line for line in lines)
