"""Turning role templates into a tenant's actual roles.

`role_templates` is a catalogue. `roles` and `role_scopes` are what a tenant
really has, and what `stmt_scopes_for_user` reads on every login. Provisioning
is the step between them, and it runs once per institution.

**This module is pure.** It takes a tenant id and the template constants and
returns ORM instances; it never touches a session. That is what lets the whole
of it be tested before a database exists — and `seed-dev --dry-run` prints
exactly what it would write, which is the half of Step 3's "done when" that is
achievable with no database.

Two properties the planner guarantees, both of which the database would
otherwise catch much later:

* **No duplicate `(role_id, scope_key)`.** `role_scopes` has a primary key on
  that pair, and `default_scopes` is a `text[]` with no uniqueness constraint —
  so a template listing a scope twice would insert twice and violate the key at
  provisioning time, in another phase, far from the cause.
* **Every scope is in the catalogue.** `role_scopes.scope_key` is a foreign key
  into `scopes`, so a typo does not fail here — it fails at the INSERT.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from app.core.scopes import ROLE_TEMPLATE_META, ROLE_TEMPLATE_SCOPES, SCOPE_KEYS
from app.models.role import Role
from app.models.role_scope import RoleScope

__all__ = ["RolePlan", "TenantPlan", "plan_tenant_roles"]


@dataclass(frozen=True)
class RolePlan:
    role: Role
    scopes: tuple[RoleScope, ...]

    @property
    def key(self) -> str:
        return str(self.role.key)


@dataclass(frozen=True)
class TenantPlan:
    """What provisioning a tenant would write. Printable, and assertable."""

    tenant_id: uuid.UUID
    roles: tuple[RolePlan, ...] = field(default_factory=tuple)

    def role(self, key: str) -> RolePlan:
        for plan in self.roles:
            if plan.key == key:
                return plan
        raise KeyError(key)

    def scope_keys(self, role_key: str) -> frozenset[str]:
        return frozenset(str(rs.scope_key) for rs in self.role(role_key).scopes)

    def describe(self) -> list[str]:
        """One line per role, for `seed-dev --dry-run`."""
        return [
            f"  role {plan.key:<8} {len(plan.scopes):>2} scopes  "
            + " ".join(sorted(str(rs.scope_key) for rs in plan.scopes))
            for plan in self.roles
        ]


def plan_tenant_roles(tenant_id: uuid.UUID) -> TenantPlan:
    """Materialise every role template for one tenant.

    Ids are generated here rather than by the database, so the plan is complete
    before anything is written — which is what makes `--dry-run` show the real
    thing rather than an approximation of it.
    """
    plans: list[RolePlan] = []

    for template_key, scope_keys in ROLE_TEMPLATE_SCOPES.items():
        # Deduplicate defensively. The catalogue tests already forbid duplicates,
        # but a duplicate here becomes a primary-key violation at INSERT, and the
        # planner is the last place it can be caught cheaply.
        unique_scopes = sorted(set(scope_keys))

        unknown = set(unique_scopes) - SCOPE_KEYS
        if unknown:
            raise ValueError(
                f"role template {template_key!r} grants uncatalogued scopes: {sorted(unknown)}"
            )

        name, description = ROLE_TEMPLATE_META[template_key]
        role = Role(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            key=template_key,
            name=name,
            description=description,
            # Materialised from a template, so it must not be deleted by hand.
            is_system=True,
            template_key=template_key,
        )
        plans.append(
            RolePlan(
                role=role,
                scopes=tuple(
                    RoleScope(role_id=role.id, scope_key=scope) for scope in unique_scopes
                ),
            )
        )

    return TenantPlan(tenant_id=tenant_id, roles=tuple(plans))
