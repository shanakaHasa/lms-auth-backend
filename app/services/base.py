"""Shared service construction rules.

A service holds a tenant (from a verified token, or resolved at login) and one
or more repositories, each carrying a tenant of its own. If they ever disagree,
every check the service makes runs against one tenant while its queries run
against another — which is a cross-tenant read produced by a wiring mistake
rather than by an attack.

`HasTenant` requires `tenant_id: uuid.UUID`, and `GlobalRepository` deliberately
has no such attribute. So passing a global repository here is a **type error**,
not a silently passing check. That is the whole reason the two bases are
separate classes.
"""

from __future__ import annotations

import uuid
from typing import Protocol

__all__ = ["HasTenant", "assert_same_tenant"]


class HasTenant(Protocol):
    tenant_id: uuid.UUID


def assert_same_tenant(tenant_id: uuid.UUID, *repositories: HasTenant) -> None:
    for repository in repositories:
        if repository.tenant_id != tenant_id:
            # A wiring bug, not anything a request can cause — so it is not an
            # AppError with a status code. If this fires in production it should
            # page someone, not return a 4xx.
            raise RuntimeError(
                f"repository is scoped to {repository.tenant_id!r} but the caller "
                f"is acting for {tenant_id!r}"
            )
