"""Two repository bases, because auth has two kinds of table.

`backend` needed only one: every table there belongs to a tenant. Auth does not.
`signing_keys` are the service's own key material, `scopes` and `role_templates`
are a global catalogue, and `tenants` is the table you must read *before* you
know which tenant you are in.

So there are two bases, and the difference is load-bearing:

* `TenantScopedRepository` takes a tenant at construction and no method accepts
  one, which makes "forgot the WHERE clause" unrepresentable rather than
  something review has to catch.
* `GlobalRepository` has **no `tenant_id` attribute at all**. That is not an
  omission — it is what makes `assert_same_tenant`, whose signature requires
  `tenant_id: str`, refuse to accept one. mypy rejects the mistake before any
  test runs.

The tempting alternative — one base, with global tables passing a sentinel
tenant — is worse than it looks. `assert_same_tenant` would then pass trivially
for them, and the base class would quietly stop meaning anything.

Two conventions hold throughout, both inherited from `backend`:

* **Query construction is a pure function**, separate from execution, so every
  statement can be compiled against the Postgres dialect and asserted on with no
  database running.
* **A row in another tenant is indistinguishable from a row that does not
  exist.** Queries return `None`; services raise `NotFound`. A 403 would confirm
  the row exists.
"""

from __future__ import annotations

import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import Conflict

__all__ = [
    "GlobalRepository",
    "TenantScopedRepository",
    "translate_integrity_error",
]


class _Repository:
    """Shared execution helpers. Not used directly."""

    session: AsyncSession

    async def flush(self, instance: object) -> object:
        """Persist far enough to surface constraint violations here.

        Without the flush a duplicate would not raise until the session commits,
        after the handler has already returned a success and written its audit
        row. Flushing keeps the failure where it can still become a 409.
        """
        self.session.add(instance)
        try:
            await self.session.flush()
        except IntegrityError as exc:
            raise translate_integrity_error(exc) from exc
        return instance


class TenantScopedRepository(_Repository):
    """For tables where every row belongs to one institution."""

    def __init__(self, session: AsyncSession, tenant_id: uuid.UUID) -> None:
        if tenant_id is None:
            # A missing tenant scopes every query to nothing at best, and to
            # everything at worst if a later refactor treats it as "unset".
            raise ValueError("tenant_id is required to build a tenant-scoped repository")
        self.session = session
        self.tenant_id = tenant_id


class GlobalRepository(_Repository):
    """For tables that belong to no tenant.

    `tenants` itself, the scope catalogue, the role templates, this service's
    signing keys, and the M2M clients — the last of which may reference a tenant
    but is not scoped by one, because the LMS backend is a platform client
    belonging to none.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session


_CONSTRAINT_MESSAGES = {
    "uq_users_tenant_email": "a user with that email already exists",
    "uq_tenants_slug": "that institution slug is already taken",
    "uq_roles_tenant_key": "a role with that key already exists",
    "pk_role_scopes": "that role already grants that scope",
    "uq_signing_keys_one_active": "another signing key is already active",
    "uq_oauth_clients_client_id": "that client id is already registered",
    "uq_refresh_tokens_token_hash": "that refresh token already exists",
}


def translate_integrity_error(exc: IntegrityError) -> Conflict:
    """Turn a constraint violation into a 409 a caller can act on.

    The alternative is a 500, which tells the caller nothing and pages someone
    for what is usually an ordinary duplicate submission.
    """
    detail = str(getattr(exc, "orig", exc))
    for constraint, message in _CONSTRAINT_MESSAGES.items():
        if constraint in detail:
            return Conflict(message, detail={"constraint": constraint})
    return Conflict("that change conflicts with an existing record")
