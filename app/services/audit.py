"""The authentication audit trail.

This lands before any feature code rather than at the hardening step, because
the enumeration defence in login *is* "the real reason goes to the audit log
only". A login service built without somewhere to put that reason would have to
either leak it to the caller or throw it away, and both are wrong.

Written through the **same session** as the action it records, so the two commit
together. An audit row in its own transaction can succeed while the action rolls
back — and a log that records things which did not happen is worse than no log,
because it is trusted.

Three fields carry the weight:

* `outcome` — `success` or `failure`, so "how many failures for this account
  today" is one indexed query rather than an inference.
* `reason` — the real cause of a failure (`unknown_user`, `bad_password`,
  `disabled`, `locked`). **Recorded here and never returned to a caller**: the
  whole point of the identical-401 defence is that the client cannot tell these
  apart, and this is where the information goes instead.
* `tenant_id` — nullable, deliberately. A failed login against an unknown email
  must not be forced to resolve a tenant first, because that resolution would
  itself be an enumeration oracle.
"""

from __future__ import annotations

import uuid
from typing import Any, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import request_id_ctx
from app.models.auth_audit_event import AuthAuditEvent

__all__ = ["AuditSink", "SqlAuditSink"]


class AuditSink(Protocol):
    """What a service needs in order to leave a trail."""

    def record(
        self,
        action: str,
        *,
        outcome: str,
        actor_type: str = "user",
        actor_id: str | None = None,
        tenant_id: uuid.UUID | None = None,
        subject_user_id: uuid.UUID | None = None,
        reason: str | None = None,
        client_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None: ...


class SqlAuditSink:
    """Appends to `auth_audit_events` in the caller's transaction.

    Synchronous and non-awaiting on purpose: it only stages an INSERT on the
    session. Making it `async` would imply it does I/O of its own and invite
    someone to commit it separately, which is exactly the failure this design
    exists to prevent.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def record(
        self,
        action: str,
        *,
        outcome: str,
        actor_type: str = "user",
        actor_id: str | None = None,
        tenant_id: uuid.UUID | None = None,
        subject_user_id: uuid.UUID | None = None,
        reason: str | None = None,
        client_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.session.add(
            AuthAuditEvent(
                tenant_id=tenant_id,
                actor_type=actor_type,
                actor_id=actor_id,
                subject_user_id=subject_user_id,
                action=action,
                outcome=outcome,
                reason=reason,
                client_id=client_id,
                # Ties the row to this request's log lines, so "what else did
                # this actor do in that request" is answerable.
                request_id=request_id_ctx.get(),
                event_metadata=metadata or {},
            )
        )
