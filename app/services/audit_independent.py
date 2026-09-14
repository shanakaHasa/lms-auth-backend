"""Audit rows that must survive the rollback of the thing they describe.

`SqlAuditSink` writes in the caller's transaction, which is right for anything
that *succeeds*: an action must not be able to commit without its audit row.

A failed login is the opposite case, and the distinction is easy to miss. The
request raises `InvalidCredentials`, `get_session` rolls the transaction back,
and an in-transaction audit row is rolled back with it — so the failure leaves
no trace at all. That is not a small gap: it defeats the enumeration design
(whose whole premise is that the real reason goes to the log), it makes lockout
impossible to build on, and it means "why can this person not sign in" has no
answer.

So failures get their own short transaction. The cost is that a failure row can
be written when the surrounding request later errors for some unrelated reason —
an audit row for an attempt that did happen, attached to a request that went on
to fail. That is the right direction to be wrong in: over-recording an
authentication attempt is safe, under-recording one is not.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger, request_id_ctx
from app.models.auth_audit_event import AuthAuditEvent

__all__ = ["IndependentAuditSink"]

log = get_logger(__name__)


class IndependentAuditSink:
    """Writes one row per call, in its own transaction, and commits it."""

    def __init__(self, session_factory: Callable[[], AsyncSession]) -> None:
        self._session_factory = session_factory

    async def record(
        self,
        action: str,
        *,
        outcome: str,
        actor_type: str = "anonymous",
        actor_id: str | None = None,
        tenant_id: uuid.UUID | None = None,
        subject_user_id: uuid.UUID | None = None,
        reason: str | None = None,
        client_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        try:
            async with self._session_factory() as session:
                session.add(
                    AuthAuditEvent(
                        tenant_id=tenant_id,
                        actor_type=actor_type,
                        actor_id=actor_id,
                        subject_user_id=subject_user_id,
                        action=action,
                        outcome=outcome,
                        reason=reason,
                        client_id=client_id,
                        request_id=request_id_ctx.get(),
                        event_metadata=metadata or {},
                    )
                )
                await session.commit()
        except Exception as exc:
            # Never let auditing turn a 401 into a 500. A lost audit row is bad;
            # a login endpoint that breaks when the audit table is unavailable
            # is worse, and would be a denial of service triggered by writing to
            # one table.
            log.error("audit_write_failed", action=action, reason=reason, error=str(exc))
