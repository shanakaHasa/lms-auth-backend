"""Append-only audit log.

Enforced twice, deliberately: the application database role is granted only
INSERT and SELECT, *and* a BEFORE UPDATE OR DELETE trigger raises. Either alone
is one migration away from being undone by accident.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Index, String, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

__all__ = ["AuthAuditEvent"]


class AuthAuditEvent(Base):
    __tablename__ = "auth_audit_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Nullable on purpose. A failed login against an unknown email must not be
    # forced to resolve a tenant first -- that resolution would itself be a
    # user-enumeration oracle.
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(128))
    subject_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    # The real reason a login failed. Recorded here, never returned to a client.
    reason: Mapped[str | None] = mapped_column(String(64))
    client_id: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64))
    ip_prefix: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        CheckConstraint(
            "actor_type IN ('user','client','system','anonymous')", name="actor_type_valid"
        ),
        CheckConstraint("outcome IN ('success','failure')", name="outcome_valid"),
        Index("ix_auth_audit_tenant_at", "tenant_id", "at"),
        Index("ix_auth_audit_action_at", "action", "at"),
    )
