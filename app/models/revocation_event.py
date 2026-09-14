"""The feed consumers poll to honour a revocation before a token expires.

Access tokens are verified offline, so they cannot be withdrawn mid-life. This
is the compensating control, and it is eventually consistent by construction --
roughly 60 seconds, not instant.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

__all__ = ["RevocationEvent"]


class RevocationEvent(Base):
    __tablename__ = "revocation_events"

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    subject_type: Mapped[str] = mapped_column(String(16), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    # Tokens issued before this instant are rejected.
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Tokens whose `tv` is below this are rejected. Immune to clock skew, which
    # is why it exists alongside not_before.
    min_token_version: Mapped[int | None] = mapped_column(Integer)
    reason: Mapped[str | None] = mapped_column(String(64))
    # When this entry may be dropped: once no token issued before `not_before`
    # could still be valid. Keeps the consumer's in-memory set bounded.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "subject_type IN ('user','tenant','session','jti','client')",
            name="subject_type_valid",
        ),
        Index("ix_revocation_events_expires", "expires_at"),
    )
