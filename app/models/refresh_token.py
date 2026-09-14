"""One row per issued refresh token; rotation appends rather than updates.

`family_id` is constant across a whole rotation chain and is the `sid` claim, so
"log out this device" and "which login produced this token" are both one query.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, uuid_pk

__all__ = ["RefreshToken"]


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = uuid_pk()
    family_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    # SHA-256 of a 256-bit random secret. Not Argon2: there is nothing to
    # brute-force in a random value, and refresh is on the user's critical path.
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="SET NULL")
    )
    client_id: Mapped[str | None] = mapped_column(String(64))

    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Set by a single atomic UPDATE. Its presence on a presented token is what
    # reuse detection keys off.
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(32))

    # A /24 or /48 prefix, not a full address: an IP is personal information,
    # and a prefix is enough for the anomaly signal we actually use it for.
    ip_prefix: Mapped[str | None] = mapped_column(String(64))
    ua_hash: Mapped[bytes | None] = mapped_column(LargeBinary)

    __table_args__ = (
        Index("ix_refresh_tokens_user_active", "user_id", "revoked_at"),
        Index("ix_refresh_tokens_family", "family_id"),
        # Drives the expiry reaper.
        Index("ix_refresh_tokens_expires", "expires_at"),
        CheckConstraint(
            "revoked_reason IS NULL OR revoked_reason IN "
            "('rotated','logout','reuse_detected','admin_revoked',"
            "'password_change','user_disabled')",
            name="revoked_reason_valid",
        ),
    )
