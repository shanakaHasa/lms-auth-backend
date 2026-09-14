"""Secrets live here, not on the client, so two can be valid at once.

That is the entire mechanism behind zero-downtime credential rotation: mint the
new secret, let auth accept both, roll the consumer, then revoke the old.
Expand/contract, applied to a credential instead of a schema.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, uuid_pk

if TYPE_CHECKING:
    from app.models.oauth_client import OAuthClient

__all__ = ["OAuthClientSecret"]


class OAuthClientSecret(Base):
    __tablename__ = "oauth_client_secrets"

    id: Mapped[uuid.UUID] = uuid_pk()
    client_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("oauth_clients.id", ondelete="CASCADE"), nullable=False
    )
    secret_hash: Mapped[str] = mapped_column(Text, nullable=False)
    # First few characters, so an operator can identify which secret is which
    # without ever seeing one.
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Checked before revoking the old secret during a rotation: if something
    # used it in the grace window, stop and investigate rather than revoke.
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    client: Mapped[OAuthClient] = relationship(back_populates="secrets")

    __table_args__ = (Index("ix_oauth_client_secrets_client", "client_id"),)
