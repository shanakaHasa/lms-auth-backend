"""A machine-to-machine client. The LMS backend is one."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, uuid_pk

if TYPE_CHECKING:
    from app.models.oauth_client_secret import OAuthClientSecret

__all__ = ["OAuthClient"]


class OAuthClient(Base, TimestampMixin):
    __tablename__ = "oauth_clients"

    id: Mapped[uuid.UUID] = uuid_pk()
    client_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # NULL means a platform client (the LMS backend), not scoped to one tenant.
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE")
    )
    allowed_grant_types: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{client_credentials}'::text[]")
    )
    allowed_scopes: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    allowed_audiences: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    token_lifetime_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="600"
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="active", server_default="active"
    )

    secrets: Mapped[list[OAuthClientSecret]] = relationship(
        back_populates="client", cascade="all, delete-orphan"
    )
