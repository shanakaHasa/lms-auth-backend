"""An institution. Every other row in this database hangs off one."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import CheckConstraint, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk

__all__ = ["Tenant"]


class Tenant(Base, TimestampMixin):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="active", server_default="active"
    )
    # Per-tenant overrides: session lifetimes, password policy, licensed scopes.
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        # The slug appears in a subdomain and in the `tsl` token claim, so it is
        # constrained to what is safe in both.
        CheckConstraint(r"slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'", name="slug_format"),
        CheckConstraint("status IN ('active','suspended','deleted')", name="status_valid"),
    )
