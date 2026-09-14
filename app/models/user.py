"""A person who can sign in. Belongs to exactly one institution."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, uuid_pk

if TYPE_CHECKING:
    from app.models.tenant import Tenant

__all__ = ["User"]


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False
    )
    # `email` keeps the form the user typed; `email_normalized` is what the
    # unique index and every lookup use. Normalisation is trim + lowercase only
    # -- provider-specific tricks like stripping gmail dots surprise people.
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    email_normalized: Mapped[str] = mapped_column(String(320), nullable=False)
    # NULL means invited but never activated. Login must treat that as a failure
    # indistinguishable from a wrong password.
    password_hash: Mapped[str | None] = mapped_column(Text)
    password_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    full_name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="invited")
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Bumped to invalidate every outstanding access token for this user. Tokens
    # carry it as `tv`; a consumer rejects any token whose `tv` is behind. This
    # is the revocation predicate that does not depend on clock agreement.
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    tenant: Mapped[Tenant] = relationship()

    __table_args__ = (
        # Exists purely so user_roles can carry a composite FK into (id, tenant_id).
        UniqueConstraint("id", "tenant_id", name="uq_users_id_tenant"),
        # Unique PER TENANT, and only among live rows -- so an address becomes
        # reusable after a user is deleted.
        Index(
            "uq_users_tenant_email",
            "tenant_id",
            "email_normalized",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_users_tenant_status", "tenant_id", "status"),
        CheckConstraint("status IN ('invited','active','disabled','deleted')", name="status_valid"),
    )
