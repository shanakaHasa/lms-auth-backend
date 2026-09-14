"""A named bundle of scopes, materialised per tenant."""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk

__all__ = ["Role"]


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # System roles are materialised from a template and should not be deleted.
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    template_key: Mapped[str | None] = mapped_column(
        ForeignKey("role_templates.key", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "key", name="uq_roles_tenant_key"),
        # Counterpart to the users constraint, for the composite FK on user_roles.
        UniqueConstraint("id", "tenant_id", name="uq_roles_id_tenant"),
    )
