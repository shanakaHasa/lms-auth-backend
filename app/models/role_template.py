"""The catalogue of roles a new tenant is provisioned with.

Templates, not shared rows: every tenant gets its own `roles` rows, which is
what makes the composite foreign key on `user_roles` possible at all.
"""

from __future__ import annotations

from sqlalchemy import String, Text, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

__all__ = ["RoleTemplate"]


class RoleTemplate(Base):
    __tablename__ = "role_templates"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    default_scopes: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
