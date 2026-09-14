"""The permission catalogue.

A table rather than free text. This is the whole reason a typo'd scope cannot be
granted: `role_scopes.scope_key` is a foreign key into here, so 'studnets:write'
fails at the database instead of silently granting nothing.
"""

from __future__ import annotations

from sqlalchemy import Boolean, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

__all__ = ["Scope"]


class Scope(Base):
    __tablename__ = "scopes"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    # Which service the scope is meaningful to. A scope for auth's own admin API
    # must never end up authorising something in the LMS.
    audience: Mapped[str] = mapped_column(String(64), nullable=False)
    # Marks scopes that grant access to student personal information, so an
    # access review can answer "who can read PII" without reading every role.
    is_sensitive: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
