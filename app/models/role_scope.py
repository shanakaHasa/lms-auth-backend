"""Which scopes a role grants."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

__all__ = ["RoleScope"]


class RoleScope(Base):
    __tablename__ = "role_scopes"

    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    # RESTRICT, not CASCADE: removing a scope from the catalogue while roles
    # still grant it should fail loudly rather than quietly de-authorising
    # people.
    scope_key: Mapped[str] = mapped_column(
        ForeignKey("scopes.key", ondelete="RESTRICT"), primary_key=True
    )
