"""Shared model building blocks.

Every model module imports from here, and nothing here imports a model — that
one-way rule is what keeps the per-table files free of circular imports.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

__all__ = ["Base", "TimestampMixin", "uuid_pk"]


def uuid_pk() -> Mapped[uuid.UUID]:
    """A UUID primary key generated application-side.

    Knowing the id before the INSERT is what lets a service build a token's
    `sub` claim and its audit row in the same transaction, with no round trip.
    """
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
