"""Fixed-window counters, in Postgres rather than in memory.

With N containers, in-process counters give an effective limit of N times the
intended one -- silently wrong, and wrong in the permissive direction. Redis
would work too, but it puts a new production dependency directly in the login
path for a service that already has a database there.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

__all__ = ["ThrottleBucket"]


class ThrottleBucket(Base):
    __tablename__ = "throttle_buckets"

    bucket_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    __table_args__ = (Index("ix_throttle_buckets_window", "window_start"),)
