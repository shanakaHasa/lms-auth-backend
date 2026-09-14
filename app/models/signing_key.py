"""RSA keys for RS256, as a state machine.

Rotation is `pending` -> `active` -> `retiring` -> `revoked`. A key must be
published in JWKS (`pending`) for longer than any consumer's cache TTL before it
signs anything, or consumers reject tokens they cannot verify.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Index, LargeBinary, String, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

__all__ = ["SigningKey"]


class SigningKey(Base):
    __tablename__ = "signing_keys"

    # RFC 7638 JWK thumbprint: deterministic, so two environments can never
    # share a kid that maps to different key material.
    kid: Mapped[str] = mapped_column(String(64), primary_key=True)
    alg: Mapped[str] = mapped_column(String(16), nullable=False, server_default="RS256")
    public_jwk: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    # Set for the KMS signer; the private key then never leaves the HSM.
    kms_key_id: Mapped[str | None] = mapped_column(String(512))
    # Set only for LocalSigner, and encrypted at rest. Never populated in prod.
    private_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retire_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("status IN ('pending','active','retiring','revoked')", name="status_valid"),
        # At most one active key, enforced by the database. A concurrent or
        # repeated rotation then fails as a constraint violation instead of
        # leaving the fleet disagreeing about which key is current.
        Index(
            "uq_signing_keys_one_active",
            text("(status)"),
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
    )
