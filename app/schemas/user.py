"""Request and response shapes for users.

`tenant_id` appears in none of them. It comes from a verified token, or from the
slug resolved at login, and is applied by the repository — so there is no field
a caller could set to reach another institution.

Normalisation is **trim and lowercase, nothing else**. Provider-specific tricks
like stripping dots from Gmail addresses or cutting everything after a `+` are
tempting and wrong: they surprise people, they differ per provider, and they
would make `ada+work@example.com` and `ada@example.com` the same account for one
provider and not another. The unique index depends on this function, so whatever
it does becomes the definition of identity.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

__all__ = [
    "USER_STATUSES",
    "UserCreate",
    "UserInvite",
    "UserOut",
    "UserSummary",
    "normalise_email",
]

UserStatus = Literal["invited", "active", "disabled", "deleted"]
# Mirrors the CHECK constraint on `users.status`; a test asserts they agree.
USER_STATUSES: frozenset[str] = frozenset({"invited", "active", "disabled", "deleted"})

FullName = Annotated[str, Field(min_length=1, max_length=255)]
RoleKey = Annotated[str, Field(min_length=1, max_length=64)]


def normalise_email(email: str) -> str:
    """The form the unique index and every lookup use.

    Case and surrounding whitespace are not identity. `EmailStr` already
    lowercases the domain, so only the local part is left to fold — but folding
    unconditionally means this function, rather than a validator's internals, is
    what the index depends on.
    """
    return email.strip().lower()


class UserCreate(BaseModel):
    """A user with a password, created directly. Used by `seed-dev` and admins."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str
    full_name: FullName | None = None
    role_keys: list[RoleKey] = Field(default_factory=list)

    @field_validator("full_name")
    @classmethod
    def _strip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("must not be blank")
        return stripped


class UserInvite(BaseModel):
    """A user with **no** password.

    `password_hash` stays NULL until they activate. Login must treat that as a
    failure indistinguishable from a wrong password — an invited-but-never-
    activated account that failed differently would tell an attacker the address
    is real.
    """

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    full_name: FullName | None = None
    role_keys: list[RoleKey] = Field(default_factory=list)


class UserSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str | None
    status: str


class UserOut(UserSummary):
    """The full record.

    `password_hash`, `token_version` and `failed_login_count` are deliberately
    absent. The first is obvious; the second and third are internal machinery
    whose values would tell a caller how close an account is to lockout.
    """

    model_config = ConfigDict(from_attributes=True)

    email_verified_at: datetime | None
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime
