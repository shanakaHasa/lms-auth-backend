"""Opaque refresh tokens.

A refresh token is **not** a JWT. It carries no claims, means nothing to anyone
but this service, and is checked by looking it up — which is the point. An
access token is verified offline precisely so auth stays out of the hot path;
a refresh token is the opposite, deliberately, because rotation and reuse
detection require a database round trip. Making it a JWT would tempt a consumer
to trust it without asking.

The format is `rt1_<uuid>.<secret>`:

* `rt1_` is a version prefix. Changing the scheme later is then a new prefix
  rather than a guess about what an unrecognised string might be.
* The **uuid is the row id**, so redemption is a primary-key lookup rather than
  a scan over a hash column. That matters because redemption happens inside a
  single atomic UPDATE, and the predicate wants to be as cheap as possible.
* The **secret is 256 bits of randomness**, and only its SHA-256 is stored.

SHA-256 and not Argon2, which looks wrong until you notice there is nothing to
brute-force: the secret is uniformly random, not a human-chosen password. Argon2
here would add tens of milliseconds to every refresh in exchange for resisting
an attack that cannot be mounted.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid

__all__ = ["PREFIX", "hash_secret", "new_refresh_token", "parse_refresh_token"]

PREFIX = "rt1_"
SECRET_BYTES = 32  # 256 bits


def hash_secret(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def new_refresh_token() -> tuple[str, uuid.UUID, bytes]:
    """Returns the token to hand out, its row id, and the hash to store.

    The plaintext is returned once and never again — there is no code path that
    can recover it from the row, which is what makes a database leak
    insufficient to mint a session.
    """
    token_id = uuid.uuid4()
    secret = secrets.token_urlsafe(SECRET_BYTES)
    return f"{PREFIX}{token_id}.{secret}", token_id, hash_secret(secret)


def parse_refresh_token(presented: str) -> tuple[uuid.UUID, str] | None:
    """Split a presented token, or return None if it is not one of ours.

    Returns `None` rather than raising for every malformed shape, because the
    caller treats "not a token" and "not a valid token" identically — telling
    them apart would leak whether a given id exists.
    """
    if not presented.startswith(PREFIX):
        return None
    body = presented[len(PREFIX) :]
    if body.count(".") != 1:
        return None

    raw_id, secret = body.split(".", 1)
    if not secret:
        return None
    try:
        return uuid.UUID(raw_id), secret
    except ValueError:
        return None


def secret_matches(secret: str, stored_hash: bytes) -> bool:
    """Constant-time comparison.

    The id half of the token is public in the sense that it is a lookup key, so
    an attacker who guesses one still has to produce the secret. Comparing with
    `==` would leak how much of a guess was right, one byte at a time.
    """
    return hmac.compare_digest(hash_secret(secret), stored_hash)
