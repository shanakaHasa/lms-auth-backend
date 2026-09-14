"""Encrypting the signing key before it is stored.

`signing_keys.private_key_encrypted` is `LargeBinary` and the model says
"encrypted at rest". Nothing implemented that, so without this module the column
would hold a plaintext PEM and the docstring would be a lie — which is worse
than storing it in the clear and saying so, because the next person reads the
docstring and believes it.

AES-256-GCM, because it authenticates as well as encrypts: a tampered
ciphertext fails to decrypt rather than yielding a different key. The nonce is
random per wrap and stored as a prefix, so re-wrapping the same key twice
produces different bytes — which matters because a database dump should not
reveal that two rows hold the same key.

This is envelope encryption with a local key-encryption key. Production should
use an Azure Key Vault key instead, and `Signer` is already a protocol so that
swap does not reach this module at all.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = ["KEK_BYTES", "generate_kek", "resolve_kek", "unwrap", "wrap"]

KEK_BYTES = 32  # AES-256
NONCE_BYTES = 12  # 96 bits, the size GCM is specified for


def generate_kek() -> str:
    """A new key-encryption key, base64 for putting in configuration."""
    return base64.b64encode(os.urandom(KEK_BYTES)).decode("ascii")


def _load_kek(kek_b64: str) -> bytes:
    try:
        kek = base64.b64decode(kek_b64, validate=True)
    except Exception as exc:
        raise ValueError("key encryption key is not valid base64") from exc
    if len(kek) != KEK_BYTES:
        raise ValueError(f"key encryption key must be {KEK_BYTES} bytes, got {len(kek)}")
    return kek


def wrap(plaintext: bytes, kek_b64: str) -> bytes:
    """Encrypt, returning `nonce || ciphertext`.

    The nonce is not secret — it only has to be unique per key. Storing it
    alongside is standard, and keeps the column a single opaque blob rather than
    two that could get separated.
    """
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(_load_kek(kek_b64)).encrypt(nonce, plaintext, None)


def unwrap(blob: bytes, kek_b64: str) -> bytes:
    if len(blob) <= NONCE_BYTES:
        raise ValueError("wrapped blob is too short to contain a nonce")
    nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    try:
        return AESGCM(_load_kek(kek_b64)).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        # Either the KEK is wrong or the ciphertext was altered. The two are
        # deliberately indistinguishable — telling them apart would help an
        # attacker who can write to the database work out which.
        raise ValueError("could not decrypt: wrong key, or the data was altered") from exc


# Used only when APP_ENV=local and no key is configured. Publicly known by
# design: it exists so a developer can run the service without ceremony, and the
# production guard refuses to boot without a real one. Same reasoning as
# AUTH_DISABLED in backend -- make the insecure path obvious and impossible in
# production, rather than absent and therefore improvised badly.
# b"DEVELOPMENT-ONLY-KEK-DO-NOT-USE!" -- exactly 32 bytes.
_DEV_KEK = "REVWRUxPUE1FTlQtT05MWS1LRUstRE8tTk9ULVVTRSE="


def resolve_kek() -> str:
    """The key-encryption key, or a loud development stand-in."""
    from app.core.config import settings
    from app.core.logging import get_logger

    if settings.local_key_encryption_key:
        return settings.local_key_encryption_key
    if settings.is_local:
        get_logger(__name__).warning(
            "using_development_key_encryption_key",
            detail="LOCAL_KEY_ENCRYPTION_KEY is unset; signing keys are wrapped "
            "with a publicly known value. Set it for anything but local.",
        )
        return _DEV_KEK
    raise RuntimeError(
        f"LOCAL_KEY_ENCRYPTION_KEY is required outside APP_ENV=local (base64 of {KEK_BYTES} bytes)"
    )
