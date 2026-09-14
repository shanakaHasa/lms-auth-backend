"""JWK construction and the RFC 7638 thumbprint.

`kid` is the one value both services must agree on byte for byte: auth stamps it
into every token header, and backend uses it to pick a key out of the cached
JWKS. Get it wrong and every token fails with "unknown signing key".

So it is **derived, not assigned** — the RFC 7638 thumbprint is a SHA-256 over a
canonical JSON form of the public key. Two consequences follow, and both are the
reason for choosing it over a random id:

* The same key always produces the same `kid`, so re-importing a key or
  restoring a backup cannot produce a second identifier for one key.
* Two environments can never share a `kid` that maps to *different* key
  material, because the id is a function of the material.

The canonicalisation is exact and unforgiving: for RSA, a JSON object with
**only** `e`, `kty`, `n`, in **lexicographic order**, **no whitespace**, UTF-8,
then SHA-256, then base64url with the padding stripped. A stray space produces a
different, silently wrong id — which is why `test_crypto_jwks.py` pins this
against the worked example in RFC 7638 §3.1 rather than against our own output.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

__all__ = [
    "b64u_decode",
    "b64u_encode",
    "jwks_document",
    "public_jwk",
    "rfc7638_thumbprint",
]


def b64u_encode(data: bytes) -> str:
    """base64url without padding, as every JOSE value is encoded."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _int_to_b64u(value: int) -> str:
    # Big-endian, minimum number of octets, per RFC 7518.
    length = (value.bit_length() + 7) // 8
    return b64u_encode(value.to_bytes(length, "big"))


def rfc7638_thumbprint(jwk: dict[str, Any]) -> str:
    """The canonical `kid` for a key.

    Only the **required** members participate — for RSA that is `e`, `kty`, `n`.
    Including `alg` or `use` would make the id depend on metadata rather than on
    key material, and the same key described two ways would get two ids.
    """
    kty = jwk["kty"]
    if kty != "RSA":
        raise ValueError(f"unsupported key type for thumbprint: {kty!r}")

    # `sort_keys` gives lexicographic order; the separators strip every space.
    canonical = json.dumps(
        {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return b64u_encode(hashlib.sha256(canonical).digest())


def public_jwk(public_key: rsa.RSAPublicKey, *, alg: str = "RS256") -> dict[str, Any]:
    """The public half of an RSA key, as a JWK.

    **Only the public half.** There is deliberately no code path here that can
    emit `d`, `p`, `q`, `dp`, `dq` or `qi` — this function takes an
    `RSAPublicKey`, so the private components are not even reachable from it.
    That is a stronger guarantee than remembering to filter them out, and a test
    asserts the serialised document contains none of them.
    """
    numbers = public_key.public_numbers()
    jwk = {
        "kty": "RSA",
        "n": _int_to_b64u(numbers.n),
        "e": _int_to_b64u(numbers.e),
    }
    # The thumbprint is computed over the required members only, so it must be
    # taken before `alg` and `use` are added.
    return {
        **jwk,
        "kid": rfc7638_thumbprint(jwk),
        "alg": alg,
        "use": "sig",
    }


def jwks_document(jwks: list[dict[str, Any]]) -> dict[str, Any]:
    """The `/.well-known/jwks.json` body.

    Order matters operationally: a consumer that walks the list and takes the
    first usable key should meet the active one first. Backend looks keys up by
    `kid`, so this is a courtesy rather than a requirement — but it costs
    nothing and other clients are less careful.
    """
    return {"keys": jwks}
