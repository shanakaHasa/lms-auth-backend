"""Signing, behind a protocol that a remote key store can implement.

`LocalSigner` holds an RSA private key in the process. That is right for
development and wrong for production, where the key should live in Azure Key
Vault and never be exportable — so the boundary is drawn now, while it is free.

The protocol is deliberately **byte-level**: `sign(signing_input) -> bytes`. It
would be simpler to hand a private key to `jwt.encode` and be done, but a remote
key store cannot hand over a private key at all — it signs bytes you send it.
Designing to the weaker capability is what makes swapping in Key Vault a change
of one class rather than a rewrite of the token service.

JWS assembly therefore lives here, in `encode_jws`, above the signer rather than
inside it. It is about thirty lines and it is the price of that portability.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.crypto.jwks import b64u_encode, public_jwk

__all__ = [
    "LocalSigner",
    "Signer",
    "encode_jws",
    "generate_rsa_keypair",
]

# 2048 is the floor for RS256 in any serious guidance, and the ceiling for
# what is worth paying per signature at this scale. 4096 roughly quadruples
# signing cost for a margin nothing here needs.
RSA_KEY_SIZE = 2048


class Signer(Protocol):
    """What the token service needs. Nothing about *where* the key lives."""

    @property
    def kid(self) -> str: ...

    @property
    def alg(self) -> str: ...

    def sign(self, signing_input: bytes) -> bytes: ...

    def public_jwk(self) -> dict[str, Any]: ...


def generate_rsa_keypair(key_size: int = RSA_KEY_SIZE) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


class LocalSigner:
    """Signs in-process with an RSA private key.

    Used in development and in tests. Production uses the Key Vault
    implementation, which satisfies the same protocol — and the prod config
    guard refuses to boot with this one.
    """

    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self._private_key = private_key
        self._public_jwk = public_jwk(private_key.public_key())

    @property
    def kid(self) -> str:
        return str(self._public_jwk["kid"])

    @property
    def alg(self) -> str:
        return "RS256"

    def sign(self, signing_input: bytes) -> bytes:
        # PKCS#1 v1.5, which is what RS256 means. PSS would be stronger and
        # would be PS256 -- a different `alg` that backend's pinned
        # `algorithms=["RS256"]` would reject.
        return self._private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

    def public_jwk(self) -> dict[str, Any]:
        return dict(self._public_jwk)

    def private_pem(self) -> bytes:
        """Only for persistence, and only ever after wrapping.

        Named explicitly rather than exposing the key object, so every call site
        that could write key material to disk is greppable.
        """
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @classmethod
    def from_pem(cls, pem: bytes) -> LocalSigner:
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("not an RSA private key")
        return cls(key)


def encode_jws(claims: dict[str, Any], signer: Signer) -> str:
    """Assemble a signed compact JWS.

    Done by hand rather than through `jwt.encode` because the signer may be
    remote and hold no exportable key. The output is an ordinary JWT and is
    verified by PyJWT in the tests, which is what proves this is not a private
    dialect.

    `typ: "JWT"` and the `kid` are both in the header: the first so generic
    tooling knows what it is holding, the second so a consumer can pick the
    right key out of a JWKS that contains several during rotation.
    """
    header = {"alg": signer.alg, "typ": "JWT", "kid": signer.kid}

    # Separators matter: a space after the colon would still be valid JSON and
    # still verify, but it wastes bytes in something sent on every request.
    segments = [
        b64u_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode()),
        b64u_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()),
    ]
    signing_input = ".".join(segments).encode("ascii")
    segments.append(b64u_encode(signer.sign(signing_input)))
    return ".".join(segments)
