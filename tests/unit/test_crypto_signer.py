"""Signing, and the proof that what we emit is an ordinary JWT.

`encode_jws` assembles the compact form by hand rather than calling
`jwt.encode`, because a remote key store holds no exportable key and can only
sign bytes. The risk that introduces is obvious: a hand-rolled encoder can
produce something that only we can read.

So the load-bearing test here verifies our output with **PyJWT** — the same
library `backend` uses, through the same public JWK a consumer would fetch from
JWKS. If that passes, the encoder is not a private dialect.
"""

from __future__ import annotations

import json

import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.crypto.jwks import b64u_decode
from app.crypto.signer import (
    LocalSigner,
    encode_jws,
    generate_rsa_keypair,
)

CLAIMS = {
    "iss": "http://localhost:8001",
    "aud": "teachassist-api",
    "sub": "11111111-1111-4111-8111-111111111111",
    "tid": "22222222-2222-4222-8222-222222222222",
    "scope": "students:read students:write",
    "token_use": "access",
    "exp": 9_999_999_999,
    "iat": 1_700_000_000,
}


@pytest.fixture(scope="module")
def signer() -> LocalSigner:
    return LocalSigner(generate_rsa_keypair())


# ── The cross-library check ─────────────────────────────────────────────────


def test_pyjwt_verifies_what_we_emit(signer: LocalSigner) -> None:
    """The test this whole module exists for.

    Verified through `jwt.PyJWK` built from the published JWKS entry — exactly
    the path `backend` takes — rather than through the private key object we
    happen to hold.
    """
    token = encode_jws(CLAIMS, signer)
    key = jwt.PyJWK(signer.public_jwk()).key

    decoded = jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        issuer="http://localhost:8001",
        audience="teachassist-api",
    )
    assert decoded == CLAIMS


def test_the_header_carries_the_kid_a_consumer_looks_up(signer: LocalSigner) -> None:
    # Without it, backend raises "token has no key id" before it ever tries a
    # signature.
    header = jwt.get_unverified_header(encode_jws(CLAIMS, signer))
    assert header["kid"] == signer.kid
    assert header["alg"] == "RS256"
    assert header["typ"] == "JWT"


def test_a_tampered_payload_fails_verification(signer: LocalSigner) -> None:
    header, payload, signature = encode_jws(CLAIMS, signer).split(".")
    forged = json.loads(b64u_decode(payload))
    forged["scope"] = "students:read students:write proposals:approve"

    from app.crypto.jwks import b64u_encode

    tampered = ".".join(
        [header, b64u_encode(json.dumps(forged, separators=(",", ":")).encode()), signature]
    )
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(
            tampered,
            jwt.PyJWK(signer.public_jwk()).key,
            algorithms=["RS256"],
            issuer="http://localhost:8001",
            audience="teachassist-api",
        )


def test_another_keys_public_half_does_not_verify(signer: LocalSigner) -> None:
    other = LocalSigner(generate_rsa_keypair())
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(
            encode_jws(CLAIMS, signer),
            jwt.PyJWK(other.public_jwk()).key,
            algorithms=["RS256"],
            issuer="http://localhost:8001",
            audience="teachassist-api",
        )


# ── Shape of the compact form ───────────────────────────────────────────────


def test_the_token_has_three_segments(signer: LocalSigner) -> None:
    assert len(encode_jws(CLAIMS, signer).split(".")) == 3


def test_no_segment_carries_base64_padding(signer: LocalSigner) -> None:
    # `=` in a JWT segment is malformed and some parsers reject it outright.
    assert "=" not in encode_jws(CLAIMS, signer)


def test_the_claims_round_trip_unchanged(signer: LocalSigner) -> None:
    _, payload, _ = encode_jws(CLAIMS, signer).split(".")
    assert json.loads(b64u_decode(payload)) == CLAIMS


def test_encoding_is_deterministic_for_identical_claims(signer: LocalSigner) -> None:
    """Sorted keys and no whitespace.

    Not required for correctness, but it is what makes the contract fixtures
    byte-stable — and a fixture pack that produced a spurious diff on every
    regeneration would simply stop being regenerated.
    """
    assert encode_jws(CLAIMS, signer) == encode_jws(dict(reversed(list(CLAIMS.items()))), signer)


# ── The signature itself ────────────────────────────────────────────────────


def test_the_signature_is_pkcs1_v15_over_sha256(signer: LocalSigner) -> None:
    """RS256 means PKCS#1 v1.5. PSS would be PS256.

    Verified against `cryptography` directly rather than through PyJWT, so the
    padding scheme is pinned rather than merely "whatever both libraries agree
    on today".
    """
    token = encode_jws(CLAIMS, signer)
    header, payload, signature = token.split(".")
    public = jwt.PyJWK(signer.public_jwk()).key

    # Raises on mismatch.
    public.verify(
        b64u_decode(signature),
        f"{header}.{payload}".encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_the_kid_is_derived_from_the_key_not_assigned(signer: LocalSigner) -> None:
    from app.crypto.jwks import rfc7638_thumbprint

    assert signer.kid == rfc7638_thumbprint(signer.public_jwk())


# ── Key material handling ───────────────────────────────────────────────────


def test_a_key_survives_a_pem_round_trip(signer: LocalSigner) -> None:
    # Persistence has to preserve the `kid`, or a restart mints tokens no
    # consumer can match to a published key.
    restored = LocalSigner.from_pem(signer.private_pem())
    assert restored.kid == signer.kid


def test_a_restored_key_produces_an_identical_signature(signer: LocalSigner) -> None:
    restored = LocalSigner.from_pem(signer.private_pem())
    assert encode_jws(CLAIMS, restored) == encode_jws(CLAIMS, signer)


def test_loading_something_that_is_not_an_rsa_key_is_refused() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="not an RSA private key"):
        LocalSigner.from_pem(pem)


def test_the_generated_key_is_large_enough() -> None:
    # 1024 is broken and 2048 is the floor for RS256 in any current guidance.
    assert generate_rsa_keypair().key_size >= 2048


def test_the_public_jwk_is_a_copy_not_the_internal_dict(signer: LocalSigner) -> None:
    # A caller mutating what it got back must not be able to change the kid
    # this signer stamps into every header.
    jwk = signer.public_jwk()
    jwk["kid"] = "tampered"
    assert signer.kid != "tampered"


def test_the_signer_never_exposes_the_private_key_object(signer: LocalSigner) -> None:
    """`private_pem()` is the only way out, and it is named to be greppable.

    The protocol a remote key store implements has no such method at all, which
    is the point: code written against `Signer` cannot reach key material.
    """
    from app.crypto.signer import Signer

    assert not hasattr(Signer, "private_pem")
    assert isinstance(signer._private_key, rsa.RSAPrivateKey)
