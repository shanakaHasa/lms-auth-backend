"""JWK construction and the `kid` derivation.

The first test is the most valuable one in this file: it pins the thumbprint
against the worked example published in **RFC 7638 §3.1**, not against our own
output. A test that compares our implementation to itself would pass just as
happily if the canonicalisation were wrong in a way both sides shared — and a
wrong `kid` is not a visible failure, it is every token being rejected with
"unknown signing key".
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.crypto.jwks import (
    b64u_decode,
    b64u_encode,
    jwks_document,
    public_jwk,
    rfc7638_thumbprint,
)

# RFC 7638 §3.1, verbatim. https://www.rfc-editor.org/rfc/rfc7638#section-3.1
RFC_EXAMPLE_JWK = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"
        "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiF"
        "V4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6C"
        "f0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9"
        "c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTW"
        "hAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1"
        "jF44-csFCur-kEgU8awapJzKnqDKgw"
    ),
    "e": "AQAB",
    "alg": "RS256",
    "kid": "2011-04-29",
}
RFC_EXPECTED_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


# ── The thumbprint, against a third-party vector ────────────────────────────


def test_the_thumbprint_matches_the_rfc_worked_example() -> None:
    """The strongest check available: someone else's answer.

    If this passes, the canonicalisation — key subset, lexicographic order, no
    whitespace, UTF-8, SHA-256, unpadded base64url — is right in every detail.
    """
    assert rfc7638_thumbprint(RFC_EXAMPLE_JWK) == RFC_EXPECTED_THUMBPRINT


def test_the_thumbprint_ignores_alg_use_and_the_supplied_kid() -> None:
    """Only the required members participate.

    The RFC example carries `alg` and its own `kid`; the thumbprint must be
    identical without them. Including metadata would mean the same key,
    described two ways, got two different ids.
    """
    bare = {k: RFC_EXAMPLE_JWK[k] for k in ("kty", "n", "e")}
    assert rfc7638_thumbprint(bare) == RFC_EXPECTED_THUMBPRINT


def test_the_thumbprint_is_stable_across_key_ordering() -> None:
    # Input dict order must not matter; the canonical form is sorted.
    reordered = {"e": RFC_EXAMPLE_JWK["e"], "n": RFC_EXAMPLE_JWK["n"], "kty": "RSA"}
    assert rfc7638_thumbprint(reordered) == RFC_EXPECTED_THUMBPRINT


def test_a_different_key_gets_a_different_thumbprint() -> None:
    other = {**RFC_EXAMPLE_JWK, "n": RFC_EXAMPLE_JWK["n"].replace("0vx7", "1vx7")}
    assert rfc7638_thumbprint(other) != RFC_EXPECTED_THUMBPRINT


def test_a_non_rsa_key_is_refused_rather_than_silently_wrong() -> None:
    # EC keys canonicalise over crv/kty/x/y. Producing an RSA-shaped thumbprint
    # for one would yield a plausible-looking id that no consumer could match.
    with pytest.raises(ValueError, match="unsupported key type"):
        rfc7638_thumbprint({"kty": "EC", "crv": "P-256", "x": "a", "y": "b"})


# ── base64url ───────────────────────────────────────────────────────────────


def test_base64url_is_unpadded_and_url_safe() -> None:
    # JOSE values are unpadded, and `+` / `/` would break them in a URL or a
    # JWT segment.
    encoded = b64u_encode(b"\xff\xff\xfe")
    assert "=" not in encoded
    assert "+" not in encoded and "/" not in encoded


@pytest.mark.parametrize("size", [1, 2, 3, 4, 31, 32, 33, 256])
def test_base64url_round_trips_at_every_padding_boundary(size: int) -> None:
    payload = bytes(range(256))[:size] * (1 + size // 256)
    assert b64u_decode(b64u_encode(payload)) == payload


def test_the_rfc_exponent_encodes_as_expected() -> None:
    # 65537 big-endian minimal octets is 0x010001 -> "AQAB". Getting the minimal
    # -octet rule wrong produces "AAEAAQ", which is a valid encoding of the same
    # number and a *different* thumbprint.
    assert b64u_decode("AQAB") == b"\x01\x00\x01"


# ── Building a JWK from a real key ──────────────────────────────────────────


@pytest.fixture(scope="module")
def key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_a_public_jwk_has_the_members_a_consumer_needs(key: rsa.RSAPrivateKey) -> None:
    jwk = public_jwk(key.public_key())
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert jwk["kid"]


def test_the_kid_is_the_thumbprint_of_the_key_itself(key: rsa.RSAPrivateKey) -> None:
    jwk = public_jwk(key.public_key())
    assert jwk["kid"] == rfc7638_thumbprint(jwk)


def test_the_same_key_always_yields_the_same_kid(key: rsa.RSAPrivateKey) -> None:
    # Deterministic: re-importing a key or restoring a backup must not mint a
    # second identifier for one key.
    assert public_jwk(key.public_key())["kid"] == public_jwk(key.public_key())["kid"]


def test_two_keys_get_different_kids() -> None:
    first = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    second = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert public_jwk(first.public_key())["kid"] != public_jwk(second.public_key())["kid"]


# ── The private half must be unreachable ────────────────────────────────────


PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth")


def test_no_private_component_appears_in_a_jwk(key: rsa.RSAPrivateKey) -> None:
    jwk = public_jwk(key.public_key())
    assert not set(jwk) & set(PRIVATE_MEMBERS)


def test_no_private_component_survives_serialisation(key: rsa.RSAPrivateKey) -> None:
    """Asserted on the serialised bytes, not on the dict.

    The dict check above would pass if a private value were nested inside some
    other member. This checks what actually goes over the wire.
    """
    document = json.dumps(jwks_document([public_jwk(key.public_key())]))
    for member in PRIVATE_MEMBERS:
        assert f'"{member}"' not in document, member


def test_the_private_numbers_are_not_derivable_from_the_document(
    key: rsa.RSAPrivateKey,
) -> None:
    # A belt-and-braces check that the modulus is published and the private
    # exponent is not, by value rather than by key name.
    document = json.dumps(jwks_document([public_jwk(key.public_key())]))
    numbers = key.private_numbers()
    assert b64u_encode(numbers.public_numbers.n.to_bytes(256, "big").lstrip(b"\x00")) in document
    assert b64u_encode(numbers.d.to_bytes(256, "big").lstrip(b"\x00")) not in document


# ── The document ────────────────────────────────────────────────────────────


def test_the_document_is_shaped_as_consumers_expect(key: rsa.RSAPrivateKey) -> None:
    # backend does `document["keys"]` and filters on `kty`/`alg`.
    document = jwks_document([public_jwk(key.public_key())])
    assert set(document) == {"keys"}
    assert isinstance(document["keys"], list)


def test_a_document_can_carry_more_than_one_key() -> None:
    """Rotation depends on this.

    A new key is published as `pending` and must appear in JWKS *before* it
    signs anything, so a consumer that cached the old document has time to
    refresh. A single-key document would make rotation a hard cutover.
    """
    keys = [
        public_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key())
        for _ in range(2)
    ]
    document = jwks_document(keys)
    assert len({k["kid"] for k in document["keys"]}) == 2
