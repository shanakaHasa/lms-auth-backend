"""The access-token contract.

The most valuable test here does not check our own round trip. It copies the
consumer's expression **verbatim** from `backend/app/core/security.py:219` and
runs it over a token this service produced. Testing `decode_scope(encode_scope(x))`
would only prove this module agrees with itself, which is exactly the agreement
that cannot fail.

The failure being guarded against is silent. If `scope` ever became a JSON
array, `str(["a","b"])` is `"['a', 'b']"` and `.split()` gives
`["['a',", "'b']"]` — a non-empty frozenset of garbage. Every scope check then
fails with "missing required scope", which reads as a permissions bug. Nothing
raises. Nothing logs.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.crypto.jwks import b64u_encode
from app.crypto.signer import LocalSigner, encode_jws, generate_rsa_keypair
from app.schemas.token import decode_scope, encode_scope
from app.services.token_service import TokenService, build_access_claims

ISSUER = "http://localhost:8001"
AUDIENCE = "teachassist-api"
USER = uuid.UUID("11111111-1111-4111-8111-111111111111")
TENANT = uuid.UUID("22222222-2222-4222-8222-222222222222")
SCOPES = frozenset({"students:read", "students:write", "courses:read"})


def claims(**overrides: object):  # type: ignore[no-untyped-def]
    base = {
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "user_id": USER,
        "tenant_id": TENANT,
        "tenant_slug": "springfield-high",
        "email": "teacher@example.com",
        "scopes": SCOPES,
        "token_version": 0,
        "session_id": "sess-1",
        "ttl_seconds": 600,
    }
    base.update(overrides)
    return build_access_claims(**base)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def signer() -> LocalSigner:
    return LocalSigner(generate_rsa_keypair())


# ── The consumer's own expression ───────────────────────────────────────────


def test_the_consumers_scope_parsing_yields_exactly_our_scopes() -> None:
    """Copied verbatim from backend/app/core/security.py:219.

    If this ever fails, every gated endpoint in the LMS 403s and the symptom
    looks like a permissions problem rather than a format one.
    """
    parsed = frozenset(str(claims().get("scope", "")).split())
    assert parsed == SCOPES


def test_a_json_array_would_have_broken_the_consumer() -> None:
    """Demonstrates the failure this design avoids, so it stays understood.

    Not testing our code — testing that the alternative encoding really does
    fail silently, which is why the string form is not negotiable.
    """
    broken = frozenset(str(sorted(SCOPES)).split())
    assert broken != SCOPES
    assert broken, "and it is NON-empty, which is what makes it silent"
    assert "students:read" not in broken


def test_the_claim_is_a_string_and_the_plural_spellings_are_absent() -> None:
    # The realistic regression is someone ADDING `scopes` alongside, and a
    # consumer picking the wrong one.
    c = claims()
    assert isinstance(c["scope"], str)
    assert "scopes" not in c
    assert "scp" not in c


def test_the_scope_claim_is_sorted_and_deduplicated() -> None:
    # Deterministic output is what lets the contract fixtures be byte-stable.
    assert encode_scope(["b", "a", "b"]) == "a b"
    assert decode_scope("a b") == frozenset({"a", "b"})


def test_no_scopes_produces_an_empty_string_not_a_missing_claim() -> None:
    # backend does `.get("scope", "")`, so either works — but a present, empty
    # claim is unambiguous where an absent one invites a default.
    assert claims(scopes=frozenset())["scope"] == ""


# ── Claims the consumer requires ────────────────────────────────────────────


@pytest.mark.parametrize(
    "claim", ["iss", "aud", "sub", "tid", "scope", "token_use", "exp", "iat", "nbf"]
)
def test_every_claim_backend_reads_is_present(claim: str) -> None:
    assert claim in claims()


def test_the_tenant_claim_is_a_uuid_and_not_the_slug() -> None:
    """`tid` keys every row backend writes.

    The slug is renameable. If it ever appeared here, a rename would orphan an
    institution's entire dataset.
    """
    c = claims()
    uuid.UUID(c["tid"])  # raises if it is not one
    assert c["tid"] != c["tsl"]
    assert c["tsl"] == "springfield-high"


def test_token_use_marks_this_as_an_access_token() -> None:
    # backend rejects anything else, which is what stops a refresh or M2M token
    # reaching a user-facing endpoint.
    assert claims()["token_use"] == "access"


def test_the_issuer_carries_no_trailing_slash() -> None:
    # Compared byte-for-byte by the consumer.
    assert not claims()["iss"].endswith("/")


# ── Time ────────────────────────────────────────────────────────────────────


def test_the_lifetime_is_exactly_the_configured_ttl() -> None:
    c = claims(ttl_seconds=600)
    assert c["exp"] - c["iat"] == 600
    assert c["nbf"] == c["iat"]


def test_the_clock_is_injectable_so_expiry_is_testable_exactly() -> None:
    fixed = datetime(2026, 1, 1, tzinfo=UTC)
    c = claims(now=fixed, ttl_seconds=300)
    assert c["iat"] == int(fixed.timestamp())
    assert c["exp"] == int((fixed + timedelta(seconds=300)).timestamp())


def test_every_token_gets_a_unique_jti() -> None:
    # The handle a revocation feed needs to name one token.
    assert claims()["jti"] != claims()["jti"]


# ── End to end through a real signer ────────────────────────────────────────


def test_an_issued_token_verifies_the_way_backend_verifies_it(
    signer: LocalSigner,
) -> None:
    service = TokenService(signer, issuer=ISSUER, audience=AUDIENCE, ttl_seconds=600)
    token, issued = service.issue_access_token(
        user_id=USER,
        tenant_id=TENANT,
        tenant_slug="springfield-high",
        email="teacher@example.com",
        scopes=SCOPES,
        token_version=3,
        session_id="s1",
    )

    decoded = jwt.decode(
        token,
        jwt.PyJWK(signer.public_jwk()).key,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
    )
    assert decoded == dict(issued)
    assert frozenset(str(decoded["scope"]).split()) == SCOPES
    assert decoded["tv"] == 3


def test_a_token_signed_for_the_wrong_audience_is_rejected(signer: LocalSigner) -> None:
    """Why `aud` matters: auth's own admin API uses a different audience.

    Without this check a token minted for auth's admin surface would be
    replayable against the LMS.
    """
    token = encode_jws(dict(claims(audience="teachassist-auth")), signer)
    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(
            token,
            jwt.PyJWK(signer.public_jwk()).key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
        )


def test_an_expired_token_is_rejected(signer: LocalSigner) -> None:
    past = datetime.now(UTC) - timedelta(hours=2)
    token = encode_jws(dict(claims(now=past, ttl_seconds=600)), signer)
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(
            token,
            jwt.PyJWK(signer.public_jwk()).key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
        )


def test_a_token_from_a_different_issuer_is_rejected(signer: LocalSigner) -> None:
    token = encode_jws(dict(claims(issuer="https://evil.example.com")), signer)
    with pytest.raises(jwt.InvalidIssuerError):
        jwt.decode(
            token,
            jwt.PyJWK(signer.public_jwk()).key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
        )


def test_hs256_signed_with_the_rsa_public_key_is_rejected(signer: LocalSigner) -> None:
    """Algorithm confusion, the classic JWT attack — forged by hand.

    The attacker takes the public key, which is published in JWKS for anyone to
    fetch, and uses those bytes as an HMAC secret. A verifier that does not pin
    the algorithm reads `alg: HS256` from the attacker-controlled header and
    happily treats the same bytes as a symmetric key.

    Built with `hmac` rather than `jwt.encode`, because PyJWT refuses to create
    this token at all — it detects a PEM being used as an HMAC secret. That
    refusal is a good guard rail, and precisely why it cannot be used to
    construct the attack: a real attacker is not using PyJWT.
    """
    import hmac
    import json
    from hashlib import sha256

    from cryptography.hazmat.primitives import serialization

    public_pem = jwt.PyJWK(signer.public_jwk()).key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    header = b64u_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64u_encode(json.dumps(dict(claims())).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = b64u_encode(hmac.new(public_pem, signing_input, sha256).digest())
    forged = f"{header}.{payload}.{signature}"

    # Pinned algorithms is what makes this structurally impossible rather than
    # merely unlikely. Both services pin RS256.
    with pytest.raises(jwt.InvalidAlgorithmError):
        jwt.decode(
            forged,
            jwt.PyJWK(signer.public_jwk()).key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
        )

    # The forged token is well-formed and claims HS256 -- a real attempt,
    # not a malformed string that would fail for the wrong reason.
    assert jwt.get_unverified_header(forged)["alg"] == "HS256"

    # Worth recording what this test CANNOT show: that a non-pinning verifier
    # would accept it. PyJWT refuses to use a PEM as an HMAC secret in either
    # direction, so the vulnerable half is not demonstrable with this library.
    # That refusal is a second, independent layer -- the one tested here is
    # ours: algorithms=["RS256"].


def test_alg_none_is_rejected(signer: LocalSigner) -> None:
    """The other classic: strip the signature and claim none was needed."""
    import json

    header = b64u_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64u_encode(json.dumps(dict(claims())).encode())
    unsigned = f"{header}.{payload}."

    with pytest.raises(jwt.PyJWTError):
        jwt.decode(
            unsigned,
            jwt.PyJWK(signer.public_jwk()).key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
        )
