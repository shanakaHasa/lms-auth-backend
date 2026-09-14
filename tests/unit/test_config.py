"""Configuration guards.

The point of these tests is that a misconfigured production deploy must fail at
startup rather than serve traffic with development defaults. Each assertion
below corresponds to a real way an identity provider gets deployed insecurely.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings

PROD_SAFE = {
    "app_env": "prod",
    "issuer": "https://auth.example.com",
    "cookie_secure": True,
    "signer_backend": "kms",
    "kms_key_id": "arn:aws:kms:ap-southeast-2:111122223333:key/abc",
    "dev_seed_password": None,
    "_env_file": None,
}


def _prod(**overrides: object) -> Settings:
    return Settings(**{**PROD_SAFE, **overrides})  # type: ignore[arg-type]


def test_a_correctly_configured_prod_boots() -> None:
    settings = _prod()
    assert settings.app_env == "prod"
    assert not settings.is_local


def test_prod_refuses_the_dev_seed_password() -> None:
    # The well-known local password is committed in .env.example, so this guard
    # is what stops it reaching a real environment.
    with pytest.raises(ValidationError, match="DEV_SEED_PASSWORD"):
        _prod(dev_seed_password="devpassword123")


def test_prod_refuses_insecure_cookies() -> None:
    with pytest.raises(ValidationError, match="COOKIE_SECURE"):
        _prod(cookie_secure=False)


def test_prod_refuses_a_plaintext_issuer() -> None:
    with pytest.raises(ValidationError, match="ISSUER must be https"):
        _prod(issuer="http://auth.example.com")


def test_prod_refuses_a_localhost_issuer() -> None:
    with pytest.raises(ValidationError, match="localhost"):
        _prod(issuer="https://localhost:8001")


def test_prod_refuses_the_local_signer() -> None:
    # A local signer in prod means the private key lives in the container.
    with pytest.raises(ValidationError, match="SIGNER_BACKEND"):
        _prod(signer_backend="local")


def test_kms_signer_requires_a_key_id_everywhere() -> None:
    with pytest.raises(ValidationError, match="KMS_KEY_ID"):
        Settings(app_env="local", signer_backend="kms", kms_key_id=None, _env_file=None)  # type: ignore[arg-type]


def test_samesite_none_requires_secure() -> None:
    with pytest.raises(ValidationError, match="SAMESITE"):
        _prod(cookie_samesite="none", cookie_secure=False)


def test_all_problems_are_reported_together() -> None:
    # One boot, one error message listing everything wrong -- rather than
    # fixing them one deploy at a time.
    with pytest.raises(ValidationError) as exc:
        _prod(cookie_secure=False, signer_backend="local", issuer="http://localhost")
    message = str(exc.value)
    assert "COOKIE_SECURE" in message
    assert "SIGNER_BACKEND" in message
    assert "ISSUER" in message


def test_issuer_trailing_slash_is_normalised() -> None:
    # `iss` is compared byte-for-byte by consumers, so a stray slash would
    # silently break every token.
    assert Settings(issuer="http://localhost:8001/", _env_file=None).issuer == (
        "http://localhost:8001"
    )


def test_jwks_uri_is_derived_from_the_issuer() -> None:
    settings = Settings(issuer="https://auth.example.com", _env_file=None)
    assert settings.jwks_uri == "https://auth.example.com/.well-known/jwks.json"


def test_cors_origins_parse_from_a_comma_separated_string() -> None:
    settings = Settings(cors_origins="http://a.test, http://b.test ,", _env_file=None)
    assert settings.cors_origin_list == ["http://a.test", "http://b.test"]
