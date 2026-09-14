"""Log redaction.

This is the boundary where a credential would leak into CloudWatch. The tests
that matter are both directions: secrets must be removed, and ordinary
diagnostic content must survive — a scrubber that eats everything gets turned
off, which is worse than not having one.
"""

from __future__ import annotations

from app.core.redaction import REDACTED, is_sensitive_key, redact_processor, scrub


def test_password_field_is_removed() -> None:
    assert scrub({"password": "hunter2"})["password"] == REDACTED


def test_sensitive_key_matching_is_substring_and_case_insensitive() -> None:
    for key in (
        "Password",
        "new_password",
        "refresh_token",
        "X-CSRF-Token",
        "client_secret",
        "Authorization",
        "private_key",
    ):
        assert is_sensitive_key(key), key


def test_ordinary_keys_are_not_sensitive() -> None:
    for key in ("email", "tenant_id", "user_id", "status", "duration_ms"):
        assert not is_sensitive_key(key), key


def test_bearer_token_inside_free_text_is_scrubbed() -> None:
    out = scrub("upstream said: Authorization: Bearer abcdef123456ghijkl")
    assert "abcdef123456ghijkl" not in out


def test_basic_auth_inside_free_text_is_scrubbed() -> None:
    out = scrub("Basic dXNlcjpwYXNzd29yZA==")
    assert "dXNlcjpwYXNzd29yZA==" not in out


def test_a_jwt_in_free_text_is_scrubbed() -> None:
    jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlX2hlcmU"
    assert jwt not in scrub(f"token was {jwt} and it failed")


def test_a_refresh_token_in_free_text_is_scrubbed() -> None:
    assert "rt1_abc123def456" not in scrub("presented rt1_abc123def456ghi")


def test_diagnostic_content_survives() -> None:
    # If this fails, the scrubber is too aggressive and someone will disable it.
    text = "login failed for tenant springfield-high after 3 attempts in 42ms"
    assert scrub(text) == text


def test_nested_structures_are_scrubbed() -> None:
    payload = {"user": {"email": "a@b.test", "password": "hunter2"}, "n": 3}
    out = scrub(payload)
    assert out["user"]["password"] == REDACTED
    assert out["user"]["email"] == "a@b.test"
    assert out["n"] == 3


def test_lists_are_scrubbed() -> None:
    out = scrub([{"token": "abc"}, {"email": "a@b.test"}])
    assert out[0]["token"] == REDACTED
    assert out[1]["email"] == "a@b.test"


def test_recursion_is_depth_capped() -> None:
    # A deeply nested payload must not turn a log call into a hang.
    deep: dict = {}
    node = deep
    for _ in range(50):
        node["next"] = {}
        node = node["next"]
    assert scrub(deep) is not None


def test_long_values_are_truncated() -> None:
    assert len(scrub("x" * 10_000)) <= 2000


def test_the_processor_redacts_the_whole_event() -> None:
    event = {"event": "login", "password": "hunter2", "email": "a@b.test"}
    out = redact_processor(None, "info", event)
    assert out["password"] == REDACTED
    assert out["email"] == "a@b.test"
    assert out["event"] == "login"
