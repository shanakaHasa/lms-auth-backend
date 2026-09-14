"""Health endpoints and the security headers every response must carry."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app

client = TestClient(create_app())


def test_healthz_is_ok_without_any_dependency() -> None:
    # No database is running in the unit suite. That is the point: /healthz must
    # not touch one, or a DB blip makes the load balancer kill healthy tasks.
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "auth-backend"


def test_every_response_carries_a_request_id() -> None:
    assert client.get("/healthz").headers["x-request-id"]


def test_an_upstream_request_id_is_honoured() -> None:
    # The ALB and the other services propagate this; traces must join up.
    response = client.get("/healthz", headers={"x-request-id": "abc-123"})
    assert response.headers["x-request-id"] == "abc-123"


def test_responses_are_never_cacheable() -> None:
    # Tokens must not sit in a proxy or the back-forward cache.
    assert client.get("/healthz").headers["cache-control"] == "no-store"


def test_security_headers_are_present() -> None:
    headers = client.get("/healthz").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]


def test_hsts_is_absent_on_plain_http_local() -> None:
    # Sending HSTS from a local http listener would pin the developer's browser
    # to https for localhost and break the next project that uses port 8001.
    assert "strict-transport-security" not in client.get("/healthz").headers
