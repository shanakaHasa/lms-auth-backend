"""The refresh cookie.

`httpOnly`, so script cannot read it. That is the entire reason the refresh
token lives in a cookie while the access token lives in memory: the long-lived
credential is the one that must survive a reload, and the only storage a page
cannot exfiltrate is storage the page cannot see.

The `__Host-` prefix is not decoration. A browser only accepts a cookie with
that name if it is `Secure`, has `Path=/`, and carries **no `Domain`
attribute** — which means a sibling subdomain cannot set it. That matters here
because institutions are expected to get subdomains; without the prefix,
anything running on one tenant's subdomain could write a cookie that the
browser would then send to the shared parent.

The trap, and the reason `config.py` now refuses the combination outright: a
`__Host-` cookie without `Secure` is **silently discarded**. No error, no
warning. Login appears to work, refresh simply never does, and there is nothing
in any log to explain it. `Secure` is safe on `http://localhost` because
browsers treat localhost as a secure context.
"""

from __future__ import annotations

from fastapi import Response

from app.core.config import settings

__all__ = ["clear_refresh_cookie", "set_refresh_cookie"]


def set_refresh_cookie(response: Response, token: str, max_age_seconds: int) -> None:
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=token,
        max_age=max_age_seconds,
        # Unreadable by script. The whole point.
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        # `__Host-` requires exactly this, and no domain.
        path="/",
    )


def clear_refresh_cookie(response: Response) -> None:
    # Same attributes as when it was set: a browser matches on name, path and
    # domain, so clearing with different attributes leaves the cookie in place.
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
