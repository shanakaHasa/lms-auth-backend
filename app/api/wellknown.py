"""The discovery endpoints, mounted at the root rather than under /api/v1.

Their paths are fixed by RFC 8414 and by what every JOSE client looks for, so
they cannot carry a version prefix.

`GET /.well-known/jwks.json` is **the single endpoint `backend` depends on**.
Everything else in this service can be down and the LMS keeps verifying tokens
from its cache; if this is wrong, nothing verifies.

Two response details matter more than they look:

* **`Cache-Control: public, max-age`.** The rest of this service sends
  `no-store`, correctly — it returns tokens. JWKS is the exception: it is public
  key material, and a consumer that cannot cache it refetches on every unknown
  `kid`. The middleware is exempted for this path; without that exemption the
  key-rotation rule ("publish for twice the cache TTL before signing") would be
  resting on a header that never reached anyone.
* **`ETag`.** Lets a consumer revalidate for free. The key set changes rarely
  and is fetched often, which is exactly when a conditional request pays.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import APIRouter, Request, Response

from app.core.config import settings
from app.core.deps import KeyServiceDep
from app.core.scopes import SCOPE_KEYS

router = APIRouter(tags=["discovery"])


@router.get("/.well-known/jwks.json", summary="Public keys for verifying tokens")
async def jwks(request: Request, response: Response, keys: KeyServiceDep) -> Any:
    document = await keys.jwks()
    body = json.dumps(document, sort_keys=True, separators=(",", ":"))
    etag = '"' + hashlib.sha256(body.encode()).hexdigest()[:32] + '"'

    # Half the JWKS cache TTL, so a consumer refreshes twice per window. That is
    # what makes "published for 2x the TTL" a real guarantee rather than a
    # best case.
    response.headers["Cache-Control"] = f"public, max-age={settings.jwks_cache_ttl_seconds // 2}"
    response.headers["ETag"] = etag

    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=dict(response.headers))
    return document


@router.get(
    "/.well-known/openid-configuration",
    summary="Discovery document",
)
async def openid_configuration(response: Response) -> dict[str, Any]:
    """Advertises only what this service actually implements.

    No `authorization_endpoint`, because there is no authorization-code flow —
    listing one would make a client attempt a redirect that goes nowhere.
    """
    response.headers["Cache-Control"] = f"public, max-age={settings.jwks_cache_ttl_seconds}"
    issuer = settings.issuer
    return {
        "issuer": issuer,
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "token_endpoint": f"{issuer}/api/v1/oauth/token",
        "id_token_signing_alg_values_supported": ["RS256"],
        "grant_types_supported": ["client_credentials"],
        "scopes_supported": sorted(SCOPE_KEYS),
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "claims_supported": [
            "iss",
            "aud",
            "sub",
            "tid",
            "tsl",
            "scope",
            "token_use",
            "sid",
            "tv",
            "jti",
            "iat",
            "nbf",
            "exp",
            "email",
        ],
    }
