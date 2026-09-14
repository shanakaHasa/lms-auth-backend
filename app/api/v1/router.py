"""Aggregates every /api/v1 router.

Routers are added here as each step lands:
  Step 4  wellknown   (jwks.json, openid-configuration -- mounted at the root,
                       not under /api/v1, because the spec requires it)
  Step 5  auth        (login)  <- done
  Step 6  auth        (refresh, logout)
  Step 7  oauth       (client_credentials)
  Step 8  me, admin_users, admin_roles, admin_tenant
  Step 10 internal    (revocations feed, key rotation)
"""

from fastapi import APIRouter

from app.api.v1 import auth

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
