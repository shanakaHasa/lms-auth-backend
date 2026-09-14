"""Test configuration.

Environment defaults are set BEFORE any app module is imported, because
`app.core.config.settings` is constructed at import time. Without this, a
developer's local `.env` leaks into the test run and CI behaves differently
from a laptop — which is the worst kind of flake to debug.
"""

from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("LOG_LEVEL", "WARNING")
os.environ.setdefault("ISSUER", "http://localhost:8001")
os.environ.setdefault("AUDIENCE", "teachassist-api")
os.environ.setdefault("SIGNER_BACKEND", "local")
# Secure is valid on http://localhost -- browsers treat it as a secure
# context -- and the refresh cookie uses the __Host- prefix, which browsers
# SILENTLY DISCARD without it. Setting false here would test a
# configuration that cannot work in a browser.
os.environ.setdefault("COOKIE_SECURE", "true")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://auth:auth@localhost:5432/authdb_test")
# CI runs Postgres as a service container on localhost, where TLS is neither
# available nor meaningful. Local runs against RDS override this to verify-full.
os.environ.setdefault("DB_SSL_MODE", "disable")
# Keep Argon2 cheap in unit tests. The real parameters are exercised in the
# integration suite; 64 MiB per hash here makes the suite crawl.
os.environ.setdefault("ARGON2_TIME_COST", "1")
os.environ.setdefault("ARGON2_MEMORY_COST_KIB", "8192")
