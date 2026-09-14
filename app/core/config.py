"""Configuration.

Every value comes from the environment (12-factor). The validators at the
bottom exist because the most dangerous failure mode for an identity provider
is booting successfully with development defaults, so misconfiguration is made
a startup crash rather than a silent security hole.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AppEnv = Literal["local", "dev", "prod"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # -- App ---------------------------------------------------------------
    app_env: AppEnv = "local"
    log_level: str = "INFO"
    api_port: int = 8001
    service_name: str = "auth-backend"

    # -- Database ----------------------------------------------------------
    # Deliberately a plain str rather than PostgresDsn: PostgresDsn happily
    # accepts "postgresql://", which then fails at connect time with an opaque
    # sync-driver error. The validator below checks the thing that actually
    # matters -- that the async driver is named.
    database_url: str = "postgresql+asyncpg://auth:auth@localhost:5432/authdb"
    # Integration tests point here. Kept separate so a mistyped env var cannot
    # make the suite truncate the development database.
    test_database_url: str | None = None
    db_pool_size: int = 10
    db_max_overflow: int = 5
    db_echo: bool = False
    # RDS is reachable over the internet, so "require" only encrypts --
    # "verify-full" is what authenticates the server against the RDS CA bundle.
    db_ssl_mode: Literal["disable", "require", "verify-full"] = "require"
    db_ca_bundle_path: str | None = None

    # -- Token issuance ----------------------------------------------------
    # Consumers verify `iss` by exact string match, so this must differ per
    # environment: a dev-issued token then cannot be accepted in prod.
    issuer: str = "http://localhost:8001"
    audience: str = "teachassist-api"
    access_token_ttl_seconds: int = 600
    refresh_idle_ttl_seconds: int = 43_200
    refresh_absolute_ttl_seconds: int = 604_800
    refresh_grace_seconds: int = 10
    clock_skew_leeway_seconds: int = 60

    # -- Signing -----------------------------------------------------------
    signer_backend: Literal["local", "kms"] = "local"
    kms_key_id: str | None = None
    jwks_cache_ttl_seconds: int = 300
    # A new key must be visible in JWKS this long before it may sign anything,
    # or consumers caching the old key set will reject tokens they cannot verify.
    key_min_publish_delay_seconds: int = 600

    # -- Passwords ---------------------------------------------------------
    argon2_time_cost: int = 3
    argon2_memory_cost_kib: int = 65_536
    argon2_parallelism: int = 1
    # 64 MiB per hash x unbounded concurrency will OOM the container.
    argon2_max_concurrency: int = 8
    password_min_length: int = 12
    password_max_bytes: int = 1024

    # -- Lockout and throttling -------------------------------------------
    lockout_threshold: int = 5
    lockout_max_minutes: int = 30
    ip_throttle_max_failures: int = 20
    ip_throttle_window_seconds: int = 900

    # -- Cookies -----------------------------------------------------------
    cookie_secure: bool = False
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    refresh_cookie_name: str = "__Host-ta_rt"
    csrf_cookie_name: str = "__Host-ta_csrf"

    # -- CORS --------------------------------------------------------------
    # Comma-separated. Exact origins only -- an over-broad origin regex is the
    # classic CORS bug, and `allow_credentials` forbids "*" anyway.
    cors_origins: str = "http://localhost:3000"

    # -- Local seeding -----------------------------------------------------
    dev_seed_password: str | None = None
    dev_seed_tenant_slug: str = "springfield-high"

    # ---------------------------------------------------------------------

    @field_validator("database_url", "test_database_url")
    @classmethod
    def _must_name_the_async_driver(cls, v: str | None) -> str | None:
        if v is not None and not v.startswith("postgresql+asyncpg://"):
            raise ValueError(
                "database URLs must use the postgresql+asyncpg:// driver; "
                f"got {v.split('://', 1)[0]}://"
            )
        return v

    @field_validator("issuer")
    @classmethod
    def _no_trailing_slash(cls, v: str) -> str:
        # `iss` is compared byte-for-byte, and the discovery document must
        # agree, so normalise once here rather than at every call site.
        return v.rstrip("/")

    @model_validator(mode="after")
    def _refuse_unsafe_production(self) -> Settings:
        if self.app_env != "prod":
            if self.signer_backend == "kms" and not self.kms_key_id:
                raise ValueError("SIGNER_BACKEND=kms requires KMS_KEY_ID")
            return self

        problems: list[str] = []
        if self.dev_seed_password:
            problems.append("DEV_SEED_PASSWORD must be unset")
        if not self.cookie_secure:
            problems.append("COOKIE_SECURE must be true")
        if not self.issuer.startswith("https://"):
            problems.append("ISSUER must be https")
        if "localhost" in self.issuer or "127.0.0.1" in self.issuer:
            problems.append("ISSUER must not point at localhost")
        if self.signer_backend != "kms":
            problems.append("SIGNER_BACKEND must be kms")
        if self.signer_backend == "kms" and not self.kms_key_id:
            problems.append("KMS_KEY_ID must be set")
        if self.cookie_samesite == "none" and not self.cookie_secure:
            problems.append("SAMESITE=none requires COOKIE_SECURE=true")

        if problems:
            raise ValueError("unsafe production configuration: " + "; ".join(problems))
        return self

    @property
    def is_local(self) -> bool:
        return self.app_env == "local"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/.well-known/jwks.json"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
