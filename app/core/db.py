"""Async SQLAlchemy engine and session factory.

`pool_pre_ping` matters on RDS: idle connections get reaped by the proxy, and a
stale one would otherwise surface as a 500 on the first request after a lull.
"""

from __future__ import annotations

import ssl
from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

# Explicit naming convention so Alembic autogenerate emits stable, diffable
# constraint names instead of whatever Postgres happened to pick. Without this,
# a constraint rename shows up as a spurious diff on someone else's machine.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def build_connect_args() -> dict[str, Any]:
    """TLS settings for asyncpg.

    asyncpg does not read `sslmode` out of the URL the way psycopg does, so it
    has to arrive through connect_args. The distinction matters here because the
    development database has a public endpoint:

      require      encrypts, but does not authenticate the server -- a
                   man-in-the-middle can still terminate the connection
      verify-full  checks the certificate chain against the RDS CA bundle and
                   the hostname. This is what you actually want over the
                   internet, and it needs the bundle on disk.
    """
    if settings.db_ssl_mode == "disable":
        return {}
    if settings.db_ssl_mode == "require":
        # asyncpg's own shorthand: encrypt, skip verification.
        return {"ssl": "require"}

    context = ssl.create_default_context(cafile=settings.db_ca_bundle_path)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return {"ssl": context}


engine = create_async_engine(
    settings.database_url,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_pre_ping=True,
    pool_recycle=1800,
    echo=settings.db_echo,
    connect_args=build_connect_args(),
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: commit on success, roll back on any exception."""
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
