"""Fixtures for the tests that need a real Postgres.

Skipped by default (`-m 'not integration'` in `pyproject.toml`) and run in CI,
and in Phase 2, once `alembic upgrade head` has been applied.

**Each test runs inside a transaction that is rolled back**, so tests share one
database without sharing state and leave nothing behind.
`join_transaction_mode="create_savepoint"` is what lets the code under test call
`session.commit()` normally — the commit releases a savepoint rather than
committing the outer transaction, so production code needs no test-only branch.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.core.config import settings


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(settings.database_url)
    try:
        connection = await engine.connect()
    except Exception as exc:  # pragma: no cover - only when no database is up
        await engine.dispose()
        pytest.skip(f"no database available: {exc}")

    transaction = await connection.begin()
    db = AsyncSession(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )
    try:
        yield db
    finally:
        await db.close()
        await transaction.rollback()
        await connection.close()
        await engine.dispose()
