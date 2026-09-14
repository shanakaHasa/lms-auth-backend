"""Compare the migration chain against the models, without a database.

`alembic check` does this properly, but it needs a live connection. This is the
offline approximation: render the DDL the models imply, render the DDL the
migrations emit, and diff the set of object names.

It catches the specific class of bug that hand-written migrations produce --
a constraint or index that exists in one and not the other, or is named
differently in each. It does NOT catch column type or default mismatches; only
`alembic check` against a real database does that, so this is a fast pre-filter,
not a replacement.

    python scripts/check_migration_drift.py
"""

from __future__ import annotations

import re
import subprocess
import sys

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable

import app.models  # noqa: F401  -- importing registers every table
from app.core.db import Base

DIALECT = postgresql.dialect()

TABLE_RE = re.compile(r"CREATE TABLE (\w+)", re.IGNORECASE)
CONSTRAINT_RE = re.compile(r"CONSTRAINT (\w+)", re.IGNORECASE)
INDEX_RE = re.compile(r"CREATE (?:UNIQUE )?INDEX (\w+)", re.IGNORECASE)

# Alembic's own bookkeeping table is not in our metadata, by design.
IGNORED_TABLES = {"alembic_version"}
IGNORED_CONSTRAINTS = {"alembic_version_pkc"}


def names_from(sql: str) -> dict[str, set[str]]:
    return {
        "tables": set(TABLE_RE.findall(sql)) - IGNORED_TABLES,
        "constraints": set(CONSTRAINT_RE.findall(sql)) - IGNORED_CONSTRAINTS,
        "indexes": set(INDEX_RE.findall(sql)),
    }


def model_sql() -> str:
    parts: list[str] = []
    for table in Base.metadata.sorted_tables:
        parts.append(str(CreateTable(table).compile(dialect=DIALECT)))
        for index in table.indexes:
            parts.append(str(CreateIndex(index).compile(dialect=DIALECT)))
    return "\n".join(parts)


def migration_sql() -> str:
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head", "--sql"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print("alembic offline render failed:\n" + result.stderr)
        sys.exit(2)
    return result.stdout


def main() -> int:
    models = names_from(model_sql())
    migrations = names_from(migration_sql())

    ok = True
    for kind in ("tables", "constraints", "indexes"):
        only_models = models[kind] - migrations[kind]
        only_migrations = migrations[kind] - models[kind]
        if not only_models and not only_migrations:
            print(f"  {kind:<12} {len(models[kind]):>3} matched")
            continue
        ok = False
        print(f"  {kind:<12} MISMATCH")
        for name in sorted(only_models):
            print(f"      in models, missing from migrations : {name}")
        for name in sorted(only_migrations):
            print(f"      in migrations, missing from models : {name}")

    if ok:
        print("\nNo drift between the models and the migration chain.")
        return 0
    print("\nDrift found. Either the migration is wrong, or a model changed")
    print("without one. Fix before this reaches a database.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
