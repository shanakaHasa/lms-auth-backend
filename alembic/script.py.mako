"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

Zero-downtime checklist. Migrations run against the PREVIOUS version of the
code, which is still serving traffic, so every migration must be safe for it.
Delete the lines that do not apply:

  [ ] Additive only (new nullable column / new table / new index)
  [ ] Index created CONCURRENTLY, in its own NON-transactional migration
  [ ] Backfill runs in batches, from a one-off task, not from here
  [ ] The currently deployed code still works against this schema (expand)
  [ ] Any drop or rename is deferred to a later release (contract)
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
${imports if imports else ""}

revision: str = ${repr(up_revision)}
down_revision: str | None = ${repr(down_revision)}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
