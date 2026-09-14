"""Storage adapters, one module per aggregate.

Services depend on the `*Repository` protocols here, never on `AsyncSession`.
That buys two things worth the extra layer: the service logic is testable with
no database, which matters because this whole phase is built before a migration
is ever applied; and tenant scoping becomes structural rather than something
review has to keep catching.

See `base.py` for why there are **two** repository bases rather than one.
"""

from app.repositories.base import (
    GlobalRepository,
    TenantScopedRepository,
    translate_integrity_error,
)
from app.repositories.role import RoleRepository, SqlRoleRepository
from app.repositories.tenant import SqlTenantRepository, TenantRepository
from app.repositories.user import SqlUserRepository, UserRepository

__all__ = [
    "GlobalRepository",
    "RoleRepository",
    "SqlRoleRepository",
    "SqlTenantRepository",
    "SqlUserRepository",
    "TenantRepository",
    "TenantScopedRepository",
    "UserRepository",
    "translate_integrity_error",
]
