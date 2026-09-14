"""One module per table.

Importing this package imports every model, which is what populates
`Base.metadata` — Alembic autogenerate, the drift checker and the schema tests
all depend on that, so `import app.models` is enough and no caller needs to know
the individual module names.

Dependency rule: model modules import from `app.models.base` and never from each
other at runtime. Where a relationship needs a type annotation, the import goes
under `if TYPE_CHECKING` and the relationship is resolved by SQLAlchemy from the
class name. That keeps the files independent and free of import cycles.
"""

from app.models.auth_audit_event import AuthAuditEvent
from app.models.base import Base, TimestampMixin, uuid_pk
from app.models.oauth_client import OAuthClient
from app.models.oauth_client_secret import OAuthClientSecret
from app.models.refresh_token import RefreshToken
from app.models.revocation_event import RevocationEvent
from app.models.role import Role
from app.models.role_scope import RoleScope
from app.models.role_template import RoleTemplate
from app.models.scope import Scope
from app.models.signing_key import SigningKey
from app.models.tenant import Tenant
from app.models.throttle_bucket import ThrottleBucket
from app.models.user import User
from app.models.user_role import UserRole
from app.models.verification_token import VerificationToken

__all__ = [
    "AuthAuditEvent",
    "Base",
    "OAuthClient",
    "OAuthClientSecret",
    "RefreshToken",
    "RevocationEvent",
    "Role",
    "RoleScope",
    "RoleTemplate",
    "Scope",
    "SigningKey",
    "Tenant",
    "ThrottleBucket",
    "TimestampMixin",
    "User",
    "UserRole",
    "VerificationToken",
    "uuid_pk",
]
