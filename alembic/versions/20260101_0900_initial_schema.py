"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-01-01 09:00:00

The first migration, so everything is additive by definition. Later migrations
follow the expand/contract rules in the template header.

Seeds the scope catalogue and the role templates, because both are reference
data the application depends on existing: a tenant cannot be provisioned
without role templates, and a role cannot grant a scope that is not catalogued.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── tenants ─────────────────────────────────────────────────────────────
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column(
            "settings", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(r"slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'", name="slug_format"),
        sa.CheckConstraint("status IN ('active','suspended','deleted')", name="status_valid"),
        sa.PrimaryKeyConstraint("id", name="pk_tenants"),
        sa.UniqueConstraint("slug", name="uq_tenants_slug"),
    )

    # ── reference data ──────────────────────────────────────────────────────
    op.create_table(
        "role_templates",
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "default_scopes",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.PrimaryKeyConstraint("key", name="pk_role_templates"),
    )

    op.create_table(
        "scopes",
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("audience", sa.String(64), nullable=False),
        sa.Column("is_sensitive", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.PrimaryKeyConstraint("key", name="pk_scopes"),
    )

    # ── users ───────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("email_normalized", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("password_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="invited"),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('invited','active','disabled','deleted')", name="status_valid"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="fk_users_tenant_id_tenants", ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        # Not decoration: user_roles carries a composite FK into (id, tenant_id),
        # and Postgres requires a matching unique constraint to reference.
        sa.UniqueConstraint("id", "tenant_id", name="uq_users_id_tenant"),
    )
    # Unique per tenant, among live rows only -- so an address is reusable once
    # a user is deleted.
    op.create_index(
        "uq_users_tenant_email",
        "users",
        ["tenant_id", "email_normalized"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index("ix_users_tenant_status", "users", ["tenant_id", "status"])

    # ── roles and scopes ────────────────────────────────────────────────────
    op.create_table(
        "roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("template_key", sa.String(64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="fk_roles_tenant_id_tenants", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["template_key"],
            ["role_templates.key"],
            name="fk_roles_template_key_role_templates",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_roles"),
        sa.UniqueConstraint("tenant_id", "key", name="uq_roles_tenant_key"),
        sa.UniqueConstraint("id", "tenant_id", name="uq_roles_id_tenant"),
    )

    op.create_table(
        "role_scopes",
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scope_key", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(
            ["role_id"], ["roles.id"], name="fk_role_scopes_role_id_roles", ondelete="CASCADE"
        ),
        # RESTRICT: removing a catalogued scope while roles still grant it must
        # fail loudly, not quietly de-authorise people.
        sa.ForeignKeyConstraint(
            ["scope_key"],
            ["scopes.key"],
            name="fk_role_scopes_scope_key_scopes",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("role_id", "scope_key", name="pk_role_scopes"),
    )

    op.create_table(
        "user_roles",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("granted_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "granted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        # The pair of composite FKs below is what makes a cross-tenant role
        # grant a database error rather than a missing WHERE clause.
        sa.ForeignKeyConstraint(
            ["user_id", "tenant_id"],
            ["users.id", "users.tenant_id"],
            name="fk_user_roles_user_tenant",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id", "tenant_id"],
            ["roles.id", "roles.tenant_id"],
            name="fk_user_roles_role_tenant",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id", "role_id", name="pk_user_roles"),
    )
    op.create_index("ix_user_roles_role", "user_roles", ["role_id"])

    # ── sessions ────────────────────────────────────────────────────────────
    op.create_table(
        "refresh_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("family_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("parent_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("client_id", sa.String(64), nullable=True),
        sa.Column(
            "issued_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(32), nullable=True),
        sa.Column("ip_prefix", sa.String(64), nullable=True),
        sa.Column("ua_hash", sa.LargeBinary(), nullable=True),
        sa.CheckConstraint(
            "revoked_reason IS NULL OR revoked_reason IN "
            "('rotated','logout','reuse_detected','admin_revoked',"
            "'password_change','user_disabled')",
            name="revoked_reason_valid",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_refresh_tokens_user_id_users", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["parent_id"],
            ["refresh_tokens.id"],
            name="fk_refresh_tokens_parent_id_refresh_tokens",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_refresh_tokens"),
        sa.UniqueConstraint("token_hash", name="uq_refresh_tokens_token_hash"),
    )
    op.create_index("ix_refresh_tokens_user_active", "refresh_tokens", ["user_id", "revoked_at"])
    op.create_index("ix_refresh_tokens_family", "refresh_tokens", ["family_id"])
    op.create_index("ix_refresh_tokens_expires", "refresh_tokens", ["expires_at"])

    # ── machine-to-machine clients ──────────────────────────────────────────
    op.create_table(
        "oauth_clients",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "allowed_grant_types",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{client_credentials}'::text[]"),
        ),
        sa.Column(
            "allowed_scopes",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.Column(
            "allowed_audiences",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.Column("token_lifetime_seconds", sa.Integer(), nullable=False, server_default="600"),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_oauth_clients_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_oauth_clients"),
        sa.UniqueConstraint("client_id", name="uq_oauth_clients_client_id"),
    )

    op.create_table(
        "oauth_client_secrets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("secret_hash", sa.Text(), nullable=False),
        sa.Column("prefix", sa.String(16), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth_clients.id"],
            name="fk_oauth_client_secrets_client_id_oauth_clients",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_oauth_client_secrets"),
    )
    op.create_index("ix_oauth_client_secrets_client", "oauth_client_secrets", ["client_id"])

    # ── signing keys ────────────────────────────────────────────────────────
    op.create_table(
        "signing_keys",
        sa.Column("kid", sa.String(64), nullable=False),
        sa.Column("alg", sa.String(16), nullable=False, server_default="RS256"),
        sa.Column("public_jwk", postgresql.JSONB(), nullable=False),
        sa.Column("kms_key_id", sa.String(512), nullable=True),
        sa.Column("private_key_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retire_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending','active','retiring','revoked')", name="status_valid"
        ),
        sa.PrimaryKeyConstraint("kid", name="pk_signing_keys"),
    )
    # At most one active key, enforced by the database. A repeated or concurrent
    # rotation then fails as a constraint violation rather than leaving the
    # fleet disagreeing about which key is current.
    op.execute(
        "CREATE UNIQUE INDEX uq_signing_keys_one_active "
        "ON signing_keys ((status)) WHERE status = 'active'"
    )

    # ── revocation ──────────────────────────────────────────────────────────
    op.create_table(
        "revocation_events",
        sa.Column("seq", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("subject_type", sa.String(16), nullable=False),
        sa.Column("subject_id", sa.String(128), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("min_token_version", sa.Integer(), nullable=True),
        sa.Column("reason", sa.String(64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "subject_type IN ('user','tenant','session','jti','client')", name="subject_type_valid"
        ),
        sa.PrimaryKeyConstraint("seq", name="pk_revocation_events"),
    )
    op.create_index("ix_revocation_events_expires", "revocation_events", ["expires_at"])

    # ── one-time tokens ─────────────────────────────────────────────────────
    op.create_table(
        "verification_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_ip_prefix", sa.String(64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "purpose IN ('password_reset','email_verify','invite')", name="purpose_valid"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_verification_tokens_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_verification_tokens"),
        sa.UniqueConstraint("token_hash", name="uq_verification_tokens_token_hash"),
    )
    op.create_index(
        "ix_verification_tokens_user_purpose",
        "verification_tokens",
        ["user_id", "purpose", "consumed_at"],
    )

    # ── throttling ──────────────────────────────────────────────────────────
    op.create_table(
        "throttle_buckets",
        sa.Column("bucket_key", sa.String(128), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("bucket_key", "window_start", name="pk_throttle_buckets"),
    )
    op.create_index("ix_throttle_buckets_window", "throttle_buckets", ["window_start"])

    # ── audit ───────────────────────────────────────────────────────────────
    op.create_table(
        "auth_audit_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_type", sa.String(16), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=True),
        sa.Column("subject_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(64), nullable=True),
        sa.Column("client_id", sa.String(64), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("ip_prefix", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column(
            "event_metadata",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.CheckConstraint(
            "actor_type IN ('user','client','system','anonymous')", name="actor_type_valid"
        ),
        sa.CheckConstraint("outcome IN ('success','failure')", name="outcome_valid"),
        sa.PrimaryKeyConstraint("id", name="pk_auth_audit_events"),
    )
    op.create_index("ix_auth_audit_tenant_at", "auth_audit_events", ["tenant_id", "at"])
    op.create_index("ix_auth_audit_action_at", "auth_audit_events", ["action", "at"])

    _seed_reference_data()


# ── Seed data, hoisted to module level so it can be asserted ────────────────
#
# A migration must never import application code: a later refactor would then
# silently change what an old migration does to a database that already ran it.
# So these are duplicated from `app/core/scopes.py` on purpose, and
# `tests/unit/test_scopes.py` imports THIS MODULE by path and diffs the two.
# Change both; the suite tells you when you have not.

API_AUDIENCE = "teachassist-api"
AUTH_AUDIENCE = "teachassist-auth"

# key -> (description, audience, is_sensitive)
#
# Student records are personal information, so every scope that reaches them is
# flagged -- an access review can then answer "who can read student PII"
# without reading every role definition.
SCOPE_CATALOGUE: dict[str, tuple[str, str, bool]] = {
    "students:read": ("Read student records", API_AUDIENCE, True),
    "students:write": ("Create and update student records", API_AUDIENCE, True),
    "courses:read": ("Read courses", API_AUDIENCE, False),
    "courses:write": ("Create and update courses", API_AUDIENCE, False),
    "enrolments:write": ("Enrol and withdraw students", API_AUDIENCE, True),
    "materials:read": ("Read course materials and policies", API_AUDIENCE, False),
    "materials:write": ("Upload and delete course materials", API_AUDIENCE, False),
    "chat:use": ("Use the assistant", API_AUDIENCE, False),
    # Deliberately separate from students:write. A tutor may ask the assistant
    # to prepare a change; only a teacher may commit it.
    "proposals:approve": ("Approve a change the assistant proposed", API_AUDIENCE, True),
    "admin:users:read": ("List users in the institution", AUTH_AUDIENCE, False),
    "admin:users:write": ("Invite, disable and manage users", AUTH_AUDIENCE, False),
    "admin:roles": ("Manage roles and grants", AUTH_AUDIENCE, False),
    "admin:audit": ("Read the authentication audit log", AUTH_AUDIENCE, True),
    "admin:tenant": ("Manage institution settings", AUTH_AUDIENCE, False),
}

# `courses:write` lives here, not in ADMIN_EXTRA_SCOPES: a teacher sets up
# their own class. Listing it in both would put it in admin's default_scopes
# TWICE -- text[] has no uniqueness constraint, so the migration would succeed
# and provisioning would then violate pk_role_scopes (role_id, scope_key) at
# the first create-tenant, a long way from the cause.
TEACHER_SCOPES = (
    "students:read",
    "students:write",
    "courses:read",
    "courses:write",
    "enrolments:write",
    "materials:read",
    "materials:write",
    "chat:use",
    "proposals:approve",
)
TUTOR_SCOPES = ("students:read", "courses:read", "materials:read", "chat:use")
ADMIN_EXTRA_SCOPES = (
    "admin:users:read",
    "admin:users:write",
    "admin:roles",
    "admin:audit",
    "admin:tenant",
)
ROLE_TEMPLATE_SCOPES: dict[str, tuple[str, ...]] = {
    "admin": (*TEACHER_SCOPES, *ADMIN_EXTRA_SCOPES),
    "teacher": TEACHER_SCOPES,
    "tutor": TUTOR_SCOPES,
}
ROLE_TEMPLATE_META: dict[str, tuple[str, str]] = {
    "admin": ("Administrator", "Full access within the institution."),
    "teacher": (
        "Teacher",
        "Manages their own courses, students and materials, and approves "
        "changes the assistant proposes.",
    ),
    "tutor": (
        "Tutor",
        "Read-only. May ask the assistant to prepare a change, but cannot approve one.",
    ),
}


def _seed_reference_data() -> None:
    """Scopes and role templates.

    Reference data, not fixtures: a tenant cannot be provisioned without role
    templates, and `role_scopes` has a foreign key into `scopes`, so a role
    cannot grant a scope that was never catalogued.
    """
    scopes = sa.table(
        "scopes",
        sa.column("key", sa.String),
        sa.column("description", sa.Text),
        sa.column("audience", sa.String),
        sa.column("is_sensitive", sa.Boolean),
    )
    op.bulk_insert(
        scopes,
        [
            {
                "key": key,
                "description": description,
                "audience": audience,
                "is_sensitive": is_sensitive,
            }
            for key, (description, audience, is_sensitive) in SCOPE_CATALOGUE.items()
        ],
    )

    templates = sa.table(
        "role_templates",
        sa.column("key", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("default_scopes", postgresql.ARRAY(sa.Text)),
    )
    op.bulk_insert(
        templates,
        [
            {
                "key": key,
                "name": ROLE_TEMPLATE_META[key][0],
                "description": ROLE_TEMPLATE_META[key][1],
                "default_scopes": list(default_scopes),
            }
            for key, default_scopes in ROLE_TEMPLATE_SCOPES.items()
        ],
    )


def downgrade() -> None:
    # Reverse dependency order.
    op.drop_table("auth_audit_events")
    op.drop_table("throttle_buckets")
    op.drop_table("verification_tokens")
    op.drop_table("revocation_events")
    op.drop_table("signing_keys")
    op.drop_table("oauth_client_secrets")
    op.drop_table("oauth_clients")
    op.drop_table("refresh_tokens")
    op.drop_table("user_roles")
    op.drop_table("role_scopes")
    op.drop_table("roles")
    op.drop_table("users")
    op.drop_table("scopes")
    op.drop_table("role_templates")
    op.drop_table("tenants")
