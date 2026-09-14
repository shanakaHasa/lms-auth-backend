"""Operator CLI.

Commands land as the steps do:
  Step 3   seed-dev      create a local institution with users  <- done
  Step 4   rotate-key    generate / promote / retire a signing key
  Step 8   create-tenant provision an institution and its first admin

The CLI calls the same service layer the HTTP API does — nothing in
`app/services/` imports FastAPI, which is what makes that possible.
"""

from __future__ import annotations

import asyncio
import time

import typer

from app.core.config import settings

app = typer.Typer(help="TeachAssist auth operator commands", no_args_is_help=True)


def _redacted_target(url: str) -> str:
    """host:port/database, with the credentials stripped."""
    return url.rsplit("@", 1)[-1] if "@" in url else url


@app.command()
def info() -> None:
    """Print the effective configuration. Secrets are never included."""
    typer.echo(f"service        : {settings.service_name}")
    typer.echo(f"environment    : {settings.app_env}")
    typer.echo(f"issuer         : {settings.issuer}")
    typer.echo(f"audience       : {settings.audience}")
    typer.echo(f"signer backend : {settings.signer_backend}")
    typer.echo(f"access ttl     : {settings.access_token_ttl_seconds}s")
    typer.echo(f"jwks uri       : {settings.jwks_uri}")
    typer.echo(f"database       : {_redacted_target(settings.database_url)}")
    typer.echo(f"db ssl mode    : {settings.db_ssl_mode}")


@app.command("db-check")
def db_check() -> None:
    """Connect to the database and report version and round-trip latency.

    Latency is printed because it is the thing that decides how you work: a
    paused Aurora cluster takes ~15 s to resume, and a cross-continent round
    trip adds 150-250 ms to every query in the integration suite.
    """
    from sqlalchemy import text

    from app.core.db import engine

    async def _check() -> int:
        typer.echo(f"connecting to {_redacted_target(settings.database_url)} ...")
        started = time.perf_counter()
        try:
            async with engine.connect() as conn:
                connect_ms = (time.perf_counter() - started) * 1000
                version = (await conn.execute(text("SELECT version()"))).scalar_one()

                ping_started = time.perf_counter()
                await conn.execute(text("SELECT 1"))
                ping_ms = (time.perf_counter() - ping_started) * 1000
        except Exception as exc:
            typer.secho(f"FAILED: {type(exc).__name__}: {exc}", fg=typer.colors.RED)
            typer.echo(
                "\nCommon causes:\n"
                "  * your public IP changed -- re-run `terraform apply` in ../platform\n"
                "  * the cluster is resuming from a pause -- wait ~15 s and retry\n"
                "  * DB_SSL_MODE=disable against a cluster with rds.force_ssl=1"
            )
            return 1
        finally:
            await engine.dispose()

        typer.secho("connected", fg=typer.colors.GREEN)
        typer.echo(f"  server   : {str(version).split(' on ')[0]}")
        typer.echo(f"  connect  : {connect_ms:.0f} ms")
        typer.echo(f"  query    : {ping_ms:.0f} ms round trip")
        if ping_ms > 100:
            typer.secho(
                f"\n  {ping_ms:.0f} ms per query is high. Every integration test pays it;\n"
                "  prefer running the unit suite locally and integration in CI.",
                fg=typer.colors.YELLOW,
            )
        return 0

    raise typer.Exit(asyncio.run(_check()))


# ── Seeding ─────────────────────────────────────────────────────────────────

# Invented people. This project never holds real credentials, and a seeder is
# exactly where a "just this once" copy of a real export would end up -- so the
# names live here, in source, where that cannot happen by accident.
SEED_USERS = [
    ("admin@springfield.example.com", "Seymour Skinner", "admin"),
    ("teacher@springfield.example.com", "Edna Krabappel", "teacher"),
    ("tutor@springfield.example.com", "Elizabeth Hoover", "tutor"),
]


@app.command("seed-dev")
def seed_dev(
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print exactly what would be written. Touches no database."
    ),
) -> None:
    """Create a development institution with one user per role.

    Runs through the same services the HTTP API does, so the rows it writes obey
    every rule the API enforces -- normalisation, uniqueness, Argon2 parameters,
    audit -- rather than being INSERTed past them.

    `--dry-run` is the half that works with no database, and it is not a
    courtesy: the provisioning planner is pure, so this prints the real plan
    rather than an approximation of it.
    """
    import uuid

    from app.core.scopes import ROLE_TEMPLATE_SCOPES
    from app.services.provisioning import plan_tenant_roles

    if settings.app_env == "prod":
        # A seeder pointed at production is one mistyped environment variable
        # away at all times, and it writes credentials.
        typer.secho("refusing to seed a production environment", fg=typer.colors.RED)
        raise typer.Exit(1)

    slug = settings.dev_seed_tenant_slug
    password = settings.dev_seed_password

    if dry_run:
        plan = plan_tenant_roles(uuid.uuid4())
        typer.secho(f"would seed institution {slug!r}", fg=typer.colors.GREEN)
        for line in plan.describe():
            typer.echo(line)
        for email, name, role in SEED_USERS:
            typer.echo(f"  user {email:<36} {name:<18} role={role}")
        typer.echo("")
        typer.echo(f"{len(plan.roles)} roles, {len(SEED_USERS)} users, 0 written")
        raise typer.Exit(0)

    if not password:
        typer.secho("DEV_SEED_PASSWORD is unset. Set it, or use --dry-run.", fg=typer.colors.RED)
        raise typer.Exit(1)

    from app.core.db import SessionLocal, engine
    from app.core.errors import Conflict
    from app.models.tenant import Tenant
    from app.repositories.role import SqlRoleRepository
    from app.repositories.tenant import SqlTenantRepository
    from app.repositories.user import SqlUserRepository
    from app.schemas.user import UserCreate
    from app.services.audit import SqlAuditSink
    from app.services.password_service import get_password_service
    from app.services.user_service import UserService

    async def _seed() -> int:
        created = {"tenants": 0, "roles": 0, "users": 0}
        async with SessionLocal() as session:
            tenants = SqlTenantRepository(session)
            tenant = await tenants.by_slug(slug)
            if tenant is None:
                tenant = await tenants.add(
                    Tenant(
                        id=uuid.uuid4(),
                        slug=slug,
                        name=slug.replace("-", " ").title(),
                        status="active",
                        settings={},
                    )
                )
                created["tenants"] += 1

            roles = SqlRoleRepository(session, tenant.id)
            existing = {r.key for r in await roles.list()}
            for role_plan in plan_tenant_roles(tenant.id).roles:
                if role_plan.key in existing:
                    continue
                await roles.add(role_plan.role)
                for role_scope in role_plan.scopes:
                    await roles.add_scope(role_scope)
                created["roles"] += 1

            service = UserService(
                SqlUserRepository(session, tenant.id),
                roles,
                get_password_service(),
                SqlAuditSink(session),
                tenant.id,
            )
            for email, name, role in SEED_USERS:
                try:
                    await service.create(
                        UserCreate(email=email, password=password, full_name=name, role_keys=[role])
                    )
                    created["users"] += 1
                except Conflict:
                    # Re-running the seeder is normal; it tops up rather than
                    # failing halfway and leaving a partial institution.
                    continue

            await session.commit()

        typer.secho(f"seeded {slug}", fg=typer.colors.GREEN)
        for label, count in created.items():
            typer.echo(f"  {label:<8}: {count} new")
        typer.echo("")
        typer.echo(f"roles available: {', '.join(sorted(ROLE_TEMPLATE_SCOPES))}")
        await engine.dispose()
        return 0

    raise typer.Exit(asyncio.run(_seed()))


# ── Signing keys ────────────────────────────────────────────────────────────


@app.command("rotate-key")
def rotate_key(
    first: bool = typer.Option(
        False, "--first", help="Activate immediately. Only valid when no key exists yet."
    ),
    promote: str = typer.Option("", help="Promote this kid from pending to active."),
) -> None:
    """Generate, promote or inspect signing keys.

    Rotation is deliberately two steps. `rotate-key` publishes a new key as
    `pending` -- it appears in JWKS at once and signs nothing. Only after
    consumers have had twice their cache TTL to notice it may `--promote` make
    it active, and promote REFUSES if asked sooner. A runbook note saying "wait
    ten minutes" is a note someone skips during an incident.

    `--first` is the exception, for the very first key: there is nothing to
    rotate away from and no consumer holding a key set that lacks it.
    """
    from app.core.db import SessionLocal, engine
    from app.crypto.keywrap import resolve_kek
    from app.repositories.signing_key import SqlSigningKeyRepository
    from app.services.audit import SqlAuditSink
    from app.services.key_service import KeyService

    async def _run() -> int:
        async with SessionLocal() as session:
            service = KeyService(
                SqlSigningKeyRepository(session),
                SqlAuditSink(session),
                kek=resolve_kek(),
                min_publish_delay_seconds=max(
                    settings.key_min_publish_delay_seconds,
                    settings.jwks_cache_ttl_seconds * 2,
                ),
            )
            if promote:
                key = await service.promote(promote)
                typer.secho(f"promoted {key.kid} to active", fg=typer.colors.GREEN)
            else:
                key = await service.generate(activate_immediately=first)
                typer.secho(f"generated {key.kid} ({key.status})", fg=typer.colors.GREEN)
                if not first:
                    delay = max(
                        settings.key_min_publish_delay_seconds,
                        settings.jwks_cache_ttl_seconds * 2,
                    )
                    typer.echo(f"  published in JWKS now; promotable in {delay}s")
            await session.commit()

            typer.echo("  key set now published:")
            for published in await service.repo.published():
                typer.echo(f"    {published.status:<9} {published.kid}")
        await engine.dispose()
        return 0

    raise typer.Exit(asyncio.run(_run()))


if __name__ == "__main__":
    app()
