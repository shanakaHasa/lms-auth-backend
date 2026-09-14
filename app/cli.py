"""Operator CLI.

Commands land as the steps do:
  Step 3   seed-dev      create a local institution with users
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


if __name__ == "__main__":
    app()
