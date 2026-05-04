"""`python -m app.cli apikey ...` — API key issuance & lifecycle (Phase 3).

Subcommands:
  issue   — generate a new (key_id, secret) pair (secret printed once)
  list    — show keys (id / name / rate / enabled / revoked)
  disable — temporarily disable a key
  enable  — re-enable a previously disabled key
  revoke  — permanent revoke (sets revoked_at)
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Annotated

import typer
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ApiKey
from app.db.session import get_sessionmaker
from app.security.api_key import (
    ApiKeyError,
    issue_api_key,
    list_keys,
    revoke,
    set_enabled,
)

apikey_app = typer.Typer(no_args_is_help=True, add_completion=False)


async def _with_session[T](
    coro_factory: Callable[[AsyncSession], Awaitable[T]],
) -> T:
    sm = get_sessionmaker()
    async with sm() as session:
        result = await coro_factory(session)
        await session.commit()
        return result


def _run[T](coro_factory: Callable[[AsyncSession], Awaitable[T]]) -> T:
    return asyncio.run(_with_session(coro_factory))


@apikey_app.command("issue")
def cmd_issue(
    name: Annotated[str, typer.Option(help="human-readable label")],
    rate_per_minute: Annotated[int, typer.Option(help="default 60")] = 60,
    rate_per_hour: Annotated[int, typer.Option(help="default 1000")] = 1000,
    ip_allowlist: Annotated[
        str, typer.Option(help="comma-separated CIDR list, optional")
    ] = "",
    admin: Annotated[
        bool,
        typer.Option(
            "--admin",
            help="grant access to /v1/admin/* (Phase 6, internal-only)",
        ),
    ] = False,
    created_by: Annotated[str, typer.Option] = "cli",
) -> None:
    """Issue a new key. The secret is printed once; capture it now."""
    cidrs = [c.strip() for c in ip_allowlist.split(",") if c.strip()] or None

    async def _do(session: AsyncSession) -> tuple[ApiKey, str]:
        try:
            return await issue_api_key(
                session,
                name=name,
                ip_allowlist=cidrs,
                rate_per_minute=rate_per_minute,
                rate_per_hour=rate_per_hour,
                created_by=created_by,
                is_admin=admin,
            )
        except ApiKeyError as e:
            raise typer.BadParameter(str(e)) from e

    row, secret = _run(_do)
    typer.echo("API key issued — capture the secret NOW; it is not recoverable:")
    typer.echo(f"  key_id : {row.key_id}")
    typer.echo(f"  secret : {secret}")
    typer.echo(
        f"  rate   : {row.rate_per_minute}/min, {row.rate_per_hour}/hour"
    )
    if row.is_admin:
        typer.echo("  admin  : YES — keep this key inside the trusted network")
    if row.ip_allowlist:
        typer.echo(f"  ips    : {','.join(row.ip_allowlist)}")


@apikey_app.command("list")
def cmd_list(
    include_revoked: Annotated[bool, typer.Option] = False,
) -> None:
    async def _do(session: AsyncSession) -> list[ApiKey]:
        return await list_keys(session, include_revoked=include_revoked)

    rows = _run(_do)
    typer.echo(
        f"{'key_id':<40} {'name':<24} {'rate(min/hr)':<16} {'on':<3} {'revoked'}"
    )
    for r in rows:
        rate = f"{r.rate_per_minute}/{r.rate_per_hour}"
        flag = "Y" if r.enabled else "n"
        rev = r.revoked_at.isoformat() if r.revoked_at else "-"
        typer.echo(
            f"{r.key_id:<40} {r.name[:23]:<24} {rate:<16} {flag:<3} {rev}"
        )


@apikey_app.command("disable")
def cmd_disable(
    key_id: Annotated[str, typer.Argument()],
) -> None:
    async def _do(session: AsyncSession) -> ApiKey:
        try:
            return await set_enabled(session, key_id, enabled=False)
        except ApiKeyError as e:
            raise typer.BadParameter(str(e)) from e

    _run(_do)
    typer.echo(f"key_id={key_id} disabled")


@apikey_app.command("enable")
def cmd_enable(
    key_id: Annotated[str, typer.Argument()],
) -> None:
    async def _do(session: AsyncSession) -> ApiKey:
        try:
            return await set_enabled(session, key_id, enabled=True)
        except ApiKeyError as e:
            raise typer.BadParameter(str(e)) from e

    _run(_do)
    typer.echo(f"key_id={key_id} enabled")


@apikey_app.command("revoke")
def cmd_revoke(
    key_id: Annotated[str, typer.Argument()],
) -> None:
    """Permanent revoke (sets revoked_at = now)."""
    async def _do(session: AsyncSession) -> ApiKey:
        try:
            return await revoke(session, key_id)
        except ApiKeyError as e:
            raise typer.BadParameter(str(e)) from e

    _run(_do)
    typer.echo(f"key_id={key_id} revoked")
