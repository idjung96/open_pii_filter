"""Top-level Typer app aggregating all CLI subcommands."""

from __future__ import annotations

import typer

from app.cli.apikey import apikey_app

cli = typer.Typer(no_args_is_help=True, add_completion=False)
cli.add_typer(apikey_app, name="apikey", help="Manage Phase-3 API keys.")
