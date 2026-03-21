"""``vectimus receipts`` -- manage governance receipts."""

from __future__ import annotations

from pathlib import Path

import click

from vectimus.engine.config import VectimusConfig


@click.group("receipts")
def receipts_cmd() -> None:
    """Manage governance receipts."""


@receipts_cmd.command("prune")
@click.option(
    "--days",
    type=int,
    default=None,
    help="Keep receipts from the last N days. Defaults to config value (7).",
)
@click.option(
    "--all",
    "prune_all",
    is_flag=True,
    default=False,
    help="Remove all receipts regardless of age.",
)
def prune_cmd(days: int | None, prune_all: bool) -> None:
    """Remove old receipt files based on retention policy.

    By default uses the configured retention period (receipts.retention_days,
    default 7).  Use --days to override or --all to remove everything.

    \b
      vectimus receipts prune          Use configured retention (default 7 days)
      vectimus receipts prune --days 3 Keep only last 3 days
      vectimus receipts prune --all    Remove all receipts
    """
    from vectimus.engine.receipts import cleanup_old_receipts

    config = VectimusConfig()
    project_path = Path.cwd()
    receipts_dir = project_path / ".vectimus" / "receipts"

    if not receipts_dir.exists():
        click.echo("No receipts directory found.")
        return

    if prune_all:
        import shutil

        removed = 0
        for entry in sorted(receipts_dir.iterdir()):
            if entry.is_dir():
                shutil.rmtree(entry)
                removed += 1
    else:
        if days is not None:
            retention_days = max(days, 0)
        else:
            retention_days = config.get_receipts_retention_days(project_path)
        removed = cleanup_old_receipts(receipts_dir, retention_days)

    if removed:
        click.echo(f"Pruned {removed} receipt director{'y' if removed == 1 else 'ies'}.")
    else:
        click.echo("No receipts to prune.")
