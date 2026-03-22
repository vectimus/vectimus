"""``vectimus policy`` -- manage policy updates and sync status."""

from __future__ import annotations

import click


def _notify_daemon_reload() -> None:
    """Tell the daemon to reload if it's running.  Silent on failure."""
    try:
        from vectimus.cli.daemon_client import daemon_reload

        if daemon_reload():
            click.echo("Daemon reloaded.")
    except Exception:
        pass


@click.group("policy")
def policy_cmd() -> None:
    """Manage policy updates and sync status."""


@policy_cmd.command("update")
@click.option("--api-url", default=None, help="Override API URL")
def update(api_url: str | None) -> None:
    """Download the latest policies from the Vectimus API."""
    from vectimus.engine.policy_sync import sync_policies

    click.echo("Checking for policy updates...")
    result = sync_policies(api_url=api_url or "https://api.vectimus.com")
    if result.error:
        click.echo(f"Update failed: {result.error}", err=True)
        raise SystemExit(1)
    if result.is_update:
        click.echo(
            f"Updated to v{result.version}:"
            f" {result.total_policies} policies,"
            f" {result.total_rules} rules"
        )
        for pack, count in sorted(result.packs_updated.items()):
            click.echo(f"  {pack}: {count} policies")
        _notify_daemon_reload()
    else:
        click.echo(f"Already up to date (v{result.version})")


@policy_cmd.command("status")
def status() -> None:
    """Show policy version and auto-update status."""
    from vectimus.engine.policy_sync import get_sync_status

    status = get_sync_status()
    click.echo(f"Bundled version: {status.bundled_version}")
    if status.has_cache:
        click.echo(f"Cached version:  {status.cached_version}")
    else:
        click.echo("Cached version:  (none — using bundled)")
    if status.last_check:
        click.echo(f"Last check:      {status.last_check.strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        click.echo("Last check:      never")
    click.echo(f"Cache dir:       {status.cache_dir}")
