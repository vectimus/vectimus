"""``vectimus pack`` -- list, enable and disable policy packs."""

from __future__ import annotations

import click

from vectimus.engine.loader import PolicyLoader


@click.group("pack")
def pack_cmd() -> None:
    """Manage policy packs."""


@pack_cmd.command("list")
@click.option("--config", "config_path", default=None, help="Path to config.toml.")
@click.option("--policy-dir", default=None, help="Policy directory to scan.")
def pack_list(config_path: str | None, policy_dir: str | None) -> None:
    """List all installed policy packs with their status."""
    dirs = [policy_dir] if policy_dir else None
    loader = PolicyLoader(policy_dirs=dirs, config_path=config_path)
    packs = loader.list_packs()

    if not packs:
        click.echo("No policy packs found.")
        return

    click.echo(f"{'Pack':<25} {'Version':<10} {'Rules':>6}  {'Status':<10}")
    click.echo("-" * 55)

    for p in packs:
        status = "enabled" if p["enabled"] else "disabled"
        click.echo(f"{p['name']:<25} {p['version']:<10} {p['rule_count']:>6}  {status:<10}")


@pack_cmd.command("enable")
@click.argument("name")
@click.option("--config", "config_path", default=None, help="Path to config.toml.")
@click.option("--policy-dir", default=None, help="Policy directory to scan.")
def pack_enable(name: str, config_path: str | None, policy_dir: str | None) -> None:
    """Enable a policy pack."""
    dirs = [policy_dir] if policy_dir else None
    loader = PolicyLoader(policy_dirs=dirs, config_path=config_path)

    pack = loader.get_pack(name)
    if pack is None:
        click.echo(f"Pack '{name}' not found.", err=True)
        raise SystemExit(1)

    loader.config.set_pack_enabled(name, True)
    click.echo(f"Pack '{name}' enabled.  {pack.rule_count} rules now active.")


@pack_cmd.command("disable")
@click.argument("name")
@click.option("--config", "config_path", default=None, help="Path to config.toml.")
@click.option("--policy-dir", default=None, help="Policy directory to scan.")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation for the base pack.")
def pack_disable(
    name: str,
    config_path: str | None,
    policy_dir: str | None,
    yes: bool,
) -> None:
    """Disable a policy pack."""
    dirs = [policy_dir] if policy_dir else None
    loader = PolicyLoader(policy_dirs=dirs, config_path=config_path)

    pack = loader.get_pack(name)
    if pack is None:
        click.echo(f"Pack '{name}' not found.", err=True)
        raise SystemExit(1)

    # Warn before disabling any pack that contains critical security rules.
    if not yes:
        click.echo(
            f"The '{name}' pack contains security rules.  Disabling it will remove"
            f" {pack.rule_count} rules from evaluation."
        )
        if not click.confirm(f"Disable the '{name}' pack?"):
            click.echo("Aborted.")
            return

    loader.config.set_pack_enabled(name, False)
    click.echo(f"Pack '{name}' disabled.  {pack.rule_count} rules now inactive.")
