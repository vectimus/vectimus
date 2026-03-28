"""``vectimus rule`` -- list, enable, disable and inspect individual rules."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import click

from vectimus.engine.loader import PolicyLoader

_log = logging.getLogger(__name__)


def _parse_duration(value: str) -> float:
    """Parse a human-friendly duration string into seconds.

    Accepts formats like ``30s``, ``5m``, ``2h``, ``1h30m``, ``90m``.
    Raises ``click.BadParameter`` on invalid input.
    """
    value = value.strip().lower()
    pattern = re.compile(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")
    m = pattern.match(value)
    if not m or not any(m.groups()):
        raise click.BadParameter(
            f"Invalid duration '{value}'. Use formats like 30s, 5m, 2h, 1h30m."
        )
    hours = int(m.group(1) or 0)
    minutes = int(m.group(2) or 0)
    seconds = int(m.group(3) or 0)
    total = hours * 3600 + minutes * 60 + seconds
    if total <= 0:
        raise click.BadParameter("Duration must be greater than zero.")
    return float(total)


def _format_remaining(seconds: float) -> str:
    """Format remaining seconds as a human-readable string like ``24m`` or ``1h30m``."""
    total = int(seconds)
    if total < 60:
        return f"{total}s"
    hours, remainder = divmod(total, 3600)
    minutes = remainder // 60
    if hours > 0:
        return f"{hours}h{minutes}m" if minutes else f"{hours}h"
    return f"{minutes}m"


def _notify_daemon_reload() -> None:
    """Tell the daemon to reload if it's running.  Silent on failure."""
    try:
        from vectimus.cli.daemon_client import daemon_reload

        if daemon_reload():
            click.echo("Daemon reloaded.")
    except Exception:
        _log.debug("Failed to notify daemon for reload", exc_info=True)


@click.group("rule")
def rule_cmd() -> None:
    """Manage individual policy rules."""


@rule_cmd.command("list")
@click.option("--config", "config_path", default=None, help="Path to config.toml.")
@click.option("--policy-dir", default=None, help="Policy directory to scan.")
def rule_list(config_path: str | None, policy_dir: str | None) -> None:
    """List all rules across active packs."""
    dirs = [policy_dir] if policy_dir else None
    project_path = Path.cwd()
    loader = PolicyLoader(policy_dirs=dirs, config_path=config_path, project_path=project_path)
    rules = loader.list_rules()

    if not rules:
        click.echo("No rules found.")
        return

    # Determine per-project disabled rules and enforcement overrides.
    project_disabled = loader.config.load_project_overrides(project_path)
    global_disabled = set(loader.config.disabled_rules())
    enforcement_overrides = loader.config.effective_enforcement_overrides(project_path)

    # Query daemon for active temp disables.
    temp_disable_map: dict[str, float] = {}  # rule_id -> remaining_s
    try:
        from vectimus.cli.daemon_client import daemon_query_temp_disables

        resp = daemon_query_temp_disables(project=str(project_path.resolve()))
        if resp and resp.get("status") == "ok":
            for entry in resp.get("temp_disables", []):
                temp_disable_map[entry["rule_id"]] = entry["remaining_s"]
    except Exception:
        _log.debug("Failed to query temp disables from daemon", exc_info=True)

    click.echo(f"{'ID':<25} {'Pack':<15} {'Description':<40} {'Status':<22}")
    click.echo("-" * 105)

    for r in rules:
        desc = r["description"]
        if len(desc) > 38:
            desc = desc[:35] + "..."

        rid = r["rule_id"]
        if rid in temp_disable_map:
            remaining = temp_disable_map[rid]
            status = f"temp ({_format_remaining(remaining)})"
        elif rid in global_disabled:
            status = "disabled (global)"
        elif rid in project_disabled:
            status = "disabled (project)"
        elif not r["enabled"]:
            status = "disabled"
        else:
            # Show enforcement level if not the default "deny".
            effective = enforcement_overrides.get(rid, r.get("enforcement", "deny"))
            if effective == "escalate":
                status = "enabled (escalate)"
            elif effective == "observe":
                status = "enabled (observe)"
            else:
                status = "enabled"
        click.echo(f"{rid:<25} {r['pack']:<15} {desc:<40} {status}")


@rule_cmd.command("disable")
@click.argument("rule_id")
@click.option("--config", "config_path", default=None, help="Path to config.toml.")
@click.option("--policy-dir", default=None, help="Policy directory to scan.")
@click.option(
    "--global", "is_global", is_flag=True, help="Disable the rule globally instead of per-project."
)
@click.option(
    "--for",
    "duration",
    default=None,
    help="Temporarily disable for a duration (e.g. 30m, 2h, 1h30m). "
    "Lives in daemon memory only -- reverts automatically.",
)
def rule_disable(
    rule_id: str,
    config_path: str | None,
    policy_dir: str | None,
    is_global: bool,
    duration: str | None,
) -> None:
    """Disable a specific rule by ID.

    Without --global, disables the rule for the current project only.
    With --global, disables the rule in the global config.
    With --for, temporarily disables via the daemon (no disk write).
    """
    dirs = [policy_dir] if policy_dir else None
    loader = PolicyLoader(policy_dirs=dirs, config_path=config_path, project_path=Path.cwd())

    rule = loader.get_rule(rule_id)
    if rule is None:
        click.echo(f"Rule '{rule_id}' not found.", err=True)
        raise SystemExit(1)

    # Temporary disable via daemon.
    if duration is not None:
        if is_global:
            click.echo(
                "--for cannot be used with --global. Temp disables are per-project.", err=True
            )
            raise SystemExit(1)

        duration_s = _parse_duration(duration)
        project_path = str(Path.cwd().resolve())

        from vectimus.cli.daemon_client import daemon_temp_disable

        resp = daemon_temp_disable(rule_id, project_path, duration_s)
        if resp is None:
            click.echo("Failed to reach daemon. Could not set temp disable.", err=True)
            raise SystemExit(1)
        if resp.get("status") != "ok":
            click.echo(f"Daemon error: {resp.get('reason', 'unknown')}", err=True)
            raise SystemExit(1)

        click.echo(f"Rule '{rule_id}' temporarily disabled for {duration}.")
        click.echo("This disable lives in daemon memory and reverts automatically.")
        return

    if is_global:
        loader.config.disable_rule(rule_id)
        click.echo(f"Rule '{rule_id}' disabled globally.")
    else:
        project_path = Path.cwd()
        loader.config.disable_rule_for_project(rule_id, project_path)
        from vectimus.engine.config import project_local_config_path

        click.echo(
            f"Rule '{rule_id}' disabled for {project_path}.\n"
            f"Config: {project_local_config_path(project_path)}"
        )

    _notify_daemon_reload()


@rule_cmd.command("enable")
@click.argument("rule_id")
@click.option("--config", "config_path", default=None, help="Path to config.toml.")
@click.option("--policy-dir", default=None, help="Policy directory to scan.")
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="Re-enable the rule globally instead of per-project.",
)
def rule_enable(
    rule_id: str,
    config_path: str | None,
    policy_dir: str | None,
    is_global: bool,
) -> None:
    """Re-enable a previously disabled rule.

    Without --global, re-enables the rule for the current project only.
    With --global, re-enables the rule in the global config.
    """
    dirs = [policy_dir] if policy_dir else None
    loader = PolicyLoader(policy_dirs=dirs, config_path=config_path, project_path=Path.cwd())

    rule = loader.get_rule(rule_id)
    if rule is None:
        click.echo(f"Rule '{rule_id}' not found.", err=True)
        raise SystemExit(1)

    # Also clear any temp disable for this rule.
    try:
        from vectimus.cli.daemon_client import daemon_clear_temp_disable

        resp = daemon_clear_temp_disable(rule_id, str(Path.cwd().resolve()))
        if resp and resp.get("status") == "ok":
            click.echo(f"Temp disable for '{rule_id}' cleared.")
    except Exception:
        _log.debug("Failed to clear temp disable via daemon", exc_info=True)

    if is_global:
        loader.config.enable_rule(rule_id)
        click.echo(f"Rule '{rule_id}' enabled globally.")
    else:
        project_path = Path.cwd()
        # Check if the rule is disabled globally.
        if loader.config.is_rule_disabled(rule_id):
            click.echo(
                f"Rule '{rule_id}' is disabled globally.  Use --global to re-enable it everywhere."
            )
            return
        loader.config.enable_rule_for_project(rule_id, project_path)
        click.echo(f"Rule '{rule_id}' enabled for {project_path}.")
        from vectimus.engine.config import project_local_config_path

        click.echo(f"Config: {project_local_config_path(project_path)}")

    _notify_daemon_reload()


@rule_cmd.command("show")
@click.argument("rule_id")
@click.option("--config", "config_path", default=None, help="Path to config.toml.")
@click.option("--policy-dir", default=None, help="Policy directory to scan.")
def rule_show(rule_id: str, config_path: str | None, policy_dir: str | None) -> None:
    """Show full details for a rule including Cedar policy text."""
    dirs = [policy_dir] if policy_dir else None
    project_path = Path.cwd()
    loader = PolicyLoader(policy_dirs=dirs, config_path=config_path, project_path=project_path)

    rule = loader.get_rule(rule_id)
    if rule is None:
        click.echo(f"Rule '{rule_id}' not found.", err=True)
        raise SystemExit(1)

    click.echo(f"Rule:        {rule.rule_id}")
    click.echo(f"Pack:        {rule.pack_name}")
    click.echo(f"Status:      {'enabled' if rule.enabled else 'disabled (user override)'}")

    # Show effective enforcement level with override source.
    config_override = loader.config.get_enforcement_override(rule_id, project_path)
    annotation_level = rule.enforcement
    if config_override:
        click.echo(f"Enforcement: {config_override} (overridden from {annotation_level})")
    else:
        click.echo(f"Enforcement: {annotation_level}")

    click.echo(f"Description: {rule.description}")
    if rule.incident:
        click.echo(f"Incident:    {rule.incident}")
    if rule.controls:
        click.echo(f"Controls:    {rule.controls}")
    if rule.suggested_alternative:
        click.echo(f"Alternative: {rule.suggested_alternative}")
    click.echo(f"Source:      {rule.source_file}")
    click.echo()
    click.echo("Cedar policy:")
    click.echo(rule.cedar_text)


@rule_cmd.command("enforce")
@click.argument("rule_id")
@click.option(
    "--level",
    required=False,
    type=click.Choice(["deny", "escalate", "observe"], case_sensitive=False),
    help="Enforcement level: deny (hard block), escalate (ask user), observe (log only).",
)
@click.option("--config", "config_path", default=None, help="Path to config.toml.")
@click.option("--policy-dir", default=None, help="Policy directory to scan.")
@click.option("--global", "is_global", is_flag=True, help="Apply globally instead of per-project.")
@click.option("--clear", is_flag=True, help="Remove the enforcement override.")
def rule_enforce(
    rule_id: str,
    level: str | None,
    config_path: str | None,
    policy_dir: str | None,
    is_global: bool,
    clear: bool,
) -> None:
    """Override the enforcement level for a rule.

    Changes how a matched rule responds: deny (hard block),
    escalate (ask the user) or observe (log only, allow through).
    Use --clear to remove the override and revert to the policy annotation.
    """
    dirs = [policy_dir] if policy_dir else None
    project_path = Path.cwd() if not is_global else None
    loader = PolicyLoader(policy_dirs=dirs, config_path=config_path, project_path=project_path)

    the_rule = loader.get_rule(rule_id)
    if the_rule is None:
        click.echo(f"Rule '{rule_id}' not found.", err=True)
        raise SystemExit(1)

    if clear:
        loader.config.clear_enforcement_override(rule_id, project_path)
        scope = "globally" if is_global else f"for {project_path}"
        click.echo(f"Enforcement override cleared {scope} for '{rule_id}'.")
        click.echo(f"Effective level: {the_rule.enforcement} (from policy annotation)")
        _notify_daemon_reload()
        return

    if level is None:
        click.echo("Either --level or --clear is required.", err=True)
        raise SystemExit(1)

    loader.config.set_enforcement_override(rule_id, level, project_path)
    scope = "globally" if is_global else f"for {project_path}"
    click.echo(f"Rule '{rule_id}' enforcement set to '{level}' {scope}.")
    _notify_daemon_reload()


@rule_cmd.command("overrides")
@click.option("--config", "config_path", default=None, help="Path to config.toml.")
def rule_overrides(config_path: str | None) -> None:
    """Show project-specific rule overrides for the current directory."""
    from vectimus.engine.config import VectimusConfig

    config = VectimusConfig(config_path)
    project_path = Path.cwd()
    overrides = config.list_project_overrides(project_path)

    if not overrides:
        click.echo(f"No project-specific overrides for {project_path}.")
        return

    click.echo(f"Project overrides for {project_path}:\n")
    for rule_id in overrides:
        click.echo(f"  - {rule_id}")
    click.echo(f"\nOverride file: {config.project_config_path(project_path)}")
