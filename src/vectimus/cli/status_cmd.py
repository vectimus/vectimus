"""``vectimus status`` -- show tool configs, policy count and audit stats."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import click

from vectimus.engine.config import VectimusConfig, project_local_config_path
from vectimus.engine.loader import PolicyLoader


def _check_claude_code() -> str | None:
    """Return config path if Claude Code hooks point at Vectimus."""
    path = Path(".claude") / "settings.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        hooks = data.get("hooks", {})
        if hooks.get("PreToolUse"):
            return str(path)
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _check_cursor() -> str | None:
    """Return config path if Cursor hooks point at Vectimus."""
    path = Path(".cursor") / "hooks.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        # New format: {"hooks": {"preToolUse": [...]}}
        hooks = data.get("hooks", {})
        if hooks.get("preToolUse") or hooks.get("beforeShellExecution"):
            return str(path)
        # Legacy flat format: {"beforeShellExecution": {...}}
        if data.get("beforeShellExecution"):
            return str(path)
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _check_copilot() -> str | None:
    """Return config path if Copilot hooks point at Vectimus."""
    path = Path(".github") / "hooks" / "vectimus.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        # New format: {"hooks": {"PreToolUse": [...]}}
        hooks = data.get("hooks", {})
        if hooks.get("PreToolUse"):
            return str(path)
        # Legacy flat format: {"PreToolUse": {...}}
        if data.get("PreToolUse"):
            return str(path)
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _read_audit_stats(log_dir: Path) -> dict[str, int | str]:
    """Read recent evaluation stats from the audit log directory."""
    stats: dict[str, int | str] = {
        "total": 0,
        "allow": 0,
        "deny": 0,
        "escalate": 0,
        "last_evaluation": "never",
    }

    if not log_dir.is_dir():
        return stats

    # Find today's log file first, then fall back to the most recent one.
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    today_file = log_dir / f"audit-{today}.jsonl"

    log_file: Path | None = None
    if today_file.exists():
        log_file = today_file
    else:
        # Find the most recent audit file.
        candidates = sorted(log_dir.glob("audit-*.jsonl"), reverse=True)
        if candidates:
            log_file = candidates[0]

    if log_file is None:
        return stats

    try:
        for line in log_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            decision = record.get("decision", {}).get("decision", "")
            stats["total"] = int(stats["total"]) + 1
            if decision in ("allow", "deny", "escalate"):
                stats[decision] = int(stats[decision]) + 1
            recorded_at = record.get("recorded_at", "")
            if recorded_at:
                stats["last_evaluation"] = recorded_at
    except OSError:
        pass

    return stats


@click.command("status")
@click.option(
    "--log-dir",
    default=None,
    help="Audit log directory.  Defaults to ~/.vectimus/.",
)
def status_cmd(log_dir: str | None) -> None:
    """Show which tools are configured, loaded policies and recent stats."""
    click.echo("Vectimus status\n")

    project_path = Path.cwd()

    # -- Tool configurations ------------------------------------------------
    click.echo("Tool configurations:")
    tools_configured = 0

    claude_path = _check_claude_code()
    if claude_path:
        click.echo(f"  [+] Claude Code  {claude_path}")
        tools_configured += 1
    else:
        click.echo("  [ ] Claude Code  not configured")

    cursor_path = _check_cursor()
    if cursor_path:
        click.echo(f"  [+] Cursor       {cursor_path}")
        tools_configured += 1
    else:
        click.echo("  [ ] Cursor       not configured")

    copilot_path = _check_copilot()
    if copilot_path:
        click.echo(f"  [+] Copilot      {copilot_path}")
        tools_configured += 1
    else:
        click.echo("  [ ] Copilot      not configured")

    click.echo(f"\n  {tools_configured}/3 tools configured")

    # -- Project-local config -----------------------------------------------
    local_config = project_local_config_path(project_path)
    if local_config.exists():
        click.echo(f"\nProject config: {local_config}")
    else:
        click.echo("\nProject config: none (.vectimus/config.toml not found)")

    # -- Mode ---------------------------------------------------------------
    config = VectimusConfig()
    if config.is_observe_mode():
        click.echo("\nMode: observe (log only, no blocking)")
    else:
        click.echo("\nMode: enforce")

    # -- Policies -----------------------------------------------------------
    click.echo("\nPolicies:")
    try:
        loader = PolicyLoader(project_path=project_path)
        rules = loader.list_rules()
        packs = loader.list_packs()

        active_packs = [p for p in packs if p["enabled"]]
        active_rules = [r for r in rules if r["enabled"]]
        disabled_rules = [r for r in rules if not r["enabled"]]

        click.echo(f"  {len(active_packs)} pack(s), {len(active_rules)} active rule(s)")

        for p in packs:
            status = "enabled" if p["enabled"] else "disabled"
            click.echo(f"    {p['name']:<20} v{p['version']}  {p['rule_count']} rules  ({status})")

        if disabled_rules:
            # Distinguish global vs project-specific disables.
            project_disabled = config.load_project_overrides(project_path)
            global_disabled = set(config.disabled_rules())

            click.echo(f"\n  {len(disabled_rules)} rule(s) disabled:")
            for r in disabled_rules:
                rid = r["rule_id"]
                if rid in global_disabled:
                    scope = "global"
                elif rid in project_disabled:
                    scope = "this project"
                else:
                    scope = "config"
                click.echo(f"    [-] {rid:<25} ({scope})")

    except Exception as exc:
        click.echo(f"  Error loading policies: {exc}")

    # -- MCP allowlist ------------------------------------------------------
    servers = config.mcp_allowed_servers()
    if servers:
        click.echo(f"\nMCP servers approved: {', '.join(sorted(servers))}")
    else:
        click.echo("\nMCP servers: none approved (all MCP calls blocked)")

    # -- Audit stats --------------------------------------------------------
    audit_dir = Path(log_dir) if log_dir else Path.home() / ".vectimus"
    stats = _read_audit_stats(audit_dir)

    click.echo("\nRecent evaluations:")
    total = stats["total"]
    if total == 0:
        click.echo("  No evaluations recorded yet.")
        click.echo(f"  Log directory: {audit_dir}")
    else:
        deny_rate = int(stats["deny"]) / int(total) * 100 if total else 0
        click.echo(f"  Total:    {stats['total']}")
        click.echo(f"  Allowed:  {stats['allow']}")
        click.echo(f"  Denied:   {stats['deny']} ({deny_rate:.0f}%)")
        click.echo(f"  Escalated: {stats['escalate']}")
        click.echo(f"  Last:     {stats['last_evaluation']}")

    click.echo(f"\nAudit log: {audit_dir}")
