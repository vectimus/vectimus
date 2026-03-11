"""``vectimus init`` -- detect installed tools and generate hook configs."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import click

from vectimus.cli.detect import ToolName, detect_all
from vectimus.cli.mcp_discover import discover_mcp_servers
from vectimus.core.config import VectimusConfig
from vectimus.core.loader import PolicyLoader

# Maps tool names to display labels and configure functions.
_TOOL_CONFIG: dict[ToolName, tuple[str, str]] = {
    ToolName.CLAUDE_CODE: ("Claude Code", "_configure_claude_code"),
    ToolName.CURSOR: ("Cursor", "_configure_cursor"),
    ToolName.COPILOT: ("VS Code / Copilot", "_configure_copilot"),
}


@click.command("init")
@click.option(
    "--server-url",
    default=None,
    help="Vectimus server URL.  Omit for local-only mode.",
)
@click.option(
    "--policy-dir",
    default=None,
    help="Directory containing Cedar policies.  Defaults to built-in policies.",
)
@click.option(
    "--allow-mcp",
    is_flag=True,
    default=False,
    help="Auto-allow all discovered MCP servers without prompting.",
)
def init_cmd(server_url: str | None, policy_dir: str | None, allow_mcp: bool) -> None:
    """Detect installed AI tools and generate Vectimus hook configurations."""
    click.echo("Vectimus init\n")

    configure_fns = {
        ToolName.CLAUDE_CODE: _configure_claude_code,
        ToolName.CURSOR: _configure_cursor,
        ToolName.COPILOT: _configure_copilot,
    }

    report = detect_all()
    tools_configured: list[str] = []

    click.echo("Tool detection:")
    for tool_name in ToolName:
        display_name = _TOOL_CONFIG[tool_name][0]
        result = report.results.get(tool_name)

        if result and result.found:
            configure_fns[tool_name]()
            tools_configured.append(tool_name.value)
            method_label = f"({result.method.value})" if result.method else ""
            click.echo(f"  [+] {display_name:<18} {method_label:<8} hook config written")
            if result.executable_path:
                click.echo(f"      {result.executable_path}")
            if tool_name == ToolName.COPILOT and result.has_copilot_extension:
                click.echo("      Copilot extension detected")
        else:
            click.echo(f"  [ ] {display_name:<18} not found")

    if not tools_configured:
        click.echo("\n  No supported tools detected.")
        click.echo("  You can configure hooks manually for your tool.")

    # -- Create config file -------------------------------------------------
    config = VectimusConfig.create_default()
    if server_url:
        config.set_server_url(server_url)
    click.echo(f"\n  Config: {config.path}")

    # Ensure the projects directory exists for per-project overrides.
    projects_dir = Path.home() / ".vectimus" / "projects"
    projects_dir.mkdir(parents=True, exist_ok=True)

    # -- Show pack summary --------------------------------------------------
    dirs = [policy_dir] if policy_dir else None
    loader = PolicyLoader(policy_dirs=dirs, config_path=str(config.path))
    packs = loader.list_packs()

    if packs:
        click.echo("\nPolicy packs:")
        for p in packs:
            status = "enabled" if p["enabled"] else "disabled"
            click.echo(
                f"  [{'+' if p['enabled'] else ' '}] {p['name']:<20} "
                f"v{p['version']}  {p['rule_count']} rules  ({status})"
            )

    # -- MCP server discovery -----------------------------------------------
    discovered = discover_mcp_servers(report)
    if discovered:
        approved = _prompt_mcp_servers(discovered, config, allow_mcp)
        if approved:
            click.echo(f"\nApproved {len(approved)} MCP server(s): {', '.join(sorted(approved))}")

    click.echo(f"\nConfigured {len(tools_configured)} tool(s).")
    if server_url:
        click.echo(f"Server URL: {server_url}")
    else:
        click.echo("Mode: local-only (no server)")

    if policy_dir:
        click.echo(f"Policy directory: {policy_dir}")
    else:
        click.echo("Policies: built-in defaults")

    if server_url:
        click.echo(
            "\nServer URL saved to config. Set VECTIMUS_API_KEY in your\n"
            "environment if the server requires authentication."
        )


def _vectimus_cmd() -> str:
    """Return the path to the vectimus CLI binary.

    Prefers the ``vectimus`` binary on PATH.  Falls back to running
    ``python -m vectimus.cli.main`` for development installs where the
    console script isn't available.
    """
    import shlex
    import sys

    found = shutil.which("vectimus")
    if found:
        return shlex.quote(found)

    return f"{shlex.quote(sys.executable)} -m vectimus.cli.main"


def _is_vectimus_hook(hook: dict) -> bool:
    """Check if a hook entry was created by Vectimus."""
    if hook.get("type") == "command":
        return "vectimus" in hook.get("command", "")
    if hook.get("type") == "http":
        return "vectimus" in hook.get("url", "").lower()
    return False


def _configure_claude_code() -> None:
    """Write .claude/settings.json with Vectimus hooks, preserving existing hooks."""
    config_dir = Path(".claude")
    config_dir.mkdir(exist_ok=True)
    settings_path = config_dir / "settings.json"

    vectimus_hook: dict = {
        "type": "command",
        "command": f"{_vectimus_cmd()} hook --source claude-code",
    }

    settings: dict = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except json.JSONDecodeError:
            pass

    settings.setdefault("hooks", {})
    existing_entries: list[dict] = settings["hooks"].get("PreToolUse", [])

    # Merge: remove any previous Vectimus hooks, then prepend ours.
    merged: list[dict] = []
    merged.append({"matcher": "", "hooks": [vectimus_hook]})
    for entry in existing_entries:
        hooks_list = entry.get("hooks", [])
        non_vectimus = [h for h in hooks_list if not _is_vectimus_hook(h)]
        if non_vectimus:
            merged.append({**entry, "hooks": non_vectimus})

    settings["hooks"]["PreToolUse"] = merged

    try:
        settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    except OSError as exc:
        click.echo(f"  Error writing {settings_path}: {exc}", err=True)
        raise SystemExit(1)


def _configure_cursor() -> None:
    """Write .cursor/hooks.json with Vectimus hooks, preserving existing hooks."""
    config_dir = Path(".cursor")
    config_dir.mkdir(exist_ok=True)
    hooks_path = config_dir / "hooks.json"

    command = f"{_vectimus_cmd()} hook --source cursor"

    existing: dict = {}
    if hooks_path.exists():
        try:
            existing = json.loads(hooks_path.read_text())
        except json.JSONDecodeError:
            pass

    # Cursor expects: {"version": 1, "hooks": {"preToolUse": [{"command": "..."}]}}
    existing.setdefault("version", 1)
    existing.setdefault("hooks", {})

    # Use preToolUse to cover all tool types (shell, file edits, reads, etc.).
    pre_hooks: list[dict] = existing["hooks"].get("preToolUse", [])
    pre_hooks = [h for h in pre_hooks if "vectimus" not in h.get("command", "")]
    pre_hooks.insert(0, {"command": command})
    existing["hooks"]["preToolUse"] = pre_hooks

    # Clean up old flat format if present (from earlier vectimus versions).
    existing.pop("beforeShellExecution", None)
    existing["hooks"].pop("beforeShellExecution", None)

    try:
        hooks_path.write_text(json.dumps(existing, indent=2) + "\n")
    except OSError as exc:
        click.echo(f"  Error writing {hooks_path}: {exc}", err=True)
        raise SystemExit(1)


def _configure_copilot() -> None:
    """Write .github/hooks/ config for Copilot / VS Code, preserving existing hooks."""
    config_dir = Path(".github") / "hooks"
    config_dir.mkdir(parents=True, exist_ok=True)
    hook_path = config_dir / "vectimus.json"

    command = f"{_vectimus_cmd()} hook --source copilot"

    existing: dict = {}
    if hook_path.exists():
        try:
            existing = json.loads(hook_path.read_text())
        except json.JSONDecodeError:
            pass

    # Copilot expects: {"hooks": {"PreToolUse": [{"type": "command", "command": "..."}]}}
    existing.setdefault("hooks", {})
    pre_hooks: list[dict] = existing["hooks"].get("PreToolUse", [])
    pre_hooks = [h for h in pre_hooks if not _is_vectimus_hook(h)]
    pre_hooks.insert(0, {"type": "command", "command": command})
    existing["hooks"]["PreToolUse"] = pre_hooks

    # Clean up old flat format if present (from earlier vectimus versions).
    existing.pop("PreToolUse", None)

    try:
        hook_path.write_text(json.dumps(existing, indent=2) + "\n")
    except OSError as exc:
        click.echo(f"  Error writing {hook_path}: {exc}", err=True)
        raise SystemExit(1)


def _prompt_mcp_servers(
    discovered: dict[ToolName, list[str]],
    config: VectimusConfig,
    allow_all: bool,
) -> list[str]:
    """Prompt user to approve discovered MCP servers (or auto-allow with --allow-mcp).

    Returns the list of server names that were approved.
    """
    display_names = {
        ToolName.CLAUDE_CODE: "Claude Code",
        ToolName.CURSOR: "Cursor",
        ToolName.COPILOT: "VS Code",
    }

    # Deduplicate across tools while preserving per-tool display.
    all_servers = sorted({s for servers in discovered.values() for s in servers})
    total = len(all_servers)

    click.echo("\nMCP servers detected:")
    for tool_name, servers in discovered.items():
        label = display_names.get(tool_name, tool_name.value)
        click.echo(f"  {label + ':':<16}{', '.join(servers)}")

    if allow_all:
        for server in all_servers:
            config.mcp_allow_server(server)
        return all_servers

    # Interactive: ask to allow all, then per-server if declined.
    if click.confirm(f"\nAllow all {total} servers?", default=False):
        for server in all_servers:
            config.mcp_allow_server(server)
        return all_servers

    approved: list[str] = []
    for server in all_servers:
        if click.confirm(f"  Allow {server}?", default=True):
            config.mcp_allow_server(server)
            approved.append(server)

    return approved
