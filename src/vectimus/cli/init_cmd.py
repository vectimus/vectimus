"""``vectimus init`` -- detect installed tools and generate hook configs."""

from __future__ import annotations

import json
import shutil
import tomllib
from pathlib import Path

import click
import tomli_w

from vectimus.cli.detect import (
    TOOL_DISPLAY_NAMES,
    ToolName,
    detect_all,
    tool_runtime_supported,
)
from vectimus.cli.mcp_discover import discover_mcp_servers
from vectimus.engine.config import VectimusConfig
from vectimus.engine.loader import PolicyLoader

# Maps tool names to display labels and configure functions.
_TOOL_CONFIG: dict[ToolName, tuple[str, str]] = {
    ToolName.CLAUDE_CODE: ("Claude Code / Agent SDK", "_configure_claude_code"),
    ToolName.CURSOR: ("Cursor", "_configure_cursor"),
    ToolName.COPILOT: ("VS Code / Copilot", "_configure_copilot"),
    ToolName.GEMINI_CLI: ("Gemini CLI", "_configure_gemini_cli"),
    ToolName.CODEX: ("Codex CLI", "_configure_codex_cli"),
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
@click.option(
    "--ci",
    is_flag=True,
    default=False,
    help="Non-interactive mode for CI/CD pipelines. Skips all prompts. "
    "MCP servers are not allowed unless --allow-mcp is also set.",
)
def init_cmd(
    server_url: str | None,
    policy_dir: str | None,
    allow_mcp: bool,
    ci: bool,
) -> None:
    """Detect installed AI tools and generate Vectimus hook configurations."""
    click.echo("Vectimus init\n")
    configure_fns = {
        ToolName.CLAUDE_CODE: _configure_claude_code,
        ToolName.CURSOR: _configure_cursor,
        ToolName.COPILOT: _configure_copilot,
        ToolName.GEMINI_CLI: _configure_gemini_cli,
        ToolName.CODEX: _configure_codex_cli,
    }

    report = detect_all()
    tools_configured: list[str] = []

    click.echo("Tool detection:")
    for tool_name in ToolName:
        display_name, _ = _TOOL_CONFIG[tool_name]
        result = report.results.get(tool_name)

        if result and result.found:
            supported, reason = tool_runtime_supported(tool_name)
            if not supported:
                click.echo(f"  [ ] {display_name:<18} found but {reason}")
                if result.executable_path:
                    click.echo(f"      {result.executable_path}")
                continue
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

    # -- Generate keypair and copy public key to project --------------------
    try:
        from vectimus.engine.keys import copy_public_key_to_project, ensure_keypair

        key_id = ensure_keypair()
        click.echo(f"\n  Signing key: {key_id}")
        dest = copy_public_key_to_project(key_id, Path.cwd())
        click.echo(f"  Public key copied to: {dest}")
    except Exception as exc:
        click.echo(f"\n  Key setup skipped: {exc}", err=True)

    # -- Ensure .vectimus/receipts/ is gitignored ---------------------------
    _update_gitignore_for_receipts(Path.cwd())

    # -- Clean up old receipts based on retention policy --------------------
    try:
        from vectimus.engine.receipts import cleanup_old_receipts

        receipts_dir = Path.cwd() / ".vectimus" / "receipts"
        if receipts_dir.exists():
            removed = cleanup_old_receipts(receipts_dir, config.get_receipts_retention_days())
            if removed:
                click.echo(f"  Cleaned up {removed} old receipt directory(ies)")
    except Exception:
        pass

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
        approved = _prompt_mcp_servers(discovered, config, allow_mcp=allow_mcp, ci=ci)
        if approved:
            click.echo(f"\nApproved {len(approved)} MCP server(s): {', '.join(sorted(approved))}")
        elif ci and not allow_mcp:
            click.echo(
                "\nMCP servers discovered but not allowed (CI mode). Use --allow-mcp to allow."
            )

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


def _update_gitignore_for_receipts(project_root: Path) -> None:
    """Ensure ``.vectimus/receipts/`` is in the project's ``.gitignore``."""
    gitignore_path = project_root / ".gitignore"

    if gitignore_path.exists():
        content = gitignore_path.read_text()
        # Already covered by a broader pattern or specific line
        if ".vectimus/receipts/" in content or ".vectimus/" in content:
            return
        if not content.endswith("\n"):
            content += "\n"
        content += "\n# Vectimus governance receipts (local evidence)\n"
        content += ".vectimus/receipts/\n"
        gitignore_path.write_text(content)
    else:
        content = "# Vectimus governance receipts (local evidence)\n"
        content += ".vectimus/receipts/\n"
        gitignore_path.write_text(content)


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


def _command_references_vectimus_source(command: str, source: str) -> bool:
    """Return whether *command* invokes Vectimus for the given source."""
    return "vectimus" in command and f"--source {source}" in command


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


def _is_vectimus_gemini_hook(entry: dict) -> bool:
    """Check if a Gemini CLI hook entry was created by Vectimus.

    Gemini CLI uses a nested format: each BeforeTool entry has a ``matcher``
    and a ``hooks`` array of hook definitions.  We check both the nested
    format and the legacy flat format for backwards compatibility.
    """
    # Nested format (correct): {"matcher": ".*", "hooks": [{"command": "...vectimus..."}]}
    for hook in entry.get("hooks", []):
        if "vectimus" in hook.get("command", ""):
            return True
    # Legacy flat format: {"command": "...vectimus...", "matcher": ".*"}
    return "vectimus" in entry.get("command", "")


def _configure_gemini_cli() -> None:
    """Write .gemini/settings.json with Vectimus hooks, preserving existing hooks."""
    config_dir = Path(".gemini")
    config_dir.mkdir(exist_ok=True)
    settings_path = config_dir / "settings.json"

    command = f"{_vectimus_cmd()} hook --source gemini-cli"

    settings: dict = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except json.JSONDecodeError:
            pass

    settings.setdefault("hooks", {})
    existing_hooks: list[dict] = settings["hooks"].get("BeforeTool", [])

    # Merge: remove any previous Vectimus hooks (nested or legacy), then prepend ours.
    cleaned = [h for h in existing_hooks if not _is_vectimus_gemini_hook(h)]
    vectimus_entry = {
        "matcher": ".*",
        "hooks": [
            {
                "type": "command",
                "command": command,
            }
        ],
    }
    cleaned.insert(0, vectimus_entry)
    settings["hooks"]["BeforeTool"] = cleaned

    try:
        settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    except OSError as exc:
        click.echo(f"  Error writing {settings_path}: {exc}", err=True)
        raise SystemExit(1)


def _is_vectimus_codex_hook(hook: dict) -> bool:
    """Check if a Codex hook definition was created by Vectimus."""
    return (
        hook.get("type") == "command"
        and _command_references_vectimus_source(hook.get("command", ""), "codex")
    )


def _is_vectimus_codex_entry(entry: dict) -> bool:
    """Check if a Codex hook matcher entry contains a Vectimus Codex hook."""
    hooks = entry.get("hooks", [])
    if not isinstance(hooks, list):
        return False
    return any(_is_vectimus_codex_hook(hook) for hook in hooks if isinstance(hook, dict))


def _has_global_codex_vectimus_hook() -> bool:
    """Return whether the user-level Codex hooks file already contains Vectimus."""
    hooks_path = Path.home() / ".codex" / "hooks.json"
    if not hooks_path.exists():
        return False
    try:
        data = json.loads(hooks_path.read_text())
    except (json.JSONDecodeError, OSError):
        return False
    entries = data.get("hooks", {}).get("PreToolUse", [])
    return any(_is_vectimus_codex_entry(entry) for entry in entries if isinstance(entry, dict))


def _enable_codex_hooks_feature(config_path: Path) -> bool:
    """Ensure ``[features].codex_hooks = true`` in the repo-local Codex config.

    Returns ``True`` when the file is updated or already enabled. Returns
    ``False`` when the existing file is invalid TOML and must be fixed
    manually.
    """
    data: dict = {}
    if config_path.exists():
        try:
            with open(config_path, "rb") as f:
                loaded = tomllib.load(f)
            if isinstance(loaded, dict):
                data = loaded
        except tomllib.TOMLDecodeError:
            click.echo(
                f"  Warning: {config_path} is invalid TOML. "
                "Set [features].codex_hooks = true manually.",
                err=True,
            )
            return False
        except OSError as exc:
            click.echo(f"  Error reading {config_path}: {exc}", err=True)
            raise SystemExit(1)

    features = data.get("features")
    if not isinstance(features, dict):
        features = {}
        data["features"] = features
    features["codex_hooks"] = True

    config_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(config_path, "wb") as f:
            tomli_w.dump(data, f)
    except OSError as exc:
        click.echo(f"  Error writing {config_path}: {exc}", err=True)
        raise SystemExit(1)
    return True


def _configure_codex_cli() -> None:
    """Write repo-local Codex hooks and feature flag config."""
    config_dir = Path(".codex")
    config_dir.mkdir(exist_ok=True)
    hooks_path = config_dir / "hooks.json"
    config_path = config_dir / "config.toml"

    vectimus_hook = {
        "type": "command",
        "command": f"{_vectimus_cmd()} hook --source codex",
        "statusMessage": "Vectimus policy check",
    }

    hooks_data: dict = {}
    if hooks_path.exists():
        try:
            hooks_data = json.loads(hooks_path.read_text())
        except json.JSONDecodeError:
            pass

    hooks_data.setdefault("hooks", {})
    existing_entries = hooks_data["hooks"].get("PreToolUse", [])

    merged: list[dict] = [{"matcher": "Bash", "hooks": [vectimus_hook]}]
    for entry in existing_entries:
        hooks_list = entry.get("hooks", [])
        if not isinstance(hooks_list, list):
            merged.append(entry)
            continue
        non_vectimus = [
            hook
            for hook in hooks_list
            if isinstance(hook, dict) and not _is_vectimus_codex_hook(hook)
        ]
        if non_vectimus:
            merged.append({**entry, "hooks": non_vectimus})

    hooks_data["hooks"]["PreToolUse"] = merged

    try:
        hooks_path.write_text(json.dumps(hooks_data, indent=2) + "\n")
    except OSError as exc:
        click.echo(f"  Error writing {hooks_path}: {exc}", err=True)
        raise SystemExit(1)

    if _has_global_codex_vectimus_hook():
        click.echo(
            "      Warning: ~/.codex/hooks.json already contains a Vectimus Codex hook. "
            "Codex runs matching user and repo hooks together."
        )

    _enable_codex_hooks_feature(config_path)


def _prompt_mcp_servers(
    discovered: dict[ToolName, list[str]],
    config: VectimusConfig,
    *,
    allow_mcp: bool = False,
    ci: bool = False,
) -> list[str]:
    """Prompt user to approve discovered MCP servers.

    In CI mode, MCP servers are skipped (not allowed) unless ``--allow-mcp``
    is also set.  Returns the list of server names that were approved.
    """
    # Deduplicate across tools while preserving per-tool display.
    all_servers = sorted({s for servers in discovered.values() for s in servers})
    total = len(all_servers)

    click.echo("\nMCP servers detected:")
    for tool_name, servers in discovered.items():
        label = TOOL_DISPLAY_NAMES.get(tool_name, tool_name.value)
        click.echo(f"  {label + ':':<16}{', '.join(servers)}")

    if allow_mcp:
        for server in all_servers:
            config.mcp_allow_server(server)
        return all_servers

    # In CI mode without --allow-mcp, skip all prompts and allow nothing.
    if ci:
        return []

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
