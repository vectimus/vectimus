"""``vectimus remove`` -- remove Vectimus hooks from installed tools."""

from __future__ import annotations

import json
from pathlib import Path

import click

from vectimus.cli.detect import ToolName, detect_all
from vectimus.cli.init_cmd import _is_vectimus_hook


@click.command("remove")
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Remove without confirmation prompt.",
)
def remove_cmd(force: bool) -> None:
    """Remove Vectimus hooks from all detected tools in this project.

    Removes hook entries from Claude Code, Cursor and Copilot config files.
    Preserves any non-Vectimus hooks in those files.  Does not remove
    ~/.vectimus/ config or audit logs.

    \b
      vectimus remove          Remove hooks (with confirmation)
      vectimus remove --force  Remove hooks without asking
    """
    click.echo("Vectimus remove\n")

    report = detect_all()
    removals: list[tuple[str, Path]] = []

    # Check each tool for Vectimus hooks.
    for tool_name in ToolName:
        result = report.results.get(tool_name)
        if not result or not result.found:
            continue

        if tool_name == ToolName.CLAUDE_CODE:
            path = Path(".claude") / "settings.json"
            if path.exists() and _has_vectimus_hooks_claude(path):
                removals.append(("Claude Code", path))

        elif tool_name == ToolName.CURSOR:
            path = Path(".cursor") / "hooks.json"
            if path.exists() and _has_vectimus_hooks_cursor(path):
                removals.append(("Cursor", path))

        elif tool_name == ToolName.COPILOT:
            path = Path(".github") / "hooks" / "vectimus.json"
            if path.exists():
                removals.append(("VS Code / Copilot", path))

        elif tool_name == ToolName.GEMINI_CLI:
            path = Path(".gemini") / "settings.json"
            if path.exists() and _has_vectimus_hooks_gemini(path):
                removals.append(("Gemini CLI", path))

    if not removals:
        click.echo("No Vectimus hooks found in this project.")
        return

    click.echo("Found Vectimus hooks in:")
    for display_name, path in removals:
        click.echo(f"  [{display_name}] {path}")

    if not force:
        click.confirm("\nRemove these hooks?", abort=True)

    remove_dispatch = {
        "Claude Code": _remove_claude_code,
        "Cursor": _remove_cursor,
        "VS Code / Copilot": _remove_copilot,
        "Gemini CLI": _remove_gemini_cli,
    }

    for display_name, path in removals:
        handler = remove_dispatch.get(display_name)
        if handler:
            handler(path)
        click.echo(f"  [-] {display_name:<18} hooks removed")

    click.echo(f"\nRemoved Vectimus from {len(removals)} tool(s).")
    click.echo("To reinstall: vectimus init")


def _has_vectimus_hooks_claude(settings_path: Path) -> bool:
    """Check if a Claude Code settings.json has Vectimus hooks."""
    try:
        settings = json.loads(settings_path.read_text())
    except (json.JSONDecodeError, OSError):
        return False

    entries = settings.get("hooks", {}).get("PreToolUse", [])
    for entry in entries:
        for hook in entry.get("hooks", []):
            if _is_vectimus_hook(hook):
                return True
    return False


def _has_vectimus_hooks_cursor(hooks_path: Path) -> bool:
    """Check if a Cursor hooks.json has Vectimus hooks."""
    try:
        data = json.loads(hooks_path.read_text())
    except (json.JSONDecodeError, OSError):
        return False

    # New format: {"version": 1, "hooks": {"preToolUse": [{"command": "..."}]}}
    hooks = data.get("hooks", {})
    for hook_type in ("preToolUse", "beforeShellExecution"):
        for entry in hooks.get(hook_type, []):
            if "vectimus" in entry.get("command", ""):
                return True

    # Old flat format: {"beforeShellExecution": {"command": "..."}}
    cmd = data.get("beforeShellExecution", {}).get("command", "")
    return "vectimus" in cmd


def _remove_claude_code(settings_path: Path) -> None:
    """Remove Vectimus hooks from .claude/settings.json, preserving other hooks."""
    try:
        settings = json.loads(settings_path.read_text())
    except (json.JSONDecodeError, OSError):
        return

    entries = settings.get("hooks", {}).get("PreToolUse", [])
    cleaned: list[dict] = []

    for entry in entries:
        hooks_list = entry.get("hooks", [])
        non_vectimus = [h for h in hooks_list if not _is_vectimus_hook(h)]
        if non_vectimus:
            cleaned.append({**entry, "hooks": non_vectimus})

    settings["hooks"]["PreToolUse"] = cleaned

    # Clean up empty hook arrays.
    if not cleaned:
        del settings["hooks"]["PreToolUse"]
    if not settings["hooks"]:
        del settings["hooks"]

    # Write back. If settings is now empty (only had hooks), remove the file.
    if not settings:
        settings_path.unlink()
    else:
        settings_path.write_text(json.dumps(settings, indent=2) + "\n")


def _remove_cursor(hooks_path: Path) -> None:
    """Remove Vectimus hooks from .cursor/hooks.json, preserving other hooks."""
    try:
        data = json.loads(hooks_path.read_text())
    except (json.JSONDecodeError, OSError):
        return

    # Remove from new format: hooks.preToolUse / hooks.beforeShellExecution
    hooks = data.get("hooks", {})
    for hook_type in ("preToolUse", "beforeShellExecution"):
        entries = hooks.get(hook_type, [])
        cleaned = [h for h in entries if "vectimus" not in h.get("command", "")]
        if cleaned:
            hooks[hook_type] = cleaned
        elif hook_type in hooks:
            del hooks[hook_type]

    # Remove old flat format.
    old_cmd = data.get("beforeShellExecution", {}).get("command", "")
    if "vectimus" in old_cmd:
        del data["beforeShellExecution"]

    # Clean up empty hooks object.
    if "hooks" in data and not data["hooks"]:
        del data["hooks"]

    # Remove file if only version key remains (or empty).
    remaining_keys = {k for k in data if k != "version"}
    if not remaining_keys:
        hooks_path.unlink()
    else:
        hooks_path.write_text(json.dumps(data, indent=2) + "\n")


def _remove_copilot(hook_path: Path) -> None:
    """Remove Vectimus hooks from .github/hooks/vectimus.json."""
    try:
        data = json.loads(hook_path.read_text())
    except (json.JSONDecodeError, OSError):
        hook_path.unlink(missing_ok=True)
        return

    # Remove from new format: hooks.PreToolUse array
    hooks = data.get("hooks", {})
    pre_hooks = hooks.get("PreToolUse", [])
    cleaned = [h for h in pre_hooks if not _is_vectimus_hook(h)]
    if cleaned:
        hooks["PreToolUse"] = cleaned
    elif "PreToolUse" in hooks:
        del hooks["PreToolUse"]

    # Remove old flat format.
    data.pop("PreToolUse", None)

    # Clean up empty hooks object.
    if "hooks" in data and not data["hooks"]:
        del data["hooks"]

    if not data:
        hook_path.unlink(missing_ok=True)
    else:
        hook_path.write_text(json.dumps(data, indent=2) + "\n")

    # Clean up empty hooks directory.
    parent = hook_path.parent
    if parent.is_dir() and not any(parent.iterdir()):
        parent.rmdir()


def _is_vectimus_gemini_entry(entry: dict) -> bool:
    """Check if a BeforeTool entry was created by Vectimus (nested or legacy)."""
    for hook in entry.get("hooks", []):
        if "vectimus" in hook.get("command", ""):
            return True
    return "vectimus" in entry.get("command", "")


def _has_vectimus_hooks_gemini(settings_path: Path) -> bool:
    """Check if a Gemini CLI settings.json has Vectimus hooks."""
    try:
        settings = json.loads(settings_path.read_text())
    except (json.JSONDecodeError, OSError):
        return False

    hooks = settings.get("hooks", {}).get("BeforeTool", [])
    return any(_is_vectimus_gemini_entry(h) for h in hooks)


def _remove_gemini_cli(settings_path: Path) -> None:
    """Remove Vectimus hooks from .gemini/settings.json, preserving other hooks."""
    try:
        settings = json.loads(settings_path.read_text())
    except (json.JSONDecodeError, OSError):
        return

    hooks = settings.get("hooks", {}).get("BeforeTool", [])
    cleaned = [h for h in hooks if not _is_vectimus_gemini_entry(h)]

    if cleaned:
        settings["hooks"]["BeforeTool"] = cleaned
    elif "BeforeTool" in settings.get("hooks", {}):
        del settings["hooks"]["BeforeTool"]

    # Clean up empty hooks object.
    if "hooks" in settings and not settings["hooks"]:
        del settings["hooks"]

    if not settings:
        settings_path.unlink()
    else:
        settings_path.write_text(json.dumps(settings, indent=2) + "\n")
