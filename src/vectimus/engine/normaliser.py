"""Tool-agnostic event normalisation.

Translates tool-specific JSON payloads (Claude Code, Cursor, Copilot) into
canonical VectimusEvent objects.  New tools are added by registering a
normaliser function with the @register decorator.

Tool-specific normalisers live in ``vectimus.adapters`` and are loaded
automatically when ``normalise()`` is first called.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vectimus.engine.enrichment import enrich
from vectimus.engine.models import (
    ActionType,
    EventType,
    VectimusEvent,
)

# ---------------------------------------------------------------------------
# Tool name -> action type mappings (shared across adapters)
# ---------------------------------------------------------------------------

CLAUDE_CODE_TOOL_MAP: dict[str, str] = {
    "Bash": ActionType.SHELL_COMMAND,
    "Write": ActionType.FILE_WRITE,
    "Edit": ActionType.FILE_WRITE,
    "MultiEdit": ActionType.FILE_WRITE,
    "Read": ActionType.FILE_READ,
    "Grep": ActionType.FILE_READ,
    "Glob": ActionType.FILE_READ,
    "WebFetch": ActionType.WEB_REQUEST,
    "WebSearch": ActionType.WEB_REQUEST,
    "Task": ActionType.AGENT_SPAWN,
    "Agent": ActionType.AGENT_SPAWN,
    "TeamCreate": ActionType.AGENT_SPAWN,
    "SendMessage": ActionType.AGENT_MESSAGE,
}

CURSOR_EVENT_MAP: dict[str, str] = {
    "beforeShellExecution": ActionType.SHELL_COMMAND,
    "beforeMCPExecution": ActionType.MCP_TOOL,
    "beforeReadFile": ActionType.FILE_READ,
    "afterFileEdit": ActionType.FILE_WRITE,
}

# Cursor preToolUse sends tool_name; map to action types.
CURSOR_TOOL_MAP: dict[str, str] = {
    "Shell": ActionType.SHELL_COMMAND,
    "Read": ActionType.FILE_READ,
    "Write": ActionType.FILE_WRITE,
    "Edit": ActionType.FILE_WRITE,
    "Task": ActionType.AGENT_SPAWN,
}

COPILOT_TOOL_MAP: dict[str, str] = {
    # VS Code Copilot Agent tool names
    "runTerminalCommand": ActionType.SHELL_COMMAND,
    "editFiles": ActionType.FILE_WRITE,
    "createFile": ActionType.FILE_WRITE,
    "deleteFile": ActionType.FILE_WRITE,
    "readFile": ActionType.FILE_READ,
    "pushToGitHub": ActionType.GIT_OPERATION,
    # GitHub Copilot CLI tool names (lowercase)
    "bash": ActionType.SHELL_COMMAND,
    "edit": ActionType.FILE_WRITE,
    "create": ActionType.FILE_WRITE,
    "view": ActionType.FILE_READ,
}

GEMINI_CLI_TOOL_MAP: dict[str, str] = {
    "run_shell_command": ActionType.SHELL_COMMAND,
    "read_file": ActionType.FILE_READ,
    "write_file": ActionType.FILE_WRITE,
    "edit_file": ActionType.FILE_WRITE,
    "list_directory": ActionType.FILE_READ,
}

OPENCODE_TOOL_MAP: dict[str, str] = {
    "bash": ActionType.SHELL_COMMAND,
    "read": ActionType.FILE_READ,
    "write": ActionType.FILE_WRITE,
    "edit": ActionType.FILE_WRITE,
    "patch": ActionType.FILE_WRITE,
    "grep": ActionType.FILE_READ,
    "find": ActionType.FILE_READ,
    "ls": ActionType.FILE_READ,
    "webfetch": ActionType.WEB_REQUEST,
}

# Patterns that refine a shell_command into a more specific action type.
_INFRA_PREFIXES = ("terraform", "kubectl", "docker", "aws", "gcloud", "az")
_PKG_PREFIXES = ("npm", "pip", "cargo", "yarn", "pnpm", "bun")
_GIT_PREFIX = "git"


_SHELL_WRAPPERS = ("sudo", "env", "nohup", "nice", "time", "exec", "command")


def _refine_shell_action(command: str) -> str:
    """Detect infrastructure, package and git commands inside shell invocations."""
    stripped = command.strip()

    # Strip common wrapper prefixes (sudo, env, nohup, nice, etc.)
    changed = True
    while changed:
        changed = False
        for wrapper in _SHELL_WRAPPERS:
            if stripped.startswith(wrapper + " "):
                stripped = stripped[len(wrapper) :].strip()
                # For `env`, skip flags (-i, -u) and VAR=val assignments.
                if wrapper == "env":
                    while stripped:
                        token = stripped.split(None, 1)[0] if stripped else ""
                        if token.startswith("-") or "=" in token:
                            stripped = stripped.split(None, 1)[1] if " " in stripped else ""
                        else:
                            break
                changed = True

    first_word = stripped.split()[0] if stripped.split() else ""

    # Strip absolute path to get the binary name (e.g. /usr/bin/npm -> npm).
    if "/" in first_word:
        first_word = first_word.rsplit("/", 1)[-1]

    if first_word in _INFRA_PREFIXES or first_word.startswith("kubectl"):
        return ActionType.INFRASTRUCTURE
    if first_word in _PKG_PREFIXES:
        return ActionType.PACKAGE_OPERATION
    if first_word == _GIT_PREFIX:
        return ActionType.GIT_OPERATION
    return ActionType.SHELL_COMMAND


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

NormaliserFn = Callable[[dict[str, Any]], VectimusEvent]
_REGISTRY: dict[str, NormaliserFn] = {}
_ADAPTERS_LOADED = False


def register(source_tool: str) -> Callable[[NormaliserFn], NormaliserFn]:
    """Decorator to register a normaliser function for a source tool."""

    def wrapper(fn: NormaliserFn) -> NormaliserFn:
        _REGISTRY[source_tool] = fn
        return fn

    return wrapper


def _ensure_adapters_loaded() -> None:
    """Import adapter modules so their @register decorators execute."""
    global _ADAPTERS_LOADED  # noqa: PLW0603
    if not _ADAPTERS_LOADED:
        import vectimus.adapters  # noqa: F401

        _ADAPTERS_LOADED = True


def normalise(raw_payload: dict[str, Any], source_tool: str) -> VectimusEvent:
    """Normalise a raw tool payload into a VectimusEvent.

    Looks up the registered normaliser for *source_tool* and delegates to it.
    Raises ValueError if no normaliser is registered.
    """
    _ensure_adapters_loaded()
    fn = _REGISTRY.get(source_tool)
    if fn is None:
        raise ValueError(
            f"No normaliser registered for source tool '{source_tool}'.  "
            f"Registered tools: {sorted(_REGISTRY)}"
        )
    event = fn(raw_payload)
    # Ensure the source tool matches what the caller specified, not what the
    # adapter hardcodes.  This matters when multiple source names share the
    # same normaliser (e.g. "claude-agent-sdk" reuses the Claude Code adapter).
    if event.source.tool != source_tool:
        event.source.tool = source_tool
    return enrich(event)


# ---------------------------------------------------------------------------
# Helpers (used by adapter modules)
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _extract_command(tool_input: dict[str, Any]) -> str | None:
    """Pull a command string from tool_input if present."""
    return tool_input.get("command") or tool_input.get("cmd")


def _extract_file_path(tool_input: dict[str, Any]) -> str | None:
    raw = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("filePath")
    if raw and isinstance(raw, str):
        # Normalize path to prevent traversal bypasses against Cedar `like` patterns.
        # Collapse redundant separators and resolve `.` / `..` segments.
        try:
            normalized = os.path.normpath(raw)
            # Preserve leading `/` for absolute paths and `./` awareness.
            return normalized
        except (OSError, ValueError):
            return raw
    return raw


def _extract_url(tool_input: dict[str, Any]) -> str | None:
    return tool_input.get("url") or tool_input.get("uri")


def _hook_event_to_event_type(hook_event: str) -> str:
    """Map hook event names to pre/post action."""
    lower = hook_event.lower()
    if "post" in lower or "after" in lower:
        return EventType.POST_ACTION
    return EventType.PRE_ACTION


try:
    _CONTENT_INSPECTION_MAX_LINES = max(
        int(os.environ.get("VECTIMUS_CONTENT_MAX_LINES", "5000")), 100
    )
except (TypeError, ValueError):
    _CONTENT_INSPECTION_MAX_LINES = 5000

# Patterns that indicate script execution: interpreter + file path argument.
_SCRIPT_EXEC_RE = re.compile(
    r"^(?:sudo\s+)?(?:bash|sh|zsh|python3?|node|ruby|perl)"
    r"(?:\s+(?:-\w+|--\w[\w-]*))*"  # skip flags like --norc, -e, -c
    r"\s+(\S+)"
)
_DOTSLASH_RE = re.compile(r"^(\./\S+)")


def _extract_file_content(tool_input: dict[str, Any]) -> str | None:
    """Extract file content from a write/edit tool payload, limited to max lines."""
    content = tool_input.get("content") or tool_input.get("new_string")
    if not content or not isinstance(content, str):
        return None
    lines = content.splitlines(keepends=True)
    if len(lines) > _CONTENT_INSPECTION_MAX_LINES:
        return "".join(lines[:_CONTENT_INSPECTION_MAX_LINES])
    return content


def _resolve_script_content(command: str, cwd: str | None) -> str | None:
    """If command executes a script file, read and return its content (line-limited).

    Reads the script line by line to avoid loading entire huge files into memory.
    Returns None if the command is not a script execution pattern or the file
    cannot be read.
    """
    match = _SCRIPT_EXEC_RE.match(command.strip()) or _DOTSLASH_RE.match(command.strip())
    if not match:
        return None

    script_path_str = match.group(1)
    script_path = Path(script_path_str)

    # Resolve relative paths against cwd.
    if not script_path.is_absolute() and cwd:
        script_path = Path(cwd) / script_path

    try:
        lines: list[str] = []
        with open(script_path, errors="replace") as f:
            for i, line in enumerate(f):
                if i >= _CONTENT_INSPECTION_MAX_LINES:
                    break
                lines.append(line)
        return "".join(lines) if lines else None
    except (OSError, ValueError):
        return None


try:
    _EXCESSIVE_TURNS_THRESHOLD = max(int(os.environ.get("VECTIMUS_EXCESSIVE_TURNS", "50")), 1)
except (TypeError, ValueError):
    _EXCESSIVE_TURNS_THRESHOLD = 50


def _build_agent_spawn_command(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Build a synthetic command string from Agent/TeamCreate tool parameters.

    The resulting string is designed for Cedar ``like`` pattern matching,
    not for human readability.  Field order is deterministic so that policies
    can rely on combined patterns (e.g. ``*background=true*``).
    """
    if tool_name == "TeamCreate":
        parts = ["team_create"]
        if team_name := tool_input.get("team_name"):
            parts.append(f"team_name={team_name}")
        return " ".join(parts)

    parts = ["spawn"]
    if subagent_type := tool_input.get("subagent_type"):
        parts.append(f"subagent_type={subagent_type}")
    if mode := tool_input.get("mode"):
        parts.append(f"mode={mode}")
    max_turns = tool_input.get("max_turns")
    if max_turns is not None:
        parts.append(f"max_turns={max_turns}")
        try:
            if int(max_turns) > _EXCESSIVE_TURNS_THRESHOLD:
                parts.append("EXCESSIVE_TURNS")
        except (TypeError, ValueError):
            pass
    if tool_input.get("run_in_background"):
        parts.append("background=true")
    if name := tool_input.get("name"):
        parts.append(f"name={name}")
    return " ".join(parts)


def _build_agent_message_command(tool_input: dict[str, Any]) -> str:
    """Build a synthetic command string from SendMessage tool parameters."""
    parts = ["message"]
    if msg_type := tool_input.get("type"):
        parts.append(f"type={msg_type}")
    if recipient := tool_input.get("recipient"):
        parts.append(f"recipient={recipient}")
    return " ".join(parts)
