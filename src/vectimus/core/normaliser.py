"""Tool-agnostic event normalisation.

Translates tool-specific JSON payloads (Claude Code, Cursor, Copilot) into
canonical VectimusEvent objects.  New tools are added by registering a
normaliser function with the @register decorator.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vectimus.core.enrichment import enrich
from vectimus.core.models import (
    ActionInfo,
    ActionType,
    ContextInfo,
    EventType,
    IdentityInfo,
    SourceInfo,
    VectimusEvent,
)

# ---------------------------------------------------------------------------
# Tool name -> action type mappings
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

# Patterns that refine a shell_command into a more specific action type.
_INFRA_PREFIXES = ("terraform", "kubectl", "docker", "aws", "gcloud", "az")
_PKG_PREFIXES = ("npm", "pip", "cargo", "yarn", "pnpm", "bun")
_GIT_PREFIX = "git"


def _refine_shell_action(command: str) -> str:
    """Detect infrastructure, package and git commands inside shell invocations."""
    stripped = command.strip()
    # Handle sudo prefix
    if stripped.startswith("sudo "):
        stripped = stripped[5:].strip()

    first_word = stripped.split()[0] if stripped.split() else ""

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


def register(source_tool: str) -> Callable[[NormaliserFn], NormaliserFn]:
    """Decorator to register a normaliser function for a source tool."""

    def wrapper(fn: NormaliserFn) -> NormaliserFn:
        _REGISTRY[source_tool] = fn
        return fn

    return wrapper


def normalise(raw_payload: dict[str, Any], source_tool: str) -> VectimusEvent:
    """Normalise a raw tool payload into a VectimusEvent.

    Looks up the registered normaliser for *source_tool* and delegates to it.
    Raises ValueError if no normaliser is registered.
    """
    fn = _REGISTRY.get(source_tool)
    if fn is None:
        raise ValueError(
            f"No normaliser registered for source tool '{source_tool}'.  "
            f"Registered tools: {sorted(_REGISTRY)}"
        )
    event = fn(raw_payload)
    return enrich(event)


# ---------------------------------------------------------------------------
# Helper
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
_SCRIPT_EXEC_RE = re.compile(r"^(?:sudo\s+)?(?:bash|sh|zsh|python3?|node|ruby|perl)\s+(\S+)")
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


# ---------------------------------------------------------------------------
# Claude Code normaliser
# ---------------------------------------------------------------------------


@register("claude-code")
def _normalise_claude_code(payload: dict[str, Any]) -> VectimusEvent:
    """Normalise a Claude Code hook payload."""
    tool_name: str = payload.get("tool_name", "unknown")
    tool_input: dict[str, Any] = payload.get("tool_input", {})
    hook_event: str = payload.get("hook_event_name", "PreToolUse")

    # Determine action type
    if tool_name.startswith("mcp__"):
        action_type = ActionType.MCP_TOOL
    else:
        action_type = CLAUDE_CODE_TOOL_MAP.get(tool_name, ActionType.SHELL_COMMAND)

    command = _extract_command(tool_input)

    # Build synthetic commands for agent operations
    if action_type == ActionType.AGENT_SPAWN and tool_name in ("Agent", "TeamCreate"):
        command = _build_agent_spawn_command(tool_name, tool_input)
    elif action_type == ActionType.AGENT_MESSAGE:
        command = _build_agent_message_command(tool_input)

    # Refine shell commands
    if action_type == ActionType.SHELL_COMMAND and command:
        action_type = _refine_shell_action(command)

    # MCP fields
    mcp_server: str | None = None
    mcp_tool: str | None = None
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        if len(parts) >= 3:
            mcp_server = parts[1]
            mcp_tool = parts[2]
        elif len(parts) == 2:
            mcp_server = parts[1]

    # Content inspection fields.
    file_content: str | None = None
    script_content: str | None = None

    if action_type == ActionType.FILE_WRITE:
        file_content = _extract_file_content(tool_input)
    elif action_type == ActionType.SHELL_COMMAND and command:
        script_content = _resolve_script_content(command, payload.get("cwd"))

    return VectimusEvent(
        event_id=payload.get("tool_use_id", str(uuid.uuid4())),
        timestamp=_now_iso(),
        event_type=_hook_event_to_event_type(hook_event),
        source=SourceInfo(
            tool="claude-code",
            session_id=payload.get("session_id"),
        ),
        identity=IdentityInfo(
            principal=payload.get("principal", "unknown"),
        ),
        action=ActionInfo(
            action_type=action_type,
            raw_tool_name=tool_name,
            command=command,
            file_path=_extract_file_path(tool_input),
            url=_extract_url(tool_input),
            mcp_server=mcp_server,
            mcp_tool=mcp_tool,
            file_content=file_content,
            script_content=script_content,
            raw_input=tool_input,
        ),
        context=ContextInfo(
            cwd=payload.get("cwd"),
        ),
    )


# ---------------------------------------------------------------------------
# Cursor normaliser
# ---------------------------------------------------------------------------


@register("cursor")
def _normalise_cursor(payload: dict[str, Any]) -> VectimusEvent:
    """Normalise a Cursor hook payload.

    Handles two payload shapes:
    - ``beforeShellExecution`` / ``afterFileEdit`` etc.: command at top level.
    - ``preToolUse`` / ``postToolUse``: structured ``tool_name`` + ``tool_input``.
    """
    hook_event: str = payload.get("hook_event_name", "beforeShellExecution")

    # preToolUse / postToolUse carry tool_name + tool_input (like Claude Code).
    tool_name: str | None = payload.get("tool_name")
    tool_input: dict[str, Any] = payload.get("tool_input", {})

    if tool_name and hook_event.lower() in ("pretooluse", "posttooluse", "posttoolusefailure"):
        # Structured tool event — resolve action type from tool name.
        if tool_name.startswith("mcp__"):
            action_type = ActionType.MCP_TOOL
        else:
            action_type = (
                CURSOR_TOOL_MAP.get(tool_name)
                or CLAUDE_CODE_TOOL_MAP.get(tool_name)
                or ActionType.SHELL_COMMAND
            )
        command = _extract_command(tool_input)
        file_path = _extract_file_path(tool_input)
        raw_tool = tool_name
    else:
        # Legacy per-event hooks (beforeShellExecution, afterFileEdit, etc.).
        action_type = CURSOR_EVENT_MAP.get(hook_event, ActionType.SHELL_COMMAND)
        command = payload.get("command")
        file_path = payload.get("file_path")
        raw_tool = hook_event

    if action_type == ActionType.SHELL_COMMAND and command:
        action_type = _refine_shell_action(command)

    cwd = payload.get("cwd")
    workspace_roots: list[str] = payload.get("workspace_roots", [])
    repository = workspace_roots[0] if workspace_roots else None

    # Content inspection: extract file/script content for double evaluation.
    file_content: str | None = None
    script_content: str | None = None
    effective_input = tool_input if tool_name else payload
    if action_type == ActionType.FILE_WRITE:
        file_content = _extract_file_content(effective_input)
    if command:
        script_content = _resolve_script_content(command, cwd)

    return VectimusEvent(
        event_id=payload.get("generation_id", str(uuid.uuid4())),
        timestamp=_now_iso(),
        event_type=_hook_event_to_event_type(hook_event),
        source=SourceInfo(
            tool="cursor",
            session_id=payload.get("conversation_id"),
        ),
        identity=IdentityInfo(
            principal=payload.get("principal") or payload.get("user_email") or "unknown",
        ),
        action=ActionInfo(
            action_type=action_type,
            raw_tool_name=raw_tool,
            command=command,
            file_path=file_path,
            file_content=file_content,
            script_content=script_content,
            raw_input=effective_input,
        ),
        context=ContextInfo(
            cwd=cwd,
            repository=repository,
        ),
    )


# ---------------------------------------------------------------------------
# Copilot / VS Code normaliser
# ---------------------------------------------------------------------------


@register("copilot")
def _normalise_copilot(payload: dict[str, Any]) -> VectimusEvent:
    """Normalise a GitHub Copilot / VS Code hook payload.

    Handles two payload formats:
    - VS Code Copilot Agent: ``tool_name`` (snake_case), ``tool_input`` (dict)
    - GitHub Copilot CLI: ``toolName`` (camelCase), ``toolArgs`` (JSON string)
    """
    # Accept both snake_case (VS Code) and camelCase (Copilot CLI) field names.
    tool_name: str = payload.get("tool_name") or payload.get("toolName") or "unknown"

    # VS Code sends tool_input as a dict; Copilot CLI sends toolArgs as a JSON string.
    tool_input: dict[str, Any] | None = payload.get("tool_input")
    if tool_input is None:
        raw_args = payload.get("toolArgs")
        if isinstance(raw_args, str):
            try:
                parsed = json.loads(raw_args)
                tool_input = parsed if isinstance(parsed, dict) else {}
            except (json.JSONDecodeError, TypeError):
                tool_input = {}
        elif isinstance(raw_args, dict):
            tool_input = raw_args
        else:
            tool_input = {}

    hook_event: str = payload.get("hookEventName", "PreToolUse")

    # Look up action type: Copilot-specific names first, then Claude Code names,
    # then fall back to SHELL_COMMAND.
    if tool_name.startswith("mcp__"):
        action_type = ActionType.MCP_TOOL
    else:
        action_type = (
            COPILOT_TOOL_MAP.get(tool_name)
            or CLAUDE_CODE_TOOL_MAP.get(tool_name)
            or ActionType.SHELL_COMMAND
        )

    command = _extract_command(tool_input)
    if action_type == ActionType.SHELL_COMMAND and command:
        action_type = _refine_shell_action(command)

    # Content inspection: extract file/script content for double evaluation.
    cwd = payload.get("cwd")
    file_content: str | None = None
    script_content: str | None = None
    if action_type == ActionType.FILE_WRITE:
        file_content = _extract_file_content(tool_input)
    if command:
        script_content = _resolve_script_content(command, cwd)

    return VectimusEvent(
        event_id=payload.get("tool_use_id", str(uuid.uuid4())),
        timestamp=_now_iso(),
        event_type=_hook_event_to_event_type(hook_event),
        source=SourceInfo(
            tool="copilot",
            session_id=payload.get("sessionId"),
        ),
        identity=IdentityInfo(
            principal=payload.get("principal", "unknown"),
        ),
        action=ActionInfo(
            action_type=action_type,
            raw_tool_name=tool_name,
            command=command,
            file_path=_extract_file_path(tool_input),
            url=_extract_url(tool_input),
            file_content=file_content,
            script_content=script_content,
            raw_input=tool_input,
        ),
        context=ContextInfo(
            cwd=cwd,
        ),
    )
