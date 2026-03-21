"""OpenCode hook normaliser.

Translates OpenCode plugin payloads into canonical VectimusEvent objects.
OpenCode tools use lowercase names (bash, read, write, edit, patch, grep,
find, ls, webfetch) and MCP tools arrive with an ``mcp_`` prefix using
single underscores (e.g. ``mcp_sentry_getIssues``).
"""

from __future__ import annotations

import uuid
from typing import Any

from vectimus.engine.models import (
    ActionInfo,
    ActionType,
    ContextInfo,
    IdentityInfo,
    SourceInfo,
    VectimusEvent,
)
from vectimus.engine.normaliser import (
    OPENCODE_TOOL_MAP,
    _extract_command,
    _extract_file_content,
    _extract_file_path,
    _extract_url,
    _hook_event_to_event_type,
    _now_iso,
    _refine_shell_action,
    _resolve_script_content,
    register,
)


@register("opencode")
def _normalise_opencode(payload: dict[str, Any]) -> VectimusEvent:
    """Normalise an OpenCode plugin payload."""
    tool_name: str = payload.get("tool_name", "unknown")
    tool_input: dict[str, Any] = payload.get("tool_input", {})
    hook_event: str = payload.get("hook_event_name", "PreToolUse")

    # Determine action type.
    # OpenCode MCP tools arrive as "mcp_<server>_<tool>" (single underscore).
    if tool_name.startswith("mcp_"):
        action_type = ActionType.MCP_TOOL
    else:
        action_type = OPENCODE_TOOL_MAP.get(tool_name, ActionType.SHELL_COMMAND)

    command = _extract_command(tool_input)

    # Refine shell commands to detect infrastructure, package, git ops.
    if action_type == ActionType.SHELL_COMMAND and command:
        action_type = _refine_shell_action(command)

    # MCP fields: split "mcp_server_tool" on first underscore after "mcp_".
    mcp_server: str | None = None
    mcp_tool: str | None = None
    if tool_name.startswith("mcp_"):
        remainder = tool_name[4:]  # strip "mcp_"
        parts = remainder.split("_", 1)
        mcp_server = parts[0]
        mcp_tool = parts[1] if len(parts) > 1 else None

    # Content inspection fields.
    file_content: str | None = None
    script_content: str | None = None

    if action_type == ActionType.FILE_WRITE:
        file_content = _extract_file_content(tool_input)
    elif action_type == ActionType.SHELL_COMMAND and command:
        script_content = _resolve_script_content(command, payload.get("cwd"))

    return VectimusEvent(
        event_id=str(uuid.uuid4()),
        timestamp=_now_iso(),
        event_type=_hook_event_to_event_type(hook_event),
        source=SourceInfo(
            tool="opencode",
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
