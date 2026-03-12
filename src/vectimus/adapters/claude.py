"""Claude Code hook normaliser.

Translates Claude Code hook payloads into canonical VectimusEvent objects.
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
    CLAUDE_CODE_TOOL_MAP,
    _build_agent_message_command,
    _build_agent_spawn_command,
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
    if action_type == ActionType.AGENT_SPAWN and tool_name in ("Agent", "Task", "TeamCreate"):
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
