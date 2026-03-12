"""GitHub Copilot / VS Code hook normaliser.

Translates Copilot hook payloads into canonical VectimusEvent objects.
Handles both VS Code Copilot Agent (snake_case) and Copilot CLI (camelCase) formats.
"""

from __future__ import annotations

import json
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
    COPILOT_TOOL_MAP,
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

    # MCP fields — extract server/tool from mcp__server__tool naming convention.
    mcp_server: str | None = None
    mcp_tool: str | None = None
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        if len(parts) >= 3:
            mcp_server = parts[1]
            mcp_tool = parts[2]
        elif len(parts) == 2:
            mcp_server = parts[1]

    # Content inspection: extract file/script content for double evaluation.
    cwd = payload.get("cwd")
    file_content: str | None = None
    script_content: str | None = None
    if action_type == ActionType.FILE_WRITE:
        file_content = _extract_file_content(tool_input)
    elif action_type == ActionType.SHELL_COMMAND and command:
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
            mcp_server=mcp_server,
            mcp_tool=mcp_tool,
            file_content=file_content,
            script_content=script_content,
            raw_input=tool_input,
        ),
        context=ContextInfo(
            cwd=cwd,
        ),
    )
