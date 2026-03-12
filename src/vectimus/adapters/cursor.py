"""Cursor hook normaliser.

Translates Cursor hook payloads into canonical VectimusEvent objects.
Handles both legacy per-event hooks and structured preToolUse/postToolUse payloads.
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
    CURSOR_EVENT_MAP,
    CURSOR_TOOL_MAP,
    _extract_command,
    _extract_file_content,
    _extract_file_path,
    _hook_event_to_event_type,
    _now_iso,
    _refine_shell_action,
    _resolve_script_content,
    register,
)


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
        file_path = _extract_file_path(payload)
        raw_tool = hook_event

    if action_type == ActionType.SHELL_COMMAND and command:
        action_type = _refine_shell_action(command)

    # MCP fields — extract server/tool from mcp__server__tool naming convention.
    mcp_server: str | None = None
    mcp_tool: str | None = None
    if raw_tool.startswith("mcp__"):
        parts = raw_tool.split("__", 2)
        if len(parts) >= 3:
            mcp_server = parts[1]
            mcp_tool = parts[2]
        elif len(parts) == 2:
            mcp_server = parts[1]

    cwd = payload.get("cwd")
    workspace_roots: list[str] = payload.get("workspace_roots", [])
    repository = workspace_roots[0] if workspace_roots else None

    # Content inspection: extract file/script content for double evaluation.
    file_content: str | None = None
    script_content: str | None = None
    effective_input = tool_input if tool_name else payload
    if action_type == ActionType.FILE_WRITE:
        file_content = _extract_file_content(effective_input)
    elif action_type == ActionType.SHELL_COMMAND and command:
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
            mcp_server=mcp_server,
            mcp_tool=mcp_tool,
            file_content=file_content,
            script_content=script_content,
            raw_input=effective_input,
        ),
        context=ContextInfo(
            cwd=cwd,
            repository=repository,
        ),
    )
