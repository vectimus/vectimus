"""Codex CLI hook normaliser.

Translates Codex CLI hook payloads into canonical VectimusEvent objects.
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
    _extract_command,
    _extract_file_content,
    _extract_file_path,
    _hook_event_to_event_type,
    _now_iso,
    _refine_shell_action,
    _resolve_script_content,
    register,
)


@register("codex")
def _normalise_codex(payload: dict[str, Any]) -> VectimusEvent:
    """Normalise a Codex CLI hook payload."""
    tool_name: str = payload.get("tool_name", "unknown")
    tool_input: dict[str, Any] = payload.get("tool_input", {})
    hook_event: str = payload.get("hook_event_name", "PreToolUse")

    action_type = CLAUDE_CODE_TOOL_MAP.get(tool_name, ActionType.SHELL_COMMAND)
    command = _extract_command(tool_input)

    shell_file_path: str | None = None
    if action_type == ActionType.SHELL_COMMAND and command:
        action_type, shell_file_path = _refine_shell_action(command)

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
            tool="codex",
            session_id=payload.get("session_id"),
        ),
        identity=IdentityInfo(
            principal=payload.get("principal", "unknown"),
        ),
        action=ActionInfo(
            action_type=action_type,
            raw_tool_name=tool_name,
            command=command,
            file_path=_extract_file_path(tool_input) or shell_file_path,
            file_content=file_content,
            script_content=script_content,
            raw_input=tool_input,
        ),
        context=ContextInfo(
            cwd=payload.get("cwd"),
        ),
    )
