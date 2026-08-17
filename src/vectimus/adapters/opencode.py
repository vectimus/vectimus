"""OpenCode plugin normaliser.

Translates OpenCode ``tool.execute.before`` payloads into canonical
VectimusEvent objects.

Stricter than the older adapters, deliberately.  OpenCode's plugin hook
blocks by throwing, so anything this module cannot map with confidence
raises instead of guessing: the caller's normalisation-error path denies,
and the plugin turns that into a thrown error.  See
``docs/opencode-tool-inventory.md`` for the tool table this enforces and
the OpenCode source it was derived from.
"""

from __future__ import annotations

import re
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
    _extract_file_path,
    _hook_event_to_event_type,
    _now_iso,
    _refine_shell_action,
    _resolve_script_content,
    register,
)

DOC_URL = "https://github.com/vectimus/vectimus/blob/main/docs/opencode-tool-inventory.md"

# tool ID -> canonical action type, per the inventory doc.  Tools absent from
# this map are denied rather than assigned a fallback action type.
OPENCODE_TOOL_MAP: dict[str, str] = {
    "bash": ActionType.SHELL_COMMAND,
    "read": ActionType.FILE_READ,
    "glob": ActionType.FILE_READ,
    "grep": ActionType.FILE_READ,
    "lsp": ActionType.FILE_READ,
    "skill": ActionType.FILE_READ,
    "edit": ActionType.FILE_WRITE,
    "write": ActionType.FILE_WRITE,
    "apply_patch": ActionType.FILE_WRITE,
    "task": ActionType.AGENT_SPAWN,
    "webfetch": ActionType.WEB_REQUEST,
    "websearch": ActionType.WEB_REQUEST,
    "todowrite": ActionType.AGENT_MESSAGE,
    "question": ActionType.AGENT_MESSAGE,
    "plan_exit": ActionType.AGENT_MESSAGE,
    "invalid": ActionType.AGENT_MESSAGE,
    "execute": ActionType.SHELL_COMMAND,
    "list_mcp_resources": ActionType.MCP_TOOL,
    "list_mcp_resource_templates": ActionType.MCP_TOOL,
    "read_mcp_resource": ActionType.MCP_TOOL,
}

# tool ID -> arguments that must be present and non-empty.  A recognised tool
# missing one of these is denied: the argument carries the thing policies match
# on, so evaluating without it would report a pass the call did not earn.
_REQUIRED_ARGS: dict[str, tuple[str, ...]] = {
    "bash": ("command",),
    "read": ("filePath",),
    "glob": ("pattern",),
    "grep": ("pattern",),
    "lsp": ("operation", "filePath", "line", "character"),
    "skill": ("name",),
    "edit": ("filePath", "oldString", "newString"),
    "write": ("filePath", "content"),
    "apply_patch": ("patchText",),
    "task": ("description", "prompt", "subagent_type"),
    "webfetch": ("url",),
    "websearch": ("query",),
    "todowrite": ("todos",),
    "question": ("questions",),
    "invalid": ("tool", "error"),
    "execute": ("code",),
    "read_mcp_resource": ("server", "uri"),
}

# apply_patch file headers, e.g. "*** Update File: src/app.ts".
_PATCH_TARGET_RE = re.compile(
    r"^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s*(.+?)\s*$",
    re.MULTILINE,
)


class OpenCodeNormalisationError(ValueError):
    """An OpenCode payload that cannot be mapped, and so must be denied."""


def _require_str(tool_input: dict[str, Any], tool_name: str, key: str) -> str:
    """Return ``tool_input[key]`` as a non-empty string, or raise."""
    value = tool_input.get(key)
    if not isinstance(value, str) or not value.strip():
        raise OpenCodeNormalisationError(
            f"OpenCode tool '{tool_name}' is missing its required '{key}' argument"
        )
    return value


def _check_required(tool_input: dict[str, Any], tool_name: str) -> None:
    """Raise unless every required argument for *tool_name* is usable.

    Strings must be non-empty, collections must be non-empty, numbers may be
    any value.  ``None`` never satisfies a requirement.
    """
    for key in _REQUIRED_ARGS.get(tool_name, ()):
        if key not in tool_input:
            raise OpenCodeNormalisationError(
                f"OpenCode tool '{tool_name}' is missing its required '{key}' argument"
            )
        value = tool_input[key]
        if value is None:
            raise OpenCodeNormalisationError(
                f"OpenCode tool '{tool_name}' has a null '{key}' argument"
            )
        if isinstance(value, str | list | tuple | dict) and len(value) == 0:
            raise OpenCodeNormalisationError(
                f"OpenCode tool '{tool_name}' has an empty '{key}' argument"
            )
        if isinstance(value, str) and not value.strip():
            raise OpenCodeNormalisationError(
                f"OpenCode tool '{tool_name}' has a blank '{key}' argument"
            )


def _patch_targets(patch_text: str) -> list[str]:
    """Return the file paths an apply_patch payload touches."""
    return [m.strip() for m in _PATCH_TARGET_RE.findall(patch_text) if m.strip()]


def _apply_patch_path(tool_input: dict[str, Any]) -> str:
    """Return the single file an apply_patch payload writes, or raise.

    A VectimusEvent carries one ``file_path``, so a patch touching several
    files cannot be evaluated per target in one call.  Rather than evaluate
    the first target and let the rest through unchecked, multi-file patches
    are denied.
    """
    patch_text = _require_str(tool_input, "apply_patch", "patchText")
    targets = _patch_targets(patch_text)
    if not targets:
        raise OpenCodeNormalisationError(
            "OpenCode tool 'apply_patch' has no '*** Add/Update/Delete File:' header, "
            "so the file it writes cannot be determined"
        )
    if len(targets) > 1:
        raise OpenCodeNormalisationError(
            f"OpenCode tool 'apply_patch' touches {len(targets)} files "
            f"({', '.join(targets[:5])}) and Vectimus evaluates one file per action.  "
            "Send one patch per file."
        )
    return targets[0]


def _spawn_command(tool_input: dict[str, Any]) -> str:
    """Build the synthetic command the agent-governance pack matches on.

    Field order is fixed so policies can rely on combined patterns.  Mirrors
    ``_build_agent_spawn_command`` but reads OpenCode's argument names --
    OpenCode calls the background flag ``background``, not
    ``run_in_background``.
    """
    parts = ["spawn"]
    subagent_type = tool_input.get("subagent_type")
    if isinstance(subagent_type, str) and subagent_type:
        parts.append(f"subagent_type={subagent_type}")
    if tool_input.get("background") is True:
        parts.append("background=true")
    task_id = tool_input.get("task_id")
    if isinstance(task_id, str) and task_id:
        parts.append(f"task_id={task_id}")
    return " ".join(parts)


def _optional_str(tool_input: dict[str, Any], key: str) -> str | None:
    value = tool_input.get(key)
    if isinstance(value, str) and value.strip():
        return value
    return None


@register("opencode")
def _normalise_opencode(payload: dict[str, Any]) -> VectimusEvent:
    """Normalise an OpenCode ``tool.execute.before`` payload.

    Raises :class:`OpenCodeNormalisationError` for anything that cannot be
    mapped: a missing or non-string tool name, a non-object ``tool_input``,
    an unlisted tool, or a recognised tool missing a required argument.  The
    caller denies on that error.
    """
    if not isinstance(payload, dict):
        raise OpenCodeNormalisationError("OpenCode payload is not a JSON object")

    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise OpenCodeNormalisationError("OpenCode payload has no tool name")
    tool_name = tool_name.strip()

    tool_input = payload.get("tool_input", {})
    if tool_input is None:
        tool_input = {}
    if not isinstance(tool_input, dict):
        raise OpenCodeNormalisationError(
            f"OpenCode tool '{tool_name}' sent a non-object tool_input "
            f"({type(tool_input).__name__})"
        )

    action_type = OPENCODE_TOOL_MAP.get(tool_name)
    if action_type is None:
        raise OpenCodeNormalisationError(
            f"Unknown OpenCode tool '{tool_name}'.  Vectimus denies tools it cannot "
            f"map to an action type rather than guessing one.  "
            f"MCP tool calls land here because OpenCode's 'server_tool' naming is not "
            f"reversible.  See {DOC_URL}"
        )

    _check_required(tool_input, tool_name)

    cwd = _optional_str(payload, "cwd")
    command: str | None = None
    file_path: str | None = None
    url: str | None = None
    file_content: str | None = None
    script_content: str | None = None
    mcp_server: str | None = None
    mcp_tool: str | None = None

    if tool_name == "bash":
        command = _require_str(tool_input, tool_name, "command")
        action_type, file_path = _refine_shell_action(command)
        if action_type == ActionType.SHELL_COMMAND:
            script_content = _resolve_script_content(command, cwd)
    elif tool_name == "execute":
        command = _require_str(tool_input, tool_name, "code")
    elif tool_name == "read":
        file_path = _require_str(tool_input, tool_name, "filePath")
    elif tool_name == "lsp":
        file_path = _require_str(tool_input, tool_name, "filePath")
    elif tool_name in ("glob", "grep"):
        file_path = _optional_str(tool_input, "path")
    elif tool_name == "edit":
        file_path = _require_str(tool_input, tool_name, "filePath")
        file_content = _require_str(tool_input, tool_name, "newString")
    elif tool_name == "write":
        file_path = _require_str(tool_input, tool_name, "filePath")
        file_content = _require_str(tool_input, tool_name, "content")
    elif tool_name == "apply_patch":
        file_path = _apply_patch_path(tool_input)
        file_content = _require_str(tool_input, tool_name, "patchText")
    elif tool_name == "task":
        command = _spawn_command(tool_input)
    elif tool_name == "webfetch":
        url = _require_str(tool_input, tool_name, "url")
    elif tool_name in (
        "list_mcp_resources",
        "list_mcp_resource_templates",
        "read_mcp_resource",
    ):
        mcp_server = _optional_str(tool_input, "server")
        mcp_tool = tool_name

    # File paths go through the shared normaliser so traversal segments cannot
    # slip past Cedar `like` patterns.
    if file_path is not None:
        file_path = _extract_file_path({"file_path": file_path})

    session_id = _optional_str(payload, "session_id")
    call_id = _optional_str(payload, "call_id")

    return VectimusEvent(
        event_id=call_id or str(uuid.uuid4()),
        timestamp=_now_iso(),
        event_type=_hook_event_to_event_type(payload.get("hook_event_name") or "PreToolUse"),
        source=SourceInfo(
            tool="opencode",
            session_id=session_id,
        ),
        identity=IdentityInfo(
            principal=_optional_str(payload, "principal") or "unknown",
        ),
        action=ActionInfo(
            action_type=action_type,
            raw_tool_name=tool_name,
            command=command,
            file_path=file_path,
            url=url,
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
