"""Pi extension normaliser.

Translates Pi ``tool_call`` payloads into canonical VectimusEvent objects.

Stricter than the older adapters, deliberately, and for the same reason as
the OpenCode one: anything this module cannot map with confidence raises
instead of guessing, the caller's normalisation-error path denies, and the
extension turns that into a block.  See ``docs/pi-tool-inventory.md`` for
the tool table this enforces and the Pi source it was derived from.
"""

from __future__ import annotations

import ntpath
import posixpath
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

DOC_URL = "https://github.com/vectimus/vectimus/blob/main/docs/pi-tool-inventory.md"

# tool ID -> canonical action type, per the inventory doc.  Tools absent from
# this map are denied rather than assigned a fallback action type.  Pi ships
# exactly these seven; it has no MCP, web or sub-agent tools.
PI_TOOL_MAP: dict[str, str] = {
    "bash": ActionType.SHELL_COMMAND,
    "read": ActionType.FILE_READ,
    "grep": ActionType.FILE_READ,
    "find": ActionType.FILE_READ,
    "ls": ActionType.FILE_READ,
    "edit": ActionType.FILE_WRITE,
    "write": ActionType.FILE_WRITE,
}

# tool ID -> arguments that must be present and non-empty.  A recognised tool
# missing one of these is denied: the argument carries the thing policies match
# on, so evaluating without it would report a pass the call did not earn.
#
# `ls` is absent on purpose, and `grep`/`find` require only their pattern:
# their `path` is optional in Pi's schema and defaults to the working
# directory, so demanding it would deny ordinary sessions.
#
# `edit` lists only its path.  Its replacements can arrive as `edits` or as
# the legacy top-level pair, so requiring either name here would refuse a
# shape Pi itself accepts; `_edit_content` is the single place that decides
# whether the replacements are readable.
_REQUIRED_ARGS: dict[str, tuple[str, ...]] = {
    "bash": ("command",),
    "read": ("path",),
    "write": ("path", "content"),
    "edit": ("path",),
    "grep": ("pattern",),
    "find": ("pattern",),
}


class PiNormalisationError(ValueError):
    """A Pi payload that cannot be mapped, and so must be denied."""


def _require_str(tool_input: dict[str, Any], tool_name: str, key: str) -> str:
    """Return ``tool_input[key]`` as a non-empty string, or raise."""
    value = tool_input.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PiNormalisationError(
            f"Pi tool '{tool_name}' is missing its required '{key}' argument"
        )
    return value


def _check_required(tool_input: dict[str, Any], tool_name: str) -> None:
    """Raise unless every required argument for *tool_name* is usable.

    Strings must be non-empty, collections must be non-empty, numbers may be
    any value.  ``None`` never satisfies a requirement.
    """
    for key in _REQUIRED_ARGS.get(tool_name, ()):
        if key not in tool_input:
            raise PiNormalisationError(
                f"Pi tool '{tool_name}' is missing its required '{key}' argument"
            )
        value = tool_input[key]
        if value is None:
            raise PiNormalisationError(f"Pi tool '{tool_name}' has a null '{key}' argument")
        if isinstance(value, str | list | tuple | dict) and len(value) == 0:
            raise PiNormalisationError(f"Pi tool '{tool_name}' has an empty '{key}' argument")
        if isinstance(value, str) and not value.strip():
            raise PiNormalisationError(f"Pi tool '{tool_name}' has a blank '{key}' argument")


def _optional_str(source: dict[str, Any], key: str) -> str | None:
    value = source.get(key)
    if isinstance(value, str) and value.strip():
        return value
    return None


def _edit_content(tool_input: dict[str, Any]) -> str:
    """Return the text an ``edit`` call is about to put into the file.

    Pi's ``edit`` carries an array of replacements against one file.  The
    content rules need the incoming text, so the ``newText`` values are
    joined; ``oldText`` is a match target, not new content, and stays in
    ``raw_input``.

    Pi's own ``prepareEditArguments`` folds a legacy top-level
    ``{oldText, newText}`` pair into ``edits`` before the hook runs, so the
    array is what arrives in practice.  The legacy pair is accepted anyway
    rather than denying a shape Pi itself accepts.
    """
    edits = tool_input.get("edits")

    if edits is None and "newText" in tool_input:
        return _require_str(tool_input, "edit", "newText")

    if not isinstance(edits, list) or not edits:
        raise PiNormalisationError("Pi tool 'edit' needs a non-empty 'edits' list of replacements")

    texts: list[str] = []
    for index, edit in enumerate(edits):
        if not isinstance(edit, dict):
            raise PiNormalisationError(
                f"Pi tool 'edit' has a non-object replacement at edits[{index}] "
                f"({type(edit).__name__})"
            )
        new_text = edit.get("newText")
        if not isinstance(new_text, str):
            raise PiNormalisationError(
                f"Pi tool 'edit' is missing a string 'newText' at edits[{index}]"
            )
        texts.append(new_text)

    return "\n".join(texts)


def _absolute_path(raw: str, cwd: str | None, tool_name: str) -> str:
    """Return *raw* as an absolute path, resolving it against *cwd*.

    Pi hands tool paths to the adapter exactly as the model wrote them, and
    models routinely write relative ones.  Left relative, a path never
    matches the absolute patterns policies are written against, so a read of
    ``../.ssh/id_rsa`` would pass a rule guarding ``/Users/*/.ssh/*``.

    A relative path with no working directory to resolve against is refused:
    it cannot be made comparable to those patterns, and evaluating it anyway
    would report a pass it did not earn.  The extension always sends
    ``ctx.cwd``, so this only fires on a hand-built payload.

    Both path flavours are recognised regardless of the host platform, so a
    payload from a Windows session is read the same way on a Linux evaluation
    server and vice versa.  Judging ``C:\\Users\\dev\\.ssh\\id_rsa`` by POSIX
    rules alone would call it relative and join it onto the cwd, producing a
    path that matches no rule at all -- a fail-open.  The shared
    ``_extract_file_path`` still does the traversal collapsing afterwards.
    """
    if posixpath.isabs(raw) or ntpath.isabs(raw):
        return raw
    if cwd is None:
        raise PiNormalisationError(
            f"Pi tool '{tool_name}' sent the relative path '{raw}' with no 'cwd' to "
            f"resolve it against, so it cannot be matched against policy paths.  "
            f"See {DOC_URL}"
        )
    # Join with the flavour the working directory is written in, so a Windows
    # cwd keeps its separators instead of gaining a POSIX one.
    flavour = ntpath if ntpath.isabs(cwd) and not posixpath.isabs(cwd) else posixpath
    return flavour.join(cwd, raw)


@register("pi")
def _normalise_pi(payload: dict[str, Any]) -> VectimusEvent:
    """Normalise a Pi ``tool_call`` payload.

    Raises :class:`PiNormalisationError` for anything that cannot be mapped:
    a missing or non-string tool name, a non-object ``tool_input``, an
    unlisted tool, a recognised tool missing a required argument, or a
    relative path that cannot be resolved.  The caller denies on that error.
    """
    if not isinstance(payload, dict):
        raise PiNormalisationError("Pi payload is not a JSON object")

    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise PiNormalisationError("Pi payload has no tool name")
    tool_name = tool_name.strip()

    tool_input = payload.get("tool_input", {})
    if tool_input is None:
        tool_input = {}
    if not isinstance(tool_input, dict):
        raise PiNormalisationError(
            f"Pi tool '{tool_name}' sent a non-object tool_input ({type(tool_input).__name__})"
        )

    action_type = PI_TOOL_MAP.get(tool_name)
    if action_type is None:
        raise PiNormalisationError(
            f"Unknown Pi tool '{tool_name}'.  Vectimus denies tools it cannot map to an "
            f"action type rather than guessing one.  Tools registered by other Pi "
            f"extensions land here.  See {DOC_URL}"
        )

    _check_required(tool_input, tool_name)

    cwd = _optional_str(payload, "cwd")
    command: str | None = None
    file_path: str | None = None
    file_content: str | None = None
    script_content: str | None = None

    if tool_name == "bash":
        command = _require_str(tool_input, tool_name, "command")
        action_type, file_path = _refine_shell_action(command)
        if action_type == ActionType.SHELL_COMMAND:
            script_content = _resolve_script_content(command, cwd)
    elif tool_name == "read":
        file_path = _require_str(tool_input, tool_name, "path")
    elif tool_name == "write":
        file_path = _require_str(tool_input, tool_name, "path")
        file_content = _require_str(tool_input, tool_name, "content")
    elif tool_name == "edit":
        file_path = _require_str(tool_input, tool_name, "path")
        file_content = _edit_content(tool_input)
    elif tool_name in ("grep", "find", "ls"):
        file_path = _optional_str(tool_input, "path")

    # Resolve before normalising: `_extract_file_path` collapses traversal
    # segments but does not make a path absolute, and a relative path cannot
    # be matched against the absolute patterns policies use.  `bash` paths
    # come from `_refine_shell_action` and get the same treatment, since a
    # redirect into a relative path is no more matchable than a `read` of one.
    if file_path is not None:
        file_path = _absolute_path(file_path, cwd, tool_name)
        file_path = _extract_file_path({"file_path": file_path})

    return VectimusEvent(
        event_id=_optional_str(payload, "call_id") or str(uuid.uuid4()),
        timestamp=_now_iso(),
        event_type=_hook_event_to_event_type(payload.get("hook_event_name") or "PreToolUse"),
        source=SourceInfo(
            tool="pi",
            session_id=_optional_str(payload, "session_id"),
        ),
        identity=IdentityInfo(
            principal=_optional_str(payload, "principal") or "unknown",
        ),
        action=ActionInfo(
            action_type=action_type,
            raw_tool_name=tool_name,
            command=command,
            file_path=file_path,
            file_content=file_content,
            script_content=script_content,
            raw_input=tool_input,
        ),
        context=ContextInfo(
            cwd=cwd,
        ),
    )
