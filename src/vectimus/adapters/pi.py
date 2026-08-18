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


# A drive-letter prefix (``C:``) or any backslash means the path is written in
# Windows form.  A POSIX-shaped ``//server/share`` with no backslash is left to
# the POSIX branch, since its forward slashes already match policy patterns.
_DRIVE_RE = re.compile(r"^[A-Za-z]:")

# A tilde followed by a digit is the shape of an 8.3 short-name alias
# (``PROGRA~1``), which points at a long name this adapter cannot resolve.
_SHORT_NAME_RE = re.compile(r"~\d")


def _looks_windows(path: str) -> bool:
    """Whether *path* is written in Windows form and must be canonicalised.

    A backslash anywhere, or a leading drive letter, is enough.  A path made
    only of forward slashes -- including a POSIX ``//server/share`` -- is left
    to the POSIX branch, whose separators already match the policy patterns.
    """
    return "\\" in path or bool(_DRIVE_RE.match(path))


def _reject_uncanonicalisable_windows(raw: str, tool_name: str) -> None:
    """Raise for Windows shapes this adapter cannot safely reduce to one form.

    Each would otherwise reach Cedar as a path matching none of the rules it
    should -- a fail-open -- so it is denied rather than guessed at.  ``raw``
    is inspected before ``ntpath.normpath`` collapses anything, because
    normpath would hide the trailing dots and short names that make these
    shapes ambiguous.
    """
    probe = raw.replace("/", "\\")
    if probe.startswith("\\\\.\\") or probe.startswith("\\\\?\\"):
        raise PiNormalisationError(
            f"Pi tool '{tool_name}' sent the Windows device path '{raw}', which names "
            f"no ordinary file and cannot be matched against policy paths.  See {DOC_URL}"
        )
    for segment in re.split(r"[\\/]", raw):
        if segment in ("", ".", ".."):
            continue
        if segment.endswith(".") or segment.endswith(" "):
            raise PiNormalisationError(
                f"Pi tool '{tool_name}' sent the path '{raw}' with a segment Windows "
                f"would strip a trailing dot or space from ('{segment}'), so what "
                f"reaches the filesystem is not what the policy sees.  See {DOC_URL}"
            )
        if _SHORT_NAME_RE.search(segment):
            raise PiNormalisationError(
                f"Pi tool '{tool_name}' sent the 8.3 short-name segment '{segment}' in "
                f"'{raw}', which aliases a long name this adapter cannot resolve.  "
                f"See {DOC_URL}"
            )


def _canonical_windows_path(raw: str, cwd: str | None, tool_name: str) -> str:
    """Return a Windows or UNC path in the form policy patterns are written in.

    The separators and the case are both the problem.  A rule guarding
    ``*.ssh/*`` matches nothing in ``C:\\Users\\dev\\.SSH\\id_rsa``: the
    backslashes are wrong, and Windows' case-insensitivity means ``.SSH`` has
    to count as ``.ssh``.  A Windows session judged by a POSIX evaluation
    server would otherwise pass every path rule it should have failed -- a
    fail-open.

    So every Windows-shaped input is folded to one spelling: traversal
    collapsed with ``ntpath`` (which understands ``..\\``), a relative path
    joined onto the working directory, separators turned to forward slashes,
    and the whole path lowercased.  The adapter therefore guarantees Windows
    paths are matched case-insensitively against the lowercase, forward-slash
    patterns the packs use; a pattern meant to catch a Windows path has to be
    written that way.

    Shapes that cannot be reduced to a matchable absolute path -- device
    namespaces, root-relative paths that dropped their drive, trailing
    dot/space segments, 8.3 aliases -- are refused rather than passed through,
    so an unresolvable Windows path fails closed instead of open.
    """
    _reject_uncanonicalisable_windows(raw, tool_name)

    normalised = ntpath.normpath(raw)
    if not ntpath.isabs(normalised):
        if cwd is None:
            raise PiNormalisationError(
                f"Pi tool '{tool_name}' sent the relative path '{raw}' with no 'cwd' to "
                f"resolve it against, so it cannot be matched against policy paths.  "
                f"See {DOC_URL}"
            )
        _reject_uncanonicalisable_windows(cwd, tool_name)
        normalised = ntpath.normpath(ntpath.join(cwd, raw))

    # Absolute to ntpath but carrying no drive and not a UNC share means a
    # root-relative path like ``\\foo`` whose drive was dropped: it resolves
    # against whichever drive is current, so it matches no rule reliably.
    drive, _ = ntpath.splitdrive(normalised)
    if not drive and not normalised.startswith("\\\\"):
        raise PiNormalisationError(
            f"Pi tool '{tool_name}' sent the root-relative path '{raw}', which names no "
            f"drive and so resolves against whichever one is current -- it cannot be "
            f"matched against policy paths.  See {DOC_URL}"
        )

    return normalised.replace("\\", "/").lower()


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

    Windows-shaped inputs are canonicalised first, before any POSIX shortcut.
    A POSIX-first check would call a mixed-separator UNC path like
    ``//server\\share\\.ssh\\id_rsa`` absolute and hand it on with its
    backslashes intact -- matchable by no rule, so a fail-open.  See
    :func:`_canonical_windows_path` for the single form Windows paths are
    reduced to and the shapes it refuses.
    """
    if _looks_windows(raw):
        return _canonical_windows_path(raw, cwd, tool_name)
    if posixpath.isabs(raw):
        return raw
    if cwd is None:
        raise PiNormalisationError(
            f"Pi tool '{tool_name}' sent the relative path '{raw}' with no 'cwd' to "
            f"resolve it against, so it cannot be matched against policy paths.  "
            f"See {DOC_URL}"
        )
    # A POSIX-shaped relative path under a Windows working directory is
    # resolved and canonicalised the Windows way, so it gains that cwd's drive
    # rather than a bare POSIX join that would match no Windows rule.
    if _looks_windows(cwd):
        return _canonical_windows_path(raw, cwd, tool_name)
    return posixpath.join(cwd, raw)


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
