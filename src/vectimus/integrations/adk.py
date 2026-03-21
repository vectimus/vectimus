"""Google Agent Development Kit (ADK) plugin integration for Vectimus.

Provides two mechanisms for governing tool calls in Google ADK agents:

1. ``VectimusADKPlugin`` — for use with ``Runner(plugins=[...])``.
   Applies governance globally to every agent, tool and LLM call managed
   by that runner.  This is the recommended approach.
2. ``create_before_tool_callback`` — factory that returns a callback for
   per-agent use with ``LlmAgent(before_tool_callback=...)``.

Both share the same evaluation pipeline: normalise the tool call to a
VectimusEvent, evaluate against Cedar policies, log to the audit trail,
and allow or block accordingly.

Usage (plugin)::

    from vectimus.integrations.adk import VectimusADKPlugin

    plugin = VectimusADKPlugin(
        policy_dir="./policies",
        observe_mode=False,
    )
    runner = Runner(
        agent=my_agent,
        app_name="my-app",
        session_service=session_service,
        plugins=[plugin],
    )

Usage (per-agent callback)::

    from vectimus.integrations.adk import create_before_tool_callback

    callback = create_before_tool_callback(
        policy_dir="./policies",
        observe_mode=False,
    )
    agent = LlmAgent(
        name="MyAgent",
        model="gemini-2.0-flash",
        before_tool_callback=callback,
    )

Dependencies (``google-adk``) are guarded behind lazy checks so that
``import vectimus`` works without them installed.  An ``ImportError``
with install instructions is raised only when the user tries to
instantiate the plugin or call the callback factory.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from vectimus.engine.audit import write_audit
from vectimus.engine.evaluator import PolicyEngine
from vectimus.engine.loader import PolicyLoader
from vectimus.engine.models import (
    ActionInfo,
    ActionType,
    ContextInfo,
    DecisionVerdict,
    EventType,
    IdentityInfo,
    SourceInfo,
    VectimusEvent,
)

if TYPE_CHECKING:
    from collections.abc import Callable

# ---------------------------------------------------------------------------
# Lazy dependency check
# ---------------------------------------------------------------------------

_INSTALL_MSG = (
    "Google ADK is required for the Vectimus ADK integration. "
    "Install it with: pip install vectimus[adk]"
)


def _check_adk_installed() -> None:
    """Raise ImportError with a helpful message if google-adk is missing."""
    try:
        import google.adk  # noqa: F401
    except ImportError:
        raise ImportError(_INSTALL_MSG) from None


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Map well-known ADK / Gemini tool names to Vectimus action types.
_TOOL_NAME_ACTION_MAP: dict[str, str] = {
    "bash": ActionType.SHELL_COMMAND,
    "shell": ActionType.SHELL_COMMAND,
    "terminal": ActionType.SHELL_COMMAND,
    "python_repl": ActionType.SHELL_COMMAND,
    "code_execution": ActionType.SHELL_COMMAND,
    "file_write": ActionType.FILE_WRITE,
    "file_read": ActionType.FILE_READ,
    "google_search": ActionType.WEB_REQUEST,
    "web_search": ActionType.WEB_REQUEST,
    "requests_get": ActionType.WEB_REQUEST,
    "requests_post": ActionType.WEB_REQUEST,
}


def _infer_action_type(tool_name: str, tool_args: dict[str, Any]) -> str:
    """Infer a Vectimus action type from an ADK tool name and args."""
    lower = tool_name.lower()

    # Direct match
    if lower in _TOOL_NAME_ACTION_MAP:
        base = _TOOL_NAME_ACTION_MAP[lower]
    elif "__" in tool_name:
        # MCP tool pattern: server__tool
        base = ActionType.MCP_TOOL
    elif "shell" in lower or "bash" in lower or "terminal" in lower:
        base = ActionType.SHELL_COMMAND
    elif "file" in lower and ("write" in lower or "edit" in lower or "create" in lower):
        base = ActionType.FILE_WRITE
    elif "file" in lower and "read" in lower:
        base = ActionType.FILE_READ
    elif "http" in lower or "request" in lower or "fetch" in lower or "web" in lower:
        base = ActionType.WEB_REQUEST
    else:
        # Default to shell_command (broadest policy coverage)
        base = ActionType.SHELL_COMMAND

    # Refine shell commands using the same heuristics as the normaliser.
    shell_file_path: str | None = None
    if base == ActionType.SHELL_COMMAND:
        command = tool_args.get("command") or tool_args.get("cmd") or ""
        if command:
            from vectimus.engine.normaliser import _refine_shell_action

            base, shell_file_path = _refine_shell_action(command)

    return base, shell_file_path


def _extract_mcp_parts(tool_name: str) -> tuple[str | None, str | None]:
    """Extract MCP server and tool name from a double-underscore name."""
    if "__" in tool_name:
        parts = tool_name.split("__", 1)
        return parts[0], parts[1]
    return None, None


def _build_event(
    tool_name: str,
    tool_args: dict[str, Any],
    *,
    principal: str = "adk-agent",
    cwd: str | None = None,
) -> VectimusEvent:
    """Build a VectimusEvent from a Google ADK tool call."""
    action_type, shell_file_path = _infer_action_type(tool_name, tool_args)
    mcp_server, mcp_tool = _extract_mcp_parts(tool_name)

    # Extract common fields from args
    command = (
        tool_args.get("command")
        or tool_args.get("cmd")
        or tool_args.get("query")
        or tool_args.get("input")
    )
    file_path = (
        tool_args.get("file_path")
        or tool_args.get("path")
        or tool_args.get("filename")
        or shell_file_path
    )
    url = tool_args.get("url") or tool_args.get("uri")
    file_content = tool_args.get("content") or tool_args.get("text")

    # For generic tools, build a synthetic command from the tool name and args
    # so Cedar policies can match against it.
    if command is None and action_type == ActionType.SHELL_COMMAND:
        command = f"{tool_name} {json.dumps(tool_args, default=str)}"

    return VectimusEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC).isoformat(),
        event_type=EventType.PRE_ACTION,
        source=SourceInfo(tool="adk"),
        identity=IdentityInfo(principal=principal, identity_type="agent"),
        action=ActionInfo(
            action_type=action_type,
            raw_tool_name=tool_name,
            command=command,
            file_path=file_path,
            url=url,
            file_content=file_content,
            mcp_server=mcp_server,
            mcp_tool=mcp_tool,
            raw_input=tool_args,
        ),
        context=ContextInfo(cwd=cwd),
    )


def _format_denial(policy_ids: list[str], reason: str | None) -> dict[str, str]:
    """Format a denial as a dict that ADK treats as the tool result.

    Returning a dict from before_tool_callback skips tool execution and
    feeds this dict back to the agent as the tool's output.
    """
    if reason:
        return {"error": f"Blocked by Vectimus: {reason}"}
    return {"error": f"Blocked by Vectimus policy {', '.join(policy_ids)}."}


# ---------------------------------------------------------------------------
# VectimusADKPlugin — for Runner(plugins=[...])
# ---------------------------------------------------------------------------


class VectimusADKPlugin:
    """Google ADK plugin that evaluates tool calls against Cedar policies.

    This is the recommended way to add Vectimus governance to ADK agents.
    Register it on the Runner to apply policies globally across all agents.

    Usage::

        from vectimus.integrations.adk import VectimusADKPlugin

        plugin = VectimusADKPlugin(
            policy_dir="./policies",
            observe_mode=False,
        )
        runner = Runner(
            agent=my_agent,
            app_name="my-app",
            session_service=session_service,
            plugins=[plugin],
        )

    Parameters
    ----------
    policy_dir:
        Path to a directory of Cedar policy files.  Defaults to the built-in
        policies shipped with Vectimus.
    observe_mode:
        When True, denied actions are logged but not blocked (the tool call
        proceeds).  Useful for trialling Vectimus without enforcement.
    principal:
        Identity string for the agent.  Defaults to ``"adk-agent"``.
    cwd:
        Working directory context for policy evaluation.
    log_dir:
        Directory for audit log JSONL files.  Defaults to ``~/.vectimus/logs``.
    """

    def __init__(
        self,
        policy_dir: str | None = None,
        observe_mode: bool = False,
        principal: str = "adk-agent",
        cwd: str | None = None,
        log_dir: str | None = None,
        loader: PolicyLoader | None = None,
    ) -> None:
        _check_adk_installed()
        self._engine = PolicyEngine(policy_dir=policy_dir, loader=loader, observe=observe_mode)
        self._observe = observe_mode
        self._principal = principal
        self._cwd = cwd
        self._log_dir = log_dir

    def before_tool_callback(
        self,
        callback_context: Any,
        tool_name: str,
        args: dict[str, Any],
    ) -> dict[str, str] | None:
        """Evaluate a tool call against Cedar policies before execution.

        Returns a dict to block the tool (the dict becomes the tool result
        the agent sees).  Returns None to allow the tool to execute.
        """
        tool_args = args if isinstance(args, dict) else {}

        event = _build_event(
            tool_name,
            tool_args,
            principal=self._principal,
            cwd=self._cwd,
        )

        decision = self._engine.evaluate(event)
        write_audit(event, decision, log_dir=self._log_dir)

        if decision.decision in (DecisionVerdict.DENY, DecisionVerdict.ESCALATE):
            return _format_denial(decision.matched_policy_ids, decision.reason)

        return None

    def after_tool_callback(
        self,
        callback_context: Any,
        tool_name: str,
        args: dict[str, Any],
        result: Any,
    ) -> None:
        """Log tool execution results to the audit trail.

        Always returns None (pass through) — results are not modified.
        """
        tool_args = args if isinstance(args, dict) else {}

        event = VectimusEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            event_type=EventType.POST_ACTION,
            source=SourceInfo(tool="adk"),
            identity=IdentityInfo(principal=self._principal, identity_type="agent"),
            action=ActionInfo(
                action_type=_infer_action_type(tool_name, tool_args)[0],
                raw_tool_name=tool_name,
                raw_input=tool_args,
            ),
            context=ContextInfo(cwd=self._cwd),
        )

        # Build a lightweight post-action decision for audit logging.
        from vectimus.engine.models import Decision

        post_decision = Decision(
            decision=DecisionVerdict.ALLOW,
            matched_policy_ids=[],
            reason="post-action audit",
        )
        write_audit(event, post_decision, log_dir=self._log_dir)

        return None


# ---------------------------------------------------------------------------
# Per-agent callback factory
# ---------------------------------------------------------------------------


def create_before_tool_callback(
    policy_dir: str | None = None,
    observe_mode: bool = False,
    principal: str = "adk-agent",
    cwd: str | None = None,
    log_dir: str | None = None,
    loader: PolicyLoader | None = None,
) -> Callable[..., dict[str, str] | None]:
    """Create a Vectimus before_tool_callback for a single ADK agent.

    Returns a callback function compatible with
    ``LlmAgent(before_tool_callback=...)``.

    Usage::

        from vectimus.integrations.adk import create_before_tool_callback

        callback = create_before_tool_callback(
            policy_dir="./policies",
            observe_mode=False,
        )
        agent = LlmAgent(
            name="MyAgent",
            model="gemini-2.0-flash",
            before_tool_callback=callback,
        )

    Parameters
    ----------
    policy_dir:
        Path to a directory of Cedar policy files.  Defaults to the built-in
        policies shipped with Vectimus.
    observe_mode:
        When True, denied actions are logged but not blocked.
    principal:
        Identity string for the agent.  Defaults to ``"adk-agent"``.
    cwd:
        Working directory context for policy evaluation.
    log_dir:
        Directory for audit log JSONL files.
    """
    _check_adk_installed()
    engine = PolicyEngine(policy_dir=policy_dir, loader=loader, observe=observe_mode)

    def before_tool_callback(
        callback_context: Any,
        tool_name: str,
        args: dict[str, Any],
    ) -> dict[str, str] | None:
        """Evaluate a tool call against Cedar policies before execution."""
        tool_args = args if isinstance(args, dict) else {}

        event = _build_event(
            tool_name,
            tool_args,
            principal=principal,
            cwd=cwd,
        )

        decision = engine.evaluate(event)
        write_audit(event, decision, log_dir=log_dir)

        if decision.decision in (DecisionVerdict.DENY, DecisionVerdict.ESCALATE):
            return _format_denial(decision.matched_policy_ids, decision.reason)

        return None

    return before_tool_callback
