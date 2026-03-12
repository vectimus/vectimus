"""LangChain / LangGraph middleware integration for Vectimus.

Provides two mechanisms for governing tool calls in LangChain agents
and LangGraph workflows:

1. ``VectimusMiddleware`` — for use with ``create_agent(middleware=[...])``.
2. ``create_interceptor`` — factory that returns an MCP tool call interceptor
   for use with ``MultiServerMCPClient(tool_interceptors=[...])``.

Both share the same evaluation pipeline: normalise the tool call to a
VectimusEvent, evaluate against Cedar policies, log to the audit trail,
and allow or block accordingly.

Usage::

    from vectimus.integrations.langgraph import VectimusMiddleware

    middleware = VectimusMiddleware(
        policy_dir="./policies",
        observe_mode=False,
    )
    agent = create_agent(model=model, tools=tools, middleware=[middleware])

For MCP interceptors::

    from vectimus.integrations.langgraph import create_interceptor

    interceptor = create_interceptor(policy_dir="./policies")
    client = MultiServerMCPClient({...}, tool_interceptors=[interceptor])

Dependencies (``langchain``, ``langgraph``) are guarded behind lazy checks
so that ``import vectimus`` works without them installed.  An
``ImportError`` with install instructions is raised only when the user
tries to instantiate the middleware or call the interceptor factory.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from vectimus.engine.audit import write_audit
from vectimus.engine.evaluator import PolicyEngine
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
    "LangChain is required for the Vectimus LangGraph integration. "
    "Install it with: pip install vectimus[langgraph]"
)


def _check_langchain_installed() -> None:
    """Raise ImportError with a helpful message if langchain is missing."""
    try:
        import langchain  # noqa: F401
    except ImportError:
        raise ImportError(_INSTALL_MSG) from None


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Map well-known LangChain tool names to Vectimus action types.
_TOOL_NAME_ACTION_MAP: dict[str, str] = {
    "bash": ActionType.SHELL_COMMAND,
    "shell": ActionType.SHELL_COMMAND,
    "terminal": ActionType.SHELL_COMMAND,
    "python_repl": ActionType.SHELL_COMMAND,
    "file_write": ActionType.FILE_WRITE,
    "file_read": ActionType.FILE_READ,
    "web_search": ActionType.WEB_REQUEST,
    "requests_get": ActionType.WEB_REQUEST,
    "requests_post": ActionType.WEB_REQUEST,
}


def _infer_action_type(tool_name: str, tool_args: dict[str, Any]) -> str:
    """Infer a Vectimus action type from a LangChain tool name and args."""
    lower = tool_name.lower()

    # Direct match
    if lower in _TOOL_NAME_ACTION_MAP:
        base = _TOOL_NAME_ACTION_MAP[lower]
    elif "shell" in lower or "bash" in lower or "terminal" in lower:
        base = ActionType.SHELL_COMMAND
    elif "file" in lower and ("write" in lower or "edit" in lower or "create" in lower):
        base = ActionType.FILE_WRITE
    elif "file" in lower and "read" in lower:
        base = ActionType.FILE_READ
    elif "http" in lower or "request" in lower or "fetch" in lower or "web" in lower:
        base = ActionType.WEB_REQUEST
    elif "__" in tool_name:
        # MCP tool pattern: server__tool
        base = ActionType.MCP_TOOL
    else:
        # Default to shell_command (broadest policy coverage)
        base = ActionType.SHELL_COMMAND

    # Refine shell commands using the same heuristics as the normaliser.
    if base == ActionType.SHELL_COMMAND:
        command = tool_args.get("command") or tool_args.get("cmd") or ""
        if command:
            from vectimus.engine.normaliser import _refine_shell_action

            base = _refine_shell_action(command)

    return base


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
    principal: str = "langgraph-agent",
    cwd: str | None = None,
) -> VectimusEvent:
    """Build a VectimusEvent from a LangChain/LangGraph tool call."""
    action_type = _infer_action_type(tool_name, tool_args)
    mcp_server, mcp_tool = _extract_mcp_parts(tool_name)

    # Extract common fields from args
    command = (
        tool_args.get("command")
        or tool_args.get("cmd")
        or tool_args.get("query")
        or tool_args.get("input")
    )
    file_path = tool_args.get("file_path") or tool_args.get("path") or tool_args.get("filename")
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
        source=SourceInfo(tool="langgraph"),
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


def _format_denial(policy_ids: list[str], reason: str | None) -> str:
    """Format a human-readable denial message for the agent."""
    if reason:
        return f"Blocked by Vectimus: {reason}"
    return f"Blocked by Vectimus policy {', '.join(policy_ids)}."


# ---------------------------------------------------------------------------
# VectimusMiddleware — for create_agent(middleware=[...])
# ---------------------------------------------------------------------------


class VectimusMiddleware:
    """LangChain agent middleware that evaluates tool calls against Cedar policies.

    Usage::

        from vectimus.integrations.langgraph import VectimusMiddleware

        middleware = VectimusMiddleware(
            policy_dir="./policies",
            observe_mode=False,
        )
        agent = create_agent(
            model="openai:gpt-4.1",
            tools=my_tools,
            middleware=[middleware],
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
        Identity string for the agent.  Defaults to ``"langgraph-agent"``.
    cwd:
        Working directory context for policy evaluation.
    log_dir:
        Directory for audit log JSONL files.  Defaults to ``~/.vectimus/logs``.
    """

    def __init__(
        self,
        policy_dir: str | None = None,
        observe_mode: bool = False,
        principal: str = "langgraph-agent",
        cwd: str | None = None,
        log_dir: str | None = None,
    ) -> None:
        _check_langchain_installed()
        self._engine = PolicyEngine(policy_dir=policy_dir, observe=observe_mode)
        self._observe = observe_mode
        self._principal = principal
        self._cwd = cwd
        self._log_dir = log_dir

    async def __call__(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        call_next: Callable[..., Any],
        **kwargs: Any,
    ) -> Any:
        """Evaluate the tool call and either allow or block it."""
        event = _build_event(
            tool_name,
            tool_args,
            principal=self._principal,
            cwd=self._cwd,
        )

        decision = self._engine.evaluate(event)
        write_audit(event, decision, log_dir=self._log_dir)

        if decision.decision in (DecisionVerdict.DENY, DecisionVerdict.ESCALATE):
            # In observe mode the engine already downgrades DENY/ESCALATE → ALLOW,
            # so reaching here means enforcement is active.
            return _format_denial(decision.matched_policy_ids, decision.reason)

        return await call_next(tool_name, tool_args, **kwargs)


# ---------------------------------------------------------------------------
# MCP interceptor — for MultiServerMCPClient(tool_interceptors=[...])
# ---------------------------------------------------------------------------


def create_interceptor(
    policy_dir: str | None = None,
    observe_mode: bool = False,
    principal: str = "langgraph-agent",
    cwd: str | None = None,
    log_dir: str | None = None,
) -> Callable[..., Any]:
    """Create a Vectimus MCP tool call interceptor.

    Returns an async function compatible with LangChain's
    ``MultiServerMCPClient(tool_interceptors=[...])`` interface.

    Usage::

        from vectimus.integrations.langgraph import create_interceptor

        interceptor = create_interceptor(
            policy_dir="./policies",
            observe_mode=False,
        )
        client = MultiServerMCPClient({...}, tool_interceptors=[interceptor])

    Parameters
    ----------
    policy_dir:
        Path to a directory of Cedar policy files.  Defaults to the built-in
        policies shipped with Vectimus.
    observe_mode:
        When True, denied actions are logged but not blocked.
    principal:
        Identity string for the agent.  Defaults to ``"langgraph-agent"``.
    cwd:
        Working directory context for policy evaluation.
    log_dir:
        Directory for audit log JSONL files.
    """
    _check_langchain_installed()
    engine = PolicyEngine(policy_dir=policy_dir, observe=observe_mode)

    async def interceptor(request: Any, handler: Callable[..., Any]) -> Any:
        """Evaluate an MCP tool call request against Cedar policies."""
        # Extract tool name and args from the request object.
        # MCPToolCallRequest has .name and .args attributes.
        tool_name = getattr(request, "name", str(request))
        tool_args = getattr(request, "args", {}) or {}
        if isinstance(tool_args, str):
            try:
                tool_args = json.loads(tool_args)
            except (json.JSONDecodeError, TypeError):
                tool_args = {"input": tool_args}

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

        return await handler(request)

    return interceptor


# Convenience alias for simple usage without the factory.
vectimus_interceptor: Callable[..., Any] | None = None
"""Pre-built interceptor with default settings.

For customisation use :func:`create_interceptor` instead.  This is set
to ``None`` and must be created by the user because it requires
LangChain to be installed::

    from vectimus.integrations.langgraph import create_interceptor
    interceptor = create_interceptor()
"""
