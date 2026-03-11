"""``vectimus hook`` -- unified hook entry point for all AI coding tools.

Reads tool call JSON from stdin, evaluates against Cedar policies,
returns a tool-specific deny payload via stdout.

Exit codes:
  0 = allow (no output)
  2 = deny  (JSON on stdout)

Supports VECTIMUS_SERVER_URL for server-mode evaluation with local fallback,
and VECTIMUS_DEBUG for diagnostic logging to stderr.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from vectimus.core.audit import write_audit
from vectimus.core.evaluator import PolicyEngine
from vectimus.core.loader import PolicyLoader
from vectimus.core.models import DecisionVerdict
from vectimus.core.normaliser import normalise

VALID_SOURCES = ("claude-code", "cursor", "copilot")


def _log_stderr(msg: str) -> None:
    """Write diagnostic message to stderr (not visible to agent)."""
    print(f"vectimus: {msg}", file=sys.stderr)


def _debug_enabled() -> bool:
    return os.environ.get("VECTIMUS_DEBUG", "").lower() in ("1", "true", "yes")


def _log_stderr_overrides(matched_policy_ids: list[str]) -> None:
    """Log rule disable hints to stderr (visible to human, not the agent)."""
    for pid in matched_policy_ids:
        _log_stderr(f"To disable for this project: vectimus rule disable {pid}")
        _log_stderr(f"To disable everywhere: vectimus rule disable {pid} --global")


def _post_to_server(payload: dict, server_url: str, source: str) -> dict | None:
    """POST to the Vectimus server. Returns response dict or None."""
    try:
        import urllib.request

        try:
            timeout = max(int(os.environ.get("VECTIMUS_TIMEOUT", "5")), 1)
        except (TypeError, ValueError):
            timeout = 5
        url = server_url.rstrip("/") + "/evaluate"
        data = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "X-Vectimus-Source": source,
        }
        api_key = os.environ.get("VECTIMUS_API_KEY")
        if api_key:
            headers["X-Vectimus-API-Key"] = api_key
        req = urllib.request.Request(
            url,
            data=data,
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        _log_stderr(f"Server unreachable ({server_url}), falling back to local evaluation")
        return None


def _deny_output(source: str, payload: dict, reason: str) -> dict:
    """Build the tool-specific deny JSON output."""
    if source == "cursor":
        return {
            "permission": "deny",
            "user_message": reason,
            "agent_message": reason,
        }
    # claude-code and copilot use the same format
    event_key = "hook_event_name" if source == "claude-code" else "hookEventName"
    return {
        "hookEventName": payload.get(event_key, "PreToolUse"),
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }


def _escalate_output(source: str, payload: dict, reason: str) -> dict:
    """Build the tool-specific escalate output.

    Local hooks cannot reliably prompt the user for approval:
    - Claude Code ignores "ask" when the tool is in the allow list.
    - Cursor does not support "ask" on preToolUse hooks.

    So escalate falls back to deny with a descriptive message on all
    local sources.  Server mode can implement real escalation workflows
    (e.g. PagerDuty, Slack approval) before returning allow/deny.
    """
    escalate_reason = f"[escalate] {reason}. Run this command manually if you approve."
    agent_reason = (
        f"[escalate] {reason}. "
        "This requires human approval -- the user must run it outside the agent."
    )
    if source == "cursor":
        return {
            "permission": "deny",
            "user_message": escalate_reason,
            "agent_message": agent_reason,
        }
    event_key = "hook_event_name" if source == "claude-code" else "hookEventName"
    return {
        "hookEventName": payload.get(event_key, "PreToolUse"),
        "permissionDecision": "deny",
        "permissionDecisionReason": agent_reason,
    }


def _project_path_from_payload(source: str, payload: dict) -> Path:
    """Extract project path from the tool-specific payload."""
    if source == "cursor":
        workspace_roots: list[str] = payload.get("workspace_roots", [])
        raw = workspace_roots[0] if workspace_roots else payload.get("cwd") or os.getcwd()
    else:
        raw = payload.get("cwd") or os.getcwd()
    return Path(raw).resolve()


@click.command("hook")
@click.option(
    "--source",
    required=True,
    type=click.Choice(VALID_SOURCES, case_sensitive=False),
    help="Which AI tool is calling this hook.",
)
def hook_cmd(source: str) -> None:
    """Evaluate an AI tool action against Cedar policies.

    Reads JSON from stdin, evaluates against loaded policies and returns
    allow (exit 0) or deny (exit 2 with JSON on stdout).

    \b
      echo '{"tool_name":"Bash",...}' | vectimus hook --source claude-code
      echo '{"command":"rm -rf /"}' | vectimus hook --source cursor
    """
    debug = _debug_enabled()
    raw = sys.stdin.read()

    if debug:
        _log_stderr(f"source={source} stdin payload: {raw[:2000]}")

    if not raw.strip():
        if debug:
            _log_stderr("empty stdin, allowing")
        sys.exit(0)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        _log_stderr("invalid JSON payload (fail closed)")
        reason = "Vectimus: invalid JSON payload (fail closed)"
        print(json.dumps(_deny_output(source, {}, reason)))
        sys.exit(2)

    project_path = _project_path_from_payload(source, payload)

    # Try server first (env var overrides config file)
    from vectimus.core.config import VectimusConfig

    config = VectimusConfig()
    server_url = config.get_server_url()
    if server_url:
        result = _post_to_server(payload, server_url, source)
        if result is not None:
            decision_val = result.get("decision", "deny")
            if decision_val in (DecisionVerdict.DENY, DecisionVerdict.ESCALATE):
                hook_output = result.get("hookSpecificOutput")
                if hook_output is None or source != "claude-code":
                    reason = result.get("reason", "Denied by Vectimus")
                    if decision_val == DecisionVerdict.ESCALATE:
                        hook_output = _escalate_output(source, payload, reason)
                    else:
                        hook_output = _deny_output(source, payload, reason)
                print(json.dumps(hook_output))
                sys.exit(2)
            sys.exit(0)

    # Local evaluation
    if debug:
        if source == "cursor":
            cmd = payload.get("command") or (payload.get("tool_input") or {}).get("command")
            _log_stderr(f"hook={payload.get('hook_event_name')} command={cmd}")
        elif source == "copilot":
            tool = payload.get("tool_name") or payload.get("toolName") or "unknown"
            cmd = (payload.get("tool_input") or {}).get("command") or "(from toolArgs)"
            _log_stderr(f"tool={tool} command={cmd}")

    try:
        event = normalise(payload, source)
    except Exception as exc:
        _log_stderr(f"Normalisation error: {exc}")
        reason = "Vectimus normalisation error (fail closed)"
        if source == "cursor":
            reason = "Normalisation error (fail closed)"
        print(json.dumps(_deny_output(source, payload, reason)))
        sys.exit(2)

    loader = PolicyLoader(project_path=project_path)

    # Apply identity from config (only override defaults, not payload values).
    if event.identity.persona == "default":
        event.identity.persona = loader.config.get_persona(project_path)
    if not event.identity.groups:
        event.identity.groups = loader.config.get_groups(project_path)
    if event.identity.identity_type == "human":
        configured_type = loader.config.get_identity_type(project_path)
        if configured_type != "human":
            event.identity.identity_type = configured_type

    observe = os.environ.get("VECTIMUS_OBSERVE", "").lower() in ("1", "true", "yes")
    if not observe:
        observe = loader.config.is_observe_mode()
    engine = PolicyEngine(loader=loader, observe=observe)
    decision = engine.evaluate(event)
    write_audit(
        event,
        decision,
        log_dir=loader.config.get_audit_log_dir(project_path),
        max_file_size_mb=loader.config.get_audit_max_file_size_mb(project_path),
    )

    if debug:
        _log_stderr(f"decision={decision.decision} policies={decision.matched_policy_ids}")

    if decision.decision == DecisionVerdict.ESCALATE:
        reason = decision.reason or "Flagged by Vectimus"
        print(json.dumps(_escalate_output(source, payload, reason)))
        _log_stderr_overrides(decision.matched_policy_ids)
        sys.exit(2)

    if decision.decision == DecisionVerdict.DENY:
        reason = decision.reason or "Denied by Vectimus"
        print(json.dumps(_deny_output(source, payload, reason)))
        _log_stderr_overrides(decision.matched_policy_ids)
        sys.exit(2)

    sys.exit(0)
