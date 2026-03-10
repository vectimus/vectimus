#!/usr/bin/env python3
"""Vectimus command hook for GitHub Copilot / VS Code agent hooks.

Handles the VS Code hook JSON schema and returns decisions via exit code
and stdout JSON.  Works on both Windows (PowerShell) and Unix (bash).
"""

from __future__ import annotations

import json
import os
import sys

from vectimus.core.evaluator import PolicyEngine
from vectimus.core.loader import PolicyLoader
from vectimus.core.models import DecisionVerdict
from vectimus.core.normaliser import normalise
from vectimus.shims import write_audit


def _log_stderr(msg: str) -> None:
    """Write diagnostic message to stderr (not visible to agent)."""
    print(f"vectimus: {msg}", file=sys.stderr)


def _post_to_server(payload: dict, server_url: str) -> dict | None:
    """POST to the Vectimus server.  Returns response dict or None."""
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
            "X-Vectimus-Source": "copilot",
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


def _debug_enabled() -> bool:
    return os.environ.get("VECTIMUS_DEBUG", "").lower() in ("1", "true", "yes")


def run() -> None:
    """Entry point for the Copilot / VS Code command hook."""
    debug = _debug_enabled()
    raw = sys.stdin.read()
    if debug:
        _log_stderr(f"stdin payload: {raw[:2000]}")
    if not raw.strip():
        if debug:
            _log_stderr("empty stdin, allowing")
        sys.exit(0)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        _log_stderr("invalid JSON payload (fail closed)")
        print(
            json.dumps(
                {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "Vectimus: invalid JSON payload (fail closed)",
                }
            )
        )
        sys.exit(2)

    # Try server
    server_url = os.environ.get("VECTIMUS_SERVER_URL")
    if server_url:
        result = _post_to_server(payload, server_url)
        if result is not None:
            if result.get("decision") == DecisionVerdict.DENY:
                hook_output = result.get(
                    "hookSpecificOutput",
                    {
                        "hookEventName": payload.get("hookEventName", "PreToolUse"),
                        "permissionDecision": "deny",
                        "permissionDecisionReason": result.get("reason", "Denied by Vectimus"),
                    },
                )
                print(json.dumps(hook_output))
                sys.exit(2)
            sys.exit(0)

    # Determine project path for per-project overrides.
    from pathlib import Path

    project_path_str = payload.get("cwd") or os.getcwd()
    project_path = Path(project_path_str).resolve()

    # Local evaluation
    if debug:
        tool = payload.get("tool_name") or payload.get("toolName") or "unknown"
        cmd = (payload.get("tool_input") or {}).get("command") or "(from toolArgs)"
        _log_stderr(f"tool={tool} command={cmd}")
    try:
        event = normalise(payload, "copilot")
    except Exception as exc:
        _log_stderr(f"Normalisation error: {exc}")
        output = {
            "hookEventName": payload.get("hookEventName", "PreToolUse"),
            "permissionDecision": "deny",
            "permissionDecisionReason": "Normalisation error (fail closed)",
        }
        print(json.dumps(output))
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

    if decision.decision == DecisionVerdict.DENY:
        output = {
            "hookEventName": payload.get("hookEventName", "PreToolUse"),
            "permissionDecision": "deny",
            "permissionDecisionReason": decision.reason or "Denied by Vectimus",
        }
        print(json.dumps(output))
        for pid in decision.matched_policy_ids:
            _log_stderr(f"To disable for this project: vectimus rule disable {pid}")
            _log_stderr(f"To disable everywhere: vectimus rule disable {pid} --global")
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    run()
