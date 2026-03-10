#!/usr/bin/env python3
"""Vectimus command hook for Cursor.

Reads Cursor hook JSON from stdin, normalises and evaluates it.
Returns decision via exit code (0=allow, 2=deny) and stdout JSON.
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
            "X-Vectimus-Source": "cursor",
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
    """Entry point for the Cursor command hook."""
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
                    "permission": "deny",
                    "user_message": "Vectimus: invalid JSON payload (fail closed)",
                    "agent_message": "Vectimus: invalid JSON payload (fail closed)",
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
                reason = result.get("reason", "Denied by Vectimus")
                print(
                    json.dumps(
                        {
                            "permission": "deny",
                            "user_message": reason,
                            "agent_message": reason,
                        }
                    )
                )
                sys.exit(2)
            sys.exit(0)

    # Determine project path for per-project overrides.
    from pathlib import Path

    workspace_roots: list[str] = payload.get("workspace_roots", [])
    project_path_str = workspace_roots[0] if workspace_roots else payload.get("cwd") or os.getcwd()
    project_path = Path(project_path_str).resolve()

    # Local evaluation
    if debug:
        cmd = payload.get("command") or (payload.get("tool_input") or {}).get("command")
        _log_stderr(f"hook={payload.get('hook_event_name')} command={cmd}")
    try:
        event = normalise(payload, "cursor")
    except Exception as exc:
        _log_stderr(f"Normalisation error: {exc}")
        print(
            json.dumps(
                {
                    "permission": "deny",
                    "user_message": "Normalisation error (fail closed)",
                    "agent_message": "Normalisation error (fail closed)",
                }
            )
        )
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
        reason = decision.reason or "Denied by Vectimus"
        print(
            json.dumps(
                {
                    "permission": "deny",
                    "user_message": reason,
                    "agent_message": reason,
                }
            )
        )
        for pid in decision.matched_policy_ids:
            _log_stderr(f"To disable for this project: vectimus rule disable {pid}")
            _log_stderr(f"To disable everywhere: vectimus rule disable {pid} --global")
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    run()
