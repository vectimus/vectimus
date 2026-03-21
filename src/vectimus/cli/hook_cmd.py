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

from vectimus.engine.audit import write_audit
from vectimus.engine.evaluator import PolicyEngine
from vectimus.engine.loader import PolicyLoader
from vectimus.engine.models import Decision, DecisionVerdict, VectimusEvent
from vectimus.engine.normaliser import normalise

VALID_SOURCES = ("claude-code", "claude-agent-sdk", "cursor", "copilot", "gemini-cli")


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
    if source == "gemini-cli":
        return {
            "decision": "deny",
            "reason": reason,
        }
    # claude-code, claude-agent-sdk and copilot use the same format
    _claude_sources = ("claude-code", "claude-agent-sdk")
    event_key = "hook_event_name" if source in _claude_sources else "hookEventName"
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
    if source == "gemini-cli":
        return {
            "decision": "deny",
            "reason": agent_reason,
        }
    _claude_sources = ("claude-code", "claude-agent-sdk")
    event_key = "hook_event_name" if source in _claude_sources else "hookEventName"
    return {
        "hookEventName": payload.get(event_key, "PreToolUse"),
        "permissionDecision": "deny",
        "permissionDecisionReason": agent_reason,
    }


def _emit_deny(source: str, payload: dict, reason: str, *, escalate: bool = False) -> None:
    """Emit the deny output and exit.

    For Gemini CLI, deny JSON is written to stdout and exit 0 is used.
    Gemini CLI treats non-zero exit codes as hook failures (crashes), not
    deliberate denials.  The deny decision is communicated via the JSON
    ``decision`` field so the agent sees the reason.

    For all other sources, deny JSON is written to stdout with exit 2.
    """
    if escalate:
        output = _escalate_output(source, payload, reason)
    else:
        output = _deny_output(source, payload, reason)

    print(json.dumps(output))

    # Background policy update check (non-blocking, never breaks hook).
    # Only runs when auto_sync is explicitly enabled in config.
    try:
        from vectimus.engine.config import VectimusConfig as _SyncConfig
        from vectimus.engine.policy_sync import check_for_updates

        _cfg = _SyncConfig()
        if _cfg.is_auto_sync_enabled():
            check_for_updates(
                api_url=_cfg.get_sync_url(),
                check_interval_hours=_cfg.get_sync_interval_hours(),
            )
    except Exception:
        pass

    if source == "gemini-cli":
        sys.exit(0)
    sys.exit(2)


def _project_path_from_payload(source: str, payload: dict) -> Path:
    """Extract project path from the tool-specific payload."""
    if source == "cursor":
        workspace_roots: list[str] = payload.get("workspace_roots", [])
        raw = workspace_roots[0] if workspace_roots else payload.get("cwd") or os.getcwd()
    else:
        raw = payload.get("cwd") or os.getcwd()
    return Path(raw).resolve()


def _configure_structlog_stderr() -> None:
    """Send structlog output to stderr so stdout stays clean for JSON responses.

    Uses a wrapper that resolves sys.stderr at log time (not configure time)
    to avoid holding references to CliRunner mock streams in tests.
    """
    import logging

    import structlog

    class _StderrLoggerFactory:
        def __call__(self, *args, **kwargs):
            return structlog.PrintLogger(file=sys.stderr)

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=_StderrLoggerFactory(),
    )


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
    # Redirect structlog to stderr so stdout stays clean for JSON responses.
    # AI tools parse stdout for hook decisions; stray log lines break parsing.
    _configure_structlog_stderr()

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
        _emit_deny(source, {}, reason)

    project_path = _project_path_from_payload(source, payload)

    # Try server first (env var overrides config file)
    from vectimus.engine.config import VectimusConfig

    config = VectimusConfig()
    server_url = config.get_server_url()
    if server_url:
        result = _post_to_server(payload, server_url, source)
        if result is not None:
            decision_val = result.get("decision", "deny")
            if decision_val in (DecisionVerdict.DENY, DecisionVerdict.ESCALATE):
                hook_output = result.get("hookSpecificOutput")
                if hook_output is None or source not in ("claude-code", "claude-agent-sdk"):
                    reason = result.get("reason", "Denied by Vectimus")
                    if decision_val == DecisionVerdict.ESCALATE:
                        _emit_deny(source, payload, reason, escalate=True)
                    else:
                        _emit_deny(source, payload, reason)
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
        _emit_deny(source, payload, reason)

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

    # Generate receipt_id synchronously (cheap UUID4) so it can be included
    # in DENY messages.  Full receipt construction + signing happens async.
    receipt_id: str | None = None
    try:
        from vectimus.engine.receipts import generate_receipt_id

        if loader.config.is_receipts_enabled(project_path):
            receipt_id = generate_receipt_id()
    except Exception:
        pass

    write_audit(
        event,
        decision,
        log_dir=loader.config.get_audit_log_dir(project_path),
        max_file_size_mb=loader.config.get_audit_max_file_size_mb(project_path),
        receipt_id=receipt_id,
    )

    # Kick off async receipt generation (never blocks the hook response).
    if receipt_id:
        try:
            _generate_receipt_async(
                receipt_id=receipt_id,
                event=event,
                decision=decision,
                engine=engine,
                loader=loader,
                project_path=project_path,
                observe=observe,
            )
        except Exception as exc:
            _log_stderr(f"receipt generation failed: {exc}")

    if debug:
        _log_stderr(f"decision={decision.decision} policies={decision.matched_policy_ids}")

    if decision.decision == DecisionVerdict.ESCALATE:
        reason = decision.reason or "Flagged by Vectimus"
        if receipt_id:
            reason += f" (receipt: {receipt_id[:13]})"
        _log_stderr_overrides(decision.matched_policy_ids)
        _emit_deny(source, payload, reason, escalate=True)

    if decision.decision == DecisionVerdict.DENY:
        reason = decision.reason or "Denied by Vectimus"
        if receipt_id:
            reason += f" (receipt: {receipt_id[:13]})"
        _log_stderr_overrides(decision.matched_policy_ids)
        _emit_deny(source, payload, reason)

    # Background policy update check (non-blocking, never breaks hook).
    # Only runs when auto_sync is explicitly enabled in config.
    try:
        from vectimus.engine.config import VectimusConfig as _SyncConfig
        from vectimus.engine.policy_sync import check_for_updates

        _cfg = _SyncConfig()
        if _cfg.is_auto_sync_enabled():
            check_for_updates(
                api_url=_cfg.get_sync_url(),
                check_interval_hours=_cfg.get_sync_interval_hours(),
            )
    except Exception:
        pass

    sys.exit(0)


def _generate_receipt_async(
    *,
    receipt_id: str,
    event: VectimusEvent,
    decision: Decision,
    engine: PolicyEngine,
    loader: PolicyLoader,
    project_path: Path,
    observe: bool,
) -> None:
    """Build, sign and write a governance receipt in a background thread."""
    from vectimus.engine.keys import load_signing_key
    from vectimus.engine.receipts import (
        build_receipt,
        compute_context_hash,
        compute_policy_set_hash,
        sign_receipt,
        write_receipt_async,
    )

    # Determine outcome string
    if observe and decision.decision in (DecisionVerdict.DENY, DecisionVerdict.ESCALATE):
        outcome = "OBSERVE"
    elif decision.decision == DecisionVerdict.DENY:
        outcome = "DENY"
    elif decision.decision == DecisionVerdict.ESCALATE:
        outcome = "DENY"  # Escalate is deny for receipt purposes
    else:
        outcome = "ALLOW"

    # Build command summary
    command_summary = event.action.command or event.action.file_path or event.action.url or ""

    # Build action context for hashing
    action_context: dict = {
        "action_type": event.action.action_type,
        "raw_tool_name": event.action.raw_tool_name,
    }
    if event.action.command:
        action_context["command"] = event.action.command
    if event.action.file_path:
        action_context["file_path"] = event.action.file_path
    if event.action.url:
        action_context["url"] = event.action.url

    context_hash = compute_context_hash(action_context)

    # Policy set hash
    policy_set_hash = compute_policy_set_hash(engine._policies_text)

    # Get pack version
    pack_version = "0.0.0"
    try:
        packs = loader.discover_packs()
        if packs:
            pack_version = packs[0].version
    except Exception:
        pass

    # Matched policy ID
    matched_policy_id = decision.matched_policy_ids[0] if decision.matched_policy_ids else None

    # Principal info
    principal_type = "agent" if event.identity.identity_type == "agent" else "developer"
    principal_id = event.identity.principal

    receipt = build_receipt(
        receipt_id=receipt_id,
        principal_type=principal_type,
        principal_id=principal_id,
        tool=event.action.raw_tool_name,
        normalised_tool=event.action.action_type,
        command_summary=command_summary,
        context_hash=context_hash,
        policy_set_hash=policy_set_hash,
        policy_pack_version=pack_version,
        matched_policy_id=matched_policy_id,
        outcome=outcome,
        reason=decision.reason or "All checks passed",
        evaluation_time_ms=decision.evaluation_time_ms,
    )

    # Sign the receipt
    try:
        key_id, signing_key = load_signing_key()
        receipt = sign_receipt(receipt, signing_key, key_id)
    except FileNotFoundError:
        # No signing key available -- write unsigned receipt
        pass

    # Write async
    receipts_dir = project_path / ".vectimus" / "receipts"
    write_receipt_async(receipt, receipts_dir)
