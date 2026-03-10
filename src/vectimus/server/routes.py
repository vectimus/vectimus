"""HTTP route handlers for the Vectimus governance server.

Endpoints:
- POST /evaluate -- evaluate a tool action against policies
- GET  /policies -- list loaded policies
- GET  /health   -- server health check
- GET  /events   -- SSE stream of evaluation events (stretch goal)
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from vectimus.core.evaluator import PolicyEngine
from vectimus.core.models import AuditRecord, Decision, DecisionVerdict, VectimusEvent
from vectimus.core.normaliser import normalise
from vectimus.core.session_store import SessionStore

logger = structlog.get_logger(__name__)

router = APIRouter()

# In-memory ring buffer for the SSE /events stream.
_EVENT_BUFFER: deque[dict[str, Any]] = deque(maxlen=1000)

# Track server start time for /health uptime.
_START_TIME = time.monotonic()


@router.post("/evaluate")
async def evaluate(request: Request) -> dict[str, Any]:
    """Evaluate an incoming tool action against Cedar policies.

    Accepts a raw tool event payload.  The ``X-Vectimus-Source`` header
    identifies which tool sent the request (defaults to ``claude-code``).
    """
    body: dict[str, Any] = await request.json()
    source = request.headers.get("X-Vectimus-Source", "claude-code")
    engine: PolicyEngine = request.app.state.engine

    try:
        event: VectimusEvent = normalise(body, source)
    except Exception as exc:
        logger.error("normalisation_error", error=str(exc))
        # Fail closed on normalisation errors.
        return _build_response(
            Decision(
                decision=DecisionVerdict.DENY,
                reason="Normalisation error (fail closed)",
            ),
            hook_event=body.get("hook_event_name") or body.get("hookEventName"),
        )

    # Session-level enrichment: detect temporal flood patterns.
    session_store: SessionStore = request.app.state.session_store
    _enrich_session(event, session_store)

    decision = engine.evaluate(event)

    # Build audit record and buffer for SSE
    record = AuditRecord(event=event, decision=decision)
    _EVENT_BUFFER.append(record.model_dump())

    # Try to export the audit record
    try:
        from vectimus.exporters.jsonl import JsonlExporter

        exporter = JsonlExporter()
        exporter.export(record)
    except Exception:
        pass  # Best-effort; don't let export errors block the response.

    logger.info(
        "evaluation_complete",
        decision=decision.decision,
        action=event.action.action_type,
        tool=event.action.raw_tool_name,
        time_ms=decision.evaluation_time_ms,
    )

    return _build_response(
        decision,
        hook_event=body.get("hook_event_name") or body.get("hookEventName"),
    )


@router.get("/policies")
async def list_policies(request: Request) -> dict[str, Any]:
    """Return metadata about all loaded policies."""
    engine: PolicyEngine = request.app.state.engine
    policies = engine.list_policies()
    return {"policies": policies, "count": len(policies)}


@router.get("/health")
async def health(request: Request) -> dict[str, Any]:
    """Return server health including policy count and uptime."""
    engine: PolicyEngine = request.app.state.engine
    policies = engine.list_policies()
    uptime_seconds = round(time.monotonic() - _START_TIME, 1)
    return {
        "status": "healthy",
        "version": "0.1.0",
        "policy_count": len(policies),
        "uptime_seconds": uptime_seconds,
    }


@router.get("/events")
async def events_stream() -> StreamingResponse:
    """Server-Sent Events stream of real-time evaluation events."""

    async def generate():  # type: ignore[return]
        last_idx = len(_EVENT_BUFFER)
        while True:
            current_len = len(_EVENT_BUFFER)
            if current_len > last_idx:
                import json

                for item in list(_EVENT_BUFFER)[last_idx:]:
                    yield f"data: {json.dumps(item, default=str)}\n\n"
                last_idx = current_len
            await asyncio.sleep(0.5)

    return StreamingResponse(generate(), media_type="text/event-stream")


def _enrich_session(event: VectimusEvent, store: SessionStore) -> None:
    """Append session-level flood flags to the event command string.

    Only tracks ``agent_spawn`` and ``agent_message`` action types.
    Skips enrichment when no session_id is present.
    """
    session_id = event.source.session_id
    if not session_id:
        return

    action_type = event.action.action_type
    if action_type not in ("agent_spawn", "agent_message"):
        return

    metrics = store.record(session_id, action_type)
    flags: list[str] = []

    if metrics.agent_spawns > store.spawn_limit:
        flags.append("SESSION_SPAWN_FLOOD")
    if metrics.agent_messages > store.message_limit:
        flags.append("SESSION_MESSAGE_FLOOD")

    if flags:
        suffix = " " + " ".join(flags)
        event.action.command = (event.action.command or "") + suffix


def _build_response(
    decision: Decision,
    hook_event: str | None = None,
) -> dict[str, Any]:
    """Build the response dict, including hook-specific output for Claude Code."""
    response: dict[str, Any] = decision.model_dump()

    # Claude Code HTTP hooks expect hookSpecificOutput.
    if hook_event:
        permission = "deny" if decision.decision == DecisionVerdict.DENY else "allow"
        response["hookSpecificOutput"] = {
            "hookEventName": hook_event,
            "permissionDecision": permission,
            "permissionDecisionReason": decision.reason or "",
        }

    return response
