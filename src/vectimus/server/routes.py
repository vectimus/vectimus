"""HTTP route handlers for the Vectimus governance server.

Endpoints:
- POST /evaluate  -- evaluate a tool action against policies
- GET  /policies  -- list loaded policies
- GET  /health    -- server health check (detailed)
- GET  /healthz   -- k8s liveness probe (lightweight)
- GET  /ready     -- k8s readiness probe (policies loaded?)
- GET  /events    -- SSE stream of evaluation events
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from typing import Any

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

import vectimus
from vectimus.core.evaluator import PolicyEngine
from vectimus.core.models import AuditRecord, Decision, DecisionVerdict, VectimusEvent
from vectimus.core.normaliser import normalise
from vectimus.core.session_store import SessionStore

logger = structlog.get_logger(__name__)

router = APIRouter()

# In-memory ring buffer for the SSE /events stream.
# Events are tagged with a monotonic counter to handle buffer wraparound.
_EVENT_BUFFER: deque[dict[str, Any]] = deque(maxlen=1000)
_event_counter: int = 0


@router.post("/evaluate")
async def evaluate(request: Request) -> dict[str, Any]:
    """Evaluate an incoming tool action against Cedar policies.

    Accepts a raw tool event payload.  The ``X-Vectimus-Source`` header
    identifies which tool sent the request (defaults to ``claude-code``).
    """
    global _event_counter

    try:
        body: dict[str, Any] = await request.json()
    except Exception:
        return _build_response(
            Decision(
                decision=DecisionVerdict.DENY,
                reason="Invalid request body (fail closed)",
            ),
        )

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
    # Run in executor to avoid blocking the event loop with threading.Lock.
    session_store: SessionStore = request.app.state.session_store
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _enrich_session, event, session_store)

    # Run the blocking Cedar evaluation in a thread to avoid blocking
    # the async event loop under concurrent load.
    decision = await loop.run_in_executor(None, engine.evaluate, event)

    # Build audit record and buffer for SSE
    record = AuditRecord(event=event, decision=decision)
    _EVENT_BUFFER.append(record.model_dump())
    _event_counter += 1

    # Best-effort audit export using the cached exporter
    try:
        exporter = request.app.state.exporter
        exporter.export(record)
    except Exception:
        pass  # Don't let export errors block the response.

    # Include API key identity in log if available
    log_extra: dict[str, Any] = {
        "decision": decision.decision,
        "action": event.action.action_type,
        "tool": event.action.raw_tool_name,
        "source": source,
        "time_ms": decision.evaluation_time_ms,
    }
    api_key_name = getattr(request.state, "api_key_name", None)
    if api_key_name:
        log_extra["client"] = api_key_name
    logger.info("evaluation_complete", **log_extra)

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
    uptime_seconds = round(time.monotonic() - request.app.state.start_time, 1)
    return {
        "status": "healthy",
        "version": vectimus.__version__,
        "policy_count": len(engine.list_policies()),
        "uptime_seconds": uptime_seconds,
    }


@router.get("/healthz")
async def healthz() -> JSONResponse:
    """Lightweight liveness probe for k8s. Returns 200 if the process is alive."""
    return JSONResponse({"status": "ok"})


@router.get("/ready")
async def ready(request: Request) -> JSONResponse:
    """Readiness probe for k8s. Returns 200 only when policies are loaded."""
    engine: PolicyEngine = request.app.state.engine
    policy_count = len(engine.list_policies())
    if policy_count > 0:
        return JSONResponse({"status": "ready", "policy_count": policy_count})
    return JSONResponse(
        {"status": "not_ready", "reason": "no policies loaded"},
        status_code=503,
    )


@router.get("/events")
async def events_stream() -> StreamingResponse:
    """Server-Sent Events stream of real-time evaluation events."""

    async def generate():  # type: ignore[return]
        last_counter = _event_counter
        while True:
            current_counter = _event_counter
            if current_counter > last_counter:
                # Read the most recent (current_counter - last_counter) items.
                new_count = min(current_counter - last_counter, len(_EVENT_BUFFER))
                items = list(_EVENT_BUFFER)[-new_count:]
                for item in items:
                    yield f"data: {json.dumps(item, default=str)}\n\n"
                last_counter = current_counter
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
        if decision.decision == DecisionVerdict.DENY:
            permission = "deny"
        elif decision.decision == DecisionVerdict.ESCALATE:
            permission = "deny"  # fail closed until escalation is resolved
        else:
            permission = "allow"
        response["hookSpecificOutput"] = {
            "hookEventName": hook_event,
            "permissionDecision": permission,
            "permissionDecisionReason": decision.reason or "",
        }

    return response
