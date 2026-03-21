"""Pydantic v2 data models for Vectimus events, decisions and audit records.

Every agent action flowing through Vectimus is represented as a VectimusEvent.
The evaluator produces a Decision, and the pair is persisted as an AuditRecord.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class ActionType(StrEnum):
    """Normalised action types that span all supported tools."""

    SHELL_COMMAND = "shell_command"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    WEB_REQUEST = "web_request"
    MCP_TOOL = "mcp_tool"
    PACKAGE_OPERATION = "package_operation"
    GIT_OPERATION = "git_operation"
    INFRASTRUCTURE = "infrastructure"
    AGENT_SPAWN = "agent_spawn"
    AGENT_MESSAGE = "agent_message"


class EventType(StrEnum):
    """Whether the event fires before or after the action."""

    PRE_ACTION = "pre_action"
    POST_ACTION = "post_action"


class DecisionVerdict(StrEnum):
    """Possible governance verdicts."""

    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


class SourceInfo(BaseModel):
    """Where the event originated."""

    tool: str  # "claude-code", "cursor", "copilot", "claude-agent-sdk", "langgraph", "api"
    version: str | None = None
    session_id: str | None = None


class IdentityInfo(BaseModel):
    """Who or what triggered the action."""

    principal: str  # email, service principal name, agent ID
    persona: str = "default"
    groups: list[str] = Field(default_factory=list)
    identity_type: Literal["human", "agent"] = "human"


class ActionInfo(BaseModel):
    """The normalised action being attempted."""

    action_type: str  # one of ActionType values
    raw_tool_name: str  # original tool name from the source tool
    command: str | None = None
    file_path: str | None = None
    url: str | None = None
    mcp_server: str | None = None
    mcp_tool: str | None = None
    package_name: str | None = None
    file_content: str | None = None  # content being written (for double-eval)
    script_content: str | None = None  # resolved script content (for double-eval)
    raw_input: dict = Field(default_factory=dict)


class ContextInfo(BaseModel):
    """Environmental context."""

    repository: str | None = None
    branch: str | None = None
    hostname: str | None = None
    cwd: str | None = None


class VectimusEvent(BaseModel):
    """The normalised event that Cedar policies evaluate against.

    Every tool-specific payload is converted into this canonical form
    before policy evaluation.
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    event_type: str = EventType.PRE_ACTION
    source: SourceInfo
    identity: IdentityInfo
    action: ActionInfo
    context: ContextInfo = Field(default_factory=ContextInfo)


class Decision(BaseModel):
    """The governance decision returned by the evaluator."""

    decision: str = DecisionVerdict.DENY  # fail closed
    reason: str | None = None
    suggested_alternative: str | None = None  # what the agent should try instead
    matched_policy_ids: list[str] = Field(default_factory=list)
    evaluation_time_ms: float = 0.0


class AuditRecord(BaseModel):
    """Complete audit trail entry pairing an event with its decision."""

    event: VectimusEvent
    decision: Decision
    recorded_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    receipt_id: str | None = None
