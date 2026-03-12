"""Tests for Pydantic models."""

from __future__ import annotations

from vectimus.engine.models import (
    ActionInfo,
    ActionType,
    AuditRecord,
    Decision,
    DecisionVerdict,
    IdentityInfo,
    SourceInfo,
    VectimusEvent,
)


def test_event_defaults() -> None:
    """VectimusEvent should populate event_id and timestamp automatically."""
    event = VectimusEvent(
        source=SourceInfo(tool="claude-code"),
        identity=IdentityInfo(principal="test@example.com"),
        action=ActionInfo(
            action_type=ActionType.SHELL_COMMAND,
            raw_tool_name="Bash",
        ),
    )
    assert event.event_id
    assert event.timestamp
    assert event.event_type == "pre_action"


def test_decision_defaults_to_deny() -> None:
    """Decision should default to deny (fail closed)."""
    d = Decision()
    assert d.decision == DecisionVerdict.DENY
    assert d.suggested_alternative is None


def test_decision_with_suggested_alternative() -> None:
    """Decision should accept and serialise suggested_alternative."""
    d = Decision(
        decision=DecisionVerdict.DENY,
        reason="Blocked by policy",
        suggested_alternative="Use a safer approach instead.",
    )
    assert d.suggested_alternative == "Use a safer approach instead."
    data = d.model_dump()
    assert data["suggested_alternative"] == "Use a safer approach instead."


def test_audit_record_round_trip() -> None:
    """AuditRecord should serialise and deserialise cleanly."""
    event = VectimusEvent(
        source=SourceInfo(tool="claude-code"),
        identity=IdentityInfo(principal="test@example.com"),
        action=ActionInfo(
            action_type=ActionType.FILE_READ,
            raw_tool_name="Read",
            file_path="src/main.py",
        ),
    )
    decision = Decision(decision=DecisionVerdict.ALLOW)
    record = AuditRecord(event=event, decision=decision)
    data = record.model_dump()
    restored = AuditRecord.model_validate(data)
    assert restored.decision.decision == DecisionVerdict.ALLOW
    assert restored.event.action.file_path == "src/main.py"


def test_action_types_are_strings() -> None:
    """ActionType enum members should be plain strings."""
    assert ActionType.SHELL_COMMAND == "shell_command"
    assert ActionType.INFRASTRUCTURE == "infrastructure"
