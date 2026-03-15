"""Tests for Cedar policy protecting .vectimus/ directory (Phase 5)."""

from __future__ import annotations

from vectimus.engine.models import ActionType, DecisionVerdict


class TestVectimusDirectoryProtection:
    """Policy vectimus-fileint-005 blocks writes to .vectimus/ directory."""

    def test_write_vectimus_config_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.vectimus/config.toml",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert "vectimus-fileint-005" in decision.matched_policy_ids

    def test_write_vectimus_nested_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.vectimus/policies/custom.cedar",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert "vectimus-fileint-005" in decision.matched_policy_ids

    def test_read_vectimus_config_allowed(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_READ,
            tool_name="Read",
            file_path="/home/user/project/.vectimus/config.toml",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    def test_write_outside_vectimus_allowed(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/src/main.py",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    def test_write_vectimus_relative_path_denied(self, engine, make_event) -> None:
        """Relative paths like .vectimus/config.toml are also caught."""
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path=".vectimus/config.toml",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert "vectimus-fileint-005" in decision.matched_policy_ids
