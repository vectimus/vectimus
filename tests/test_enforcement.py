"""Tests for per-policy enforcement levels (@enforcement annotation + config overrides)."""

from __future__ import annotations

import textwrap

import pytest

from vectimus.core.evaluator import PolicyEngine, _parse_policy_metadata
from vectimus.core.loader import parse_rules_from_cedar
from vectimus.core.models import DecisionVerdict

# ---------------------------------------------------------------------------
# Annotation parsing
# ---------------------------------------------------------------------------


class TestEnforcementAnnotationParsing:
    """@enforcement annotation is correctly extracted from Cedar policy text."""

    def test_parse_enforcement_deny(self):
        cedar = textwrap.dedent("""\
            @id("test-001")
            @description("test rule")
            @enforcement("deny")
            forbid (principal, action, resource) when { true };
        """)
        metadata, _ = _parse_policy_metadata(cedar)
        assert metadata["test-001"].enforcement == "deny"

    def test_parse_enforcement_escalate(self):
        cedar = textwrap.dedent("""\
            @id("test-002")
            @description("test rule")
            @enforcement("escalate")
            forbid (principal, action, resource) when { true };
        """)
        metadata, _ = _parse_policy_metadata(cedar)
        assert metadata["test-002"].enforcement == "escalate"

    def test_parse_enforcement_observe(self):
        cedar = textwrap.dedent("""\
            @id("test-003")
            @description("test rule")
            @enforcement("observe")
            forbid (principal, action, resource) when { true };
        """)
        metadata, _ = _parse_policy_metadata(cedar)
        assert metadata["test-003"].enforcement == "observe"

    def test_parse_enforcement_default_is_deny(self):
        """Rules without @enforcement default to deny."""
        cedar = textwrap.dedent("""\
            @id("test-004")
            @description("no enforcement annotation")
            forbid (principal, action, resource) when { true };
        """)
        metadata, _ = _parse_policy_metadata(cedar)
        assert metadata["test-004"].enforcement == "deny"

    def test_parse_enforcement_invalid_value_defaults_to_deny(self):
        cedar = textwrap.dedent("""\
            @id("test-005")
            @description("invalid enforcement value")
            @enforcement("invalid")
            forbid (principal, action, resource) when { true };
        """)
        metadata, _ = _parse_policy_metadata(cedar)
        assert metadata["test-005"].enforcement == "deny"

    def test_loader_parse_rules_includes_enforcement(self):
        cedar = textwrap.dedent("""\
            @id("test-006")
            @description("escalate rule")
            @enforcement("escalate")
            forbid (principal, action, resource) when { true };
        """)
        rules = parse_rules_from_cedar(cedar, pack_name="test")
        assert len(rules) == 1
        assert rules[0].enforcement == "escalate"


# ---------------------------------------------------------------------------
# Evaluator enforcement behaviour
# ---------------------------------------------------------------------------


_ESCALATE_POLICY = textwrap.dedent("""\
    @id("esc-001")
    @description("Escalate on echo test")
    @enforcement("escalate")
    forbid (
        principal,
        action == Vectimus::Action::"shell_command",
        resource
    ) when {
        context.command like "*echo escalate-test*"
    };
""")

_OBSERVE_POLICY = textwrap.dedent("""\
    @id("obs-001")
    @description("Observe mode for echo observe-test")
    @enforcement("observe")
    forbid (
        principal,
        action == Vectimus::Action::"shell_command",
        resource
    ) when {
        context.command like "*echo observe-test*"
    };
""")

_DENY_POLICY = textwrap.dedent("""\
    @id("deny-001")
    @description("Deny echo deny-test")
    @enforcement("deny")
    forbid (
        principal,
        action == Vectimus::Action::"shell_command",
        resource
    ) when {
        context.command like "*echo deny-test*"
    };
""")


class TestEnforcementEvaluation:
    """PolicyEngine produces the correct verdict based on enforcement level."""

    @pytest.fixture()
    def escalate_engine(self, tmp_path):
        policy_file = tmp_path / "test.cedar"
        policy_file.write_text(_ESCALATE_POLICY)
        return PolicyEngine(policy_dir=str(tmp_path))

    @pytest.fixture()
    def observe_engine(self, tmp_path):
        policy_file = tmp_path / "test.cedar"
        policy_file.write_text(_OBSERVE_POLICY)
        return PolicyEngine(policy_dir=str(tmp_path))

    @pytest.fixture()
    def deny_engine(self, tmp_path):
        policy_file = tmp_path / "test.cedar"
        policy_file.write_text(_DENY_POLICY)
        return PolicyEngine(policy_dir=str(tmp_path))

    def test_escalate_produces_escalate_verdict(self, escalate_engine, make_event):
        event = make_event(command="echo escalate-test")
        decision = escalate_engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ESCALATE
        assert "esc-001" in decision.matched_policy_ids

    def test_escalate_non_matching_allows(self, escalate_engine, make_event):
        event = make_event(command="echo something-else")
        decision = escalate_engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    def test_observe_produces_allow_with_reason(self, observe_engine, make_event):
        event = make_event(command="echo observe-test")
        decision = observe_engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW
        assert "[observe]" in decision.reason
        assert "obs-001" in decision.matched_policy_ids

    def test_deny_produces_deny_verdict(self, deny_engine, make_event):
        event = make_event(command="echo deny-test")
        decision = deny_engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert "deny-001" in decision.matched_policy_ids

    def test_strictest_enforcement_wins(self, tmp_path, make_event):
        """When multiple policies match, the strictest enforcement wins."""
        combined = textwrap.dedent("""\
            @id("obs-multi")
            @description("Observe rule")
            @enforcement("observe")
            forbid (
                principal,
                action == Vectimus::Action::"shell_command",
                resource
            ) when {
                context.command like "*echo multi-test*"
            };

            @id("deny-multi")
            @description("Deny rule")
            @enforcement("deny")
            forbid (
                principal,
                action == Vectimus::Action::"shell_command",
                resource
            ) when {
                context.command like "*echo multi-test*"
            };
        """)
        policy_file = tmp_path / "test.cedar"
        policy_file.write_text(combined)
        engine = PolicyEngine(policy_dir=str(tmp_path))
        event = make_event(command="echo multi-test")
        decision = engine.evaluate(event)
        # deny is stricter than observe, so deny must win.
        assert decision.decision == DecisionVerdict.DENY

    def test_global_observe_overrides_escalate(self, tmp_path, make_event):
        """Global observe mode downgrades ESCALATE to ALLOW."""
        policy_file = tmp_path / "test.cedar"
        policy_file.write_text(_ESCALATE_POLICY)
        engine = PolicyEngine(policy_dir=str(tmp_path), observe=True)
        event = make_event(command="echo escalate-test")
        decision = engine.evaluate(event)
        # Global observe mode turns everything into ALLOW.
        assert decision.decision == DecisionVerdict.ALLOW
        assert "[observe]" in decision.reason


# ---------------------------------------------------------------------------
# Config enforcement overrides
# ---------------------------------------------------------------------------


class TestEnforcementConfigOverrides:
    """Config-based enforcement overrides work correctly."""

    def test_set_and_get_global_override(self, tmp_path):
        from vectimus.core.config import VectimusConfig

        config_path = tmp_path / "config.toml"
        config_path.write_text("")
        config = VectimusConfig(str(config_path))

        config.set_enforcement_override("test-001", "escalate")
        assert config.get_enforcement_override("test-001") == "escalate"

    def test_set_and_get_project_override(self, tmp_path):
        from vectimus.core.config import VectimusConfig

        config_path = tmp_path / "config.toml"
        config_path.write_text("")
        config = VectimusConfig(str(config_path))

        project = tmp_path / "myproject"
        project.mkdir()
        config.set_enforcement_override("test-001", "observe", project)
        assert config.get_enforcement_override("test-001", project) == "observe"

    def test_project_override_wins_over_global(self, tmp_path):
        from vectimus.core.config import VectimusConfig

        config_path = tmp_path / "config.toml"
        config_path.write_text("")
        config = VectimusConfig(str(config_path))

        project = tmp_path / "myproject"
        project.mkdir()
        config.set_enforcement_override("test-001", "escalate")
        config.set_enforcement_override("test-001", "observe", project)

        assert config.get_enforcement_override("test-001", project) == "observe"
        assert config.get_enforcement_override("test-001") == "escalate"

    def test_clear_override(self, tmp_path):
        from vectimus.core.config import VectimusConfig

        config_path = tmp_path / "config.toml"
        config_path.write_text("")
        config = VectimusConfig(str(config_path))

        config.set_enforcement_override("test-001", "escalate")
        assert config.get_enforcement_override("test-001") == "escalate"

        config.clear_enforcement_override("test-001")
        assert config.get_enforcement_override("test-001") is None

    def test_effective_overrides_merged(self, tmp_path):
        from vectimus.core.config import VectimusConfig

        config_path = tmp_path / "config.toml"
        config_path.write_text("")
        config = VectimusConfig(str(config_path))

        project = tmp_path / "myproject"
        project.mkdir()
        config.set_enforcement_override("rule-a", "escalate")
        config.set_enforcement_override("rule-b", "observe")
        config.set_enforcement_override("rule-a", "observe", project)

        effective = config.effective_enforcement_overrides(project)
        assert effective["rule-a"] == "observe"  # project wins
        assert effective["rule-b"] == "observe"  # global carries through

    def test_invalid_level_raises(self, tmp_path):
        from vectimus.core.config import VectimusConfig

        config_path = tmp_path / "config.toml"
        config_path.write_text("")
        config = VectimusConfig(str(config_path))

        with pytest.raises(ValueError, match="Invalid enforcement level"):
            config.set_enforcement_override("test-001", "invalid")

    def test_no_override_returns_none(self, tmp_path):
        from vectimus.core.config import VectimusConfig

        config_path = tmp_path / "config.toml"
        config_path.write_text("")
        config = VectimusConfig(str(config_path))

        assert config.get_enforcement_override("nonexistent") is None
