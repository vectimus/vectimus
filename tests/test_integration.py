"""End-to-end integration tests: raw payload -> normalise -> PolicyEngine -> Decision."""

from __future__ import annotations

from pathlib import Path

import pytest

from vectimus.engine.config import VectimusConfig
from vectimus.engine.evaluator import PolicyEngine
from vectimus.engine.loader import PolicyLoader
from vectimus.engine.models import DecisionVerdict
from vectimus.engine.normaliser import normalise

SAMPLE_CEDAR = """\
@id("int-001")
@description("Block rm -rf")
@suggested_alternative("Use a safer deletion method")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*rm -rf /*"
};

@id("int-002")
@description("Block .env reads")
forbid (
    principal,
    action == Vectimus::Action::"file_read",
    resource
) when {
    context.file_path like "*.env"
};

@id("int-003")
@description("Block npm publish")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm publish*"
};
"""


@pytest.fixture()
def setup(tmp_path: Path) -> tuple[str, str]:
    """Create policy pack and config.  Returns (policy_dir, config_path)."""
    policy_dir = tmp_path / "policies" / "base"
    policy_dir.mkdir(parents=True)
    (policy_dir / "pack.toml").write_text(
        '[pack]\nname = "base"\nversion = "1.0.0"\ndescription = "Test base"\nauthor = "Test"\n'
    )
    (policy_dir / "rules.cedar").write_text(SAMPLE_CEDAR)
    config_path = str(tmp_path / "config.toml")
    return str(tmp_path / "policies"), config_path


class TestClaudeCodeDeny:
    """Claude Code payload that should be denied."""

    def test_rm_rf_denied(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "claude-code")
        loader = PolicyLoader(policy_dirs=[policy_dir], config_path=config_path)
        engine = PolicyEngine(loader=loader)
        decision = engine.evaluate(event)

        assert decision.decision == DecisionVerdict.DENY
        assert "int-001" in decision.matched_policy_ids
        assert decision.suggested_alternative == "Use a safer deletion method"

    def test_env_read_denied(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        payload = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/app/.env"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "claude-code")
        loader = PolicyLoader(policy_dirs=[policy_dir], config_path=config_path)
        engine = PolicyEngine(loader=loader)
        decision = engine.evaluate(event)

        assert decision.decision == DecisionVerdict.DENY
        assert "int-002" in decision.matched_policy_ids


class TestCursorAllow:
    """Cursor payload that should be allowed."""

    def test_safe_command_allowed(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        payload = {
            "command": "ls -la",
            "hook_event_name": "beforeShellExecution",
            "cwd": "/home/user/project",
        }
        event = normalise(payload, "cursor")
        loader = PolicyLoader(policy_dirs=[policy_dir], config_path=config_path)
        engine = PolicyEngine(loader=loader)
        decision = engine.evaluate(event)

        assert decision.decision == DecisionVerdict.ALLOW


class TestBothPacksLoaded:
    """Verify that rules from multiple packs are evaluated."""

    def test_multi_pack(self, tmp_path: Path) -> None:
        # First pack
        base_dir = tmp_path / "policies" / "base"
        base_dir.mkdir(parents=True)
        (base_dir / "pack.toml").write_text(
            '[pack]\nname = "base"\nversion = "1.0.0"\ndescription = "B"\nauthor = "T"\n'
        )
        (base_dir / "rules.cedar").write_text(SAMPLE_CEDAR)

        # Second pack
        extra_dir = tmp_path / "policies" / "extra"
        extra_dir.mkdir(parents=True)
        (extra_dir / "pack.toml").write_text(
            '[pack]\nname = "extra"\nversion = "0.1.0"\ndescription = "E"\nauthor = "T"\n'
        )
        extra_cedar = """\
@id("extra-block-curl")
@description("Block curl to internal")
forbid (
    principal,
    action == Vectimus::Action::"web_request",
    resource
) when {
    context.url like "*internal.corp*"
};
"""
        (extra_dir / "extra.cedar").write_text(extra_cedar)

        config_path = str(tmp_path / "config.toml")
        payload = {
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://internal.corp/secrets"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "claude-code")
        loader = PolicyLoader(policy_dirs=[str(tmp_path / "policies")], config_path=config_path)
        engine = PolicyEngine(loader=loader)
        decision = engine.evaluate(event)

        assert decision.decision == DecisionVerdict.DENY
        assert "extra-block-curl" in decision.matched_policy_ids


class TestDisabledRuleSkipped:
    """A disabled rule should not cause a deny."""

    def test_disabled_rule_allows(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("int-001")

        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "claude-code")
        loader = PolicyLoader(policy_dirs=[policy_dir], config_path=config_path)
        engine = PolicyEngine(loader=loader)
        decision = engine.evaluate(event)

        assert decision.decision == DecisionVerdict.ALLOW

    def test_project_disabled_rule_allows(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        project_path = Path("/tmp/test-project")

        cfg = VectimusConfig(config_path)
        cfg.disable_rule_for_project("int-001", project_path)

        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "claude-code")
        loader = PolicyLoader(
            policy_dirs=[policy_dir],
            config_path=config_path,
            project_path=project_path,
        )
        engine = PolicyEngine(loader=loader)
        decision = engine.evaluate(event)

        assert decision.decision == DecisionVerdict.ALLOW


class TestNpmPublishDeny:
    """npm publish should be denied via package_operation rule."""

    def test_npm_publish_denied(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "npm publish --access public"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "claude-code")
        loader = PolicyLoader(policy_dirs=[policy_dir], config_path=config_path)
        engine = PolicyEngine(loader=loader)
        decision = engine.evaluate(event)

        assert decision.decision == DecisionVerdict.DENY
        assert "int-003" in decision.matched_policy_ids
