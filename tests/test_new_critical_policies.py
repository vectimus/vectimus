"""Tests for the new critical Cedar policies (phase 1).

Covers:
- database.cedar (vectimus-db-001 through 007)
- agent_governance.cedar (vectimus-agentgov-001 through 004)
- file_integrity.cedar updates (fileint-004 expansion, 007, 008)
- asi06_memory_poisoning.cedar expansion (vectimus-fileint-011 new patterns)

Each rule is tested with at least one deny case (matching command) and one
allow case (similar but legitimate command).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vectimus.engine.evaluator import PolicyEngine
from vectimus.engine.loader import parse_rules_from_cedar
from vectimus.engine.models import ActionType, DecisionVerdict

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_POLICIES_ROOT = _PROJECT_ROOT / "policies"


def _all_pack_dirs() -> list[Path]:
    """Return all pack directories (those containing pack.toml)."""
    return sorted(d for d in _POLICIES_ROOT.iterdir() if d.is_dir() and (d / "pack.toml").exists())


def _find_cedar_file(filename: str) -> Path | None:
    """Find a cedar file by name across all pack directories."""
    for pack_dir in _all_pack_dirs():
        candidate = pack_dir / filename
        if candidate.exists():
            return candidate
    return None


@pytest.fixture()
def engine(make_event) -> PolicyEngine:
    """Return a PolicyEngine loaded with all policy packs."""
    parts: list[str] = []
    for pack_dir in _all_pack_dirs():
        for cedar_file in sorted(pack_dir.glob("*.cedar")):
            parts.append(cedar_file.read_text())

    combined = "\n\n".join(parts)

    import tempfile

    tmpdir = tempfile.mkdtemp()
    combined_path = Path(tmpdir) / "all_policies.cedar"
    combined_path.write_text(combined)

    return PolicyEngine(policy_dir=tmpdir)


@pytest.fixture()
def all_new_base_rules() -> list:
    """Parse rules from database/agent governance Cedar files for annotation testing."""
    rules = []
    for filename in ["database.cedar", "agent_governance.cedar"]:
        cedar_file = _find_cedar_file(filename)
        if cedar_file is None:
            continue
        text = cedar_file.read_text()
        rules.extend(
            parse_rules_from_cedar(
                text,
                pack_name=cedar_file.parent.name,
                source_file=str(cedar_file),
            )
        )
    # Also grab the new rules from file_integrity.cedar (007, 008)
    fp_file = _find_cedar_file("file_integrity.cedar")
    if fp_file is not None:
        fp_text = fp_file.read_text()
        for rule in parse_rules_from_cedar(
            fp_text,
            pack_name=fp_file.parent.name,
            source_file=str(fp_file),
        ):
            if rule.rule_id in ("vectimus-fileint-007", "vectimus-fileint-008"):
                rules.append(rule)
    return rules


# ---------------------------------------------------------------------------
# Annotation completeness
# ---------------------------------------------------------------------------


class TestNewRuleAnnotations:
    """Verify all new rules have required annotations."""

    def test_all_new_rules_have_required_annotations(self, all_new_base_rules) -> None:
        for rule in all_new_base_rules:
            assert rule.rule_id, f"Rule missing @id in {rule.source_file}"
            assert rule.description, f"Rule {rule.rule_id} missing @description"
            assert rule.incident, f"Rule {rule.rule_id} missing @incident"
            assert rule.suggested_alternative, f"Rule {rule.rule_id} missing @suggested_alternative"

    def test_new_rule_count(self, all_new_base_rules) -> None:
        """Database (8) + agent-governance (14) + file-integrity subset (2) = 24 rules."""
        assert len(all_new_base_rules) == 24

    def test_no_duplicate_ids(self, all_new_base_rules) -> None:
        ids = [r.rule_id for r in all_new_base_rules]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"


# ---------------------------------------------------------------------------
# GAP 1: Database safety (vectimus-db-001 through 007) -- deny tests
# ---------------------------------------------------------------------------


class TestDatabaseSafety:
    """Test ORM/migration destructive flag detection."""

    # -- vectimus-db-001: drizzle-kit --

    def test_drizzle_push_force_denied(self, engine, make_event) -> None:
        event = make_event(command="npx drizzle-kit push --force")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-001" in pid for pid in decision.matched_policy_ids)

    def test_drizzle_drop_denied(self, engine, make_event) -> None:
        event = make_event(command="npx drizzle-kit drop")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-001" in pid for pid in decision.matched_policy_ids)

    def test_drizzle_push_without_force_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx drizzle-kit push")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    def test_drizzle_generate_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx drizzle-kit generate")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-db-002: prisma --

    def test_prisma_accept_data_loss_denied(self, engine, make_event) -> None:
        event = make_event(command="npx prisma db push --accept-data-loss")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-002" in pid for pid in decision.matched_policy_ids)

    def test_prisma_migrate_reset_denied(self, engine, make_event) -> None:
        event = make_event(command="npx prisma migrate reset")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-002" in pid for pid in decision.matched_policy_ids)

    def test_prisma_db_execute_denied(self, engine, make_event) -> None:
        event = make_event(command="npx prisma db execute --file ./migration.sql")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-002" in pid for pid in decision.matched_policy_ids)

    def test_prisma_db_push_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx prisma db push")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    def test_prisma_migrate_dev_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx prisma migrate dev")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-db-003: knex --

    def test_knex_rollback_all_denied(self, engine, make_event) -> None:
        event = make_event(command="npx knex migrate:rollback --all")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-003" in pid for pid in decision.matched_policy_ids)

    def test_knex_rollback_single_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx knex migrate:rollback")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    def test_knex_migrate_latest_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx knex migrate:latest")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-db-004: sequelize --

    def test_sequelize_db_drop_denied(self, engine, make_event) -> None:
        event = make_event(command="npx sequelize db:drop")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-004" in pid for pid in decision.matched_policy_ids)

    def test_sequelize_undo_all_denied(self, engine, make_event) -> None:
        event = make_event(command="npx sequelize db:migrate:undo:all")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-004" in pid for pid in decision.matched_policy_ids)

    def test_sequelize_migrate_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx sequelize db:migrate")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-db-005: rails --

    def test_rails_db_drop_denied(self, engine, make_event) -> None:
        event = make_event(command="rails db:drop")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-005" in pid for pid in decision.matched_policy_ids)

    def test_rails_db_reset_denied(self, engine, make_event) -> None:
        event = make_event(command="rails db:reset")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-005" in pid for pid in decision.matched_policy_ids)

    def test_rails_db_schema_load_denied(self, engine, make_event) -> None:
        event = make_event(command="rails db:schema:load")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-005" in pid for pid in decision.matched_policy_ids)

    def test_rake_db_drop_denied(self, engine, make_event) -> None:
        event = make_event(command="rake db:drop")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-005" in pid for pid in decision.matched_policy_ids)

    def test_rails_db_migrate_allowed(self, engine, make_event) -> None:
        event = make_event(command="rails db:migrate")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-db-006: django --

    def test_django_flush_no_input_denied(self, engine, make_event) -> None:
        event = make_event(command="python manage.py flush --no-input")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-006" in pid for pid in decision.matched_policy_ids)

    def test_django_flush_interactive_allowed(self, engine, make_event) -> None:
        """flush without --no-input still shows confirmation prompt."""
        event = make_event(command="python manage.py flush")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    def test_django_migrate_allowed(self, engine, make_event) -> None:
        event = make_event(command="python manage.py migrate")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-db-007: typeorm --

    def test_typeorm_schema_drop_denied(self, engine, make_event) -> None:
        event = make_event(command="npx typeorm schema:drop")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-007" in pid for pid in decision.matched_policy_ids)

    def test_typeorm_migration_revert_denied(self, engine, make_event) -> None:
        event = make_event(command="npx typeorm migration:revert")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-db-007" in pid for pid in decision.matched_policy_ids)

    def test_typeorm_migration_run_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx typeorm migration:run")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW


# ---------------------------------------------------------------------------
# GAP 2: Agent safety (vectimus-agentgov-001 through 004) -- deny tests
# ---------------------------------------------------------------------------


class TestAgentSafety:
    """Test AI tool permission bypass flag detection."""

    # -- vectimus-agentgov-001: claude --dangerously-skip-permissions --

    def test_claude_skip_permissions_denied(self, engine, make_event) -> None:
        event = make_event(command="claude --dangerously-skip-permissions 'delete all files'")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-agentgov-001" in pid for pid in decision.matched_policy_ids)

    def test_claude_normal_allowed(self, engine, make_event) -> None:
        event = make_event(command="claude 'fix the login bug'")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-agentgov-002: gemini --yolo --

    def test_gemini_yolo_denied(self, engine, make_event) -> None:
        event = make_event(command="gemini --yolo 'rewrite everything'")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-agentgov-002" in pid for pid in decision.matched_policy_ids)

    def test_gemini_normal_allowed(self, engine, make_event) -> None:
        event = make_event(command="gemini 'explain this function'")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-agentgov-003: --trust-all-tools --

    def test_trust_all_tools_denied(self, engine, make_event) -> None:
        event = make_event(command="q --trust-all-tools 'scan for secrets'")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-agentgov-003" in pid for pid in decision.matched_policy_ids)

    def test_amazon_q_normal_allowed(self, engine, make_event) -> None:
        event = make_event(command="q 'explain this code'")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-agentgov-004: generic bypass flags --

    def test_skip_permissions_denied(self, engine, make_event) -> None:
        event = make_event(command="some-tool --skip-permissions run")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-agentgov-004" in pid for pid in decision.matched_policy_ids)

    def test_no_safety_denied(self, engine, make_event) -> None:
        event = make_event(command="ai-tool --no-safety execute")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-agentgov-004" in pid for pid in decision.matched_policy_ids)

    def test_normal_flag_allowed(self, engine, make_event) -> None:
        event = make_event(command="some-tool --verbose run")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW


# ---------------------------------------------------------------------------
# GAP 3: File integrity updates (fileint-004 expansion, 007, 008)
# ---------------------------------------------------------------------------


class TestFileProtectionUpdates:
    """Test expanded governance config protection and new IDE settings rules."""

    # -- vectimus-fileint-004 expansion --

    def test_cursor_mcp_json_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.cursor/mcp.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-004" in pid for pid in decision.matched_policy_ids)

    def test_claude_mcp_json_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.claude/mcp.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-004" in pid for pid in decision.matched_policy_ids)

    def test_vscode_settings_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.vscode/settings.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-004" in pid for pid in decision.matched_policy_ids)

    def test_vscode_tasks_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.vscode/tasks.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-004" in pid for pid in decision.matched_policy_ids)

    # -- vectimus-fileint-007: launch.json and extensions.json --

    def test_vscode_launch_json_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.vscode/launch.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-007" in pid for pid in decision.matched_policy_ids)

    def test_vscode_extensions_json_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.vscode/extensions.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-007" in pid for pid in decision.matched_policy_ids)

    # -- vectimus-fileint-008: generic MCP config --

    def test_generic_mcp_json_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/.config/some-tool/mcp.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-008" in pid for pid in decision.matched_policy_ids)

    def test_mcp_config_yaml_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/.config/tool/mcp_config.yaml",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-008" in pid for pid in decision.matched_policy_ids)

    # -- false positive tests --

    def test_normal_json_write_allowed(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/tsconfig.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    def test_normal_vscode_snippet_allowed(self, engine, make_event) -> None:
        """Writing to .vscode/snippets.json is not blocked."""
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.vscode/snippets.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW


# ---------------------------------------------------------------------------
# vectimus-fileint-011 expansion: new agent instruction files
# ---------------------------------------------------------------------------


class TestOwaspMemoryPoisoningExpansion:
    """Test that new agent instruction file patterns are blocked."""

    def test_kirorules_write_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.kirorules",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-011" in pid for pid in decision.matched_policy_ids)

    def test_aider_conf_write_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.aider.conf.yml",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-011" in pid for pid in decision.matched_policy_ids)

    def test_zed_settings_write_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.zed/settings.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-011" in pid for pid in decision.matched_policy_ids)

    def test_roorules_write_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.roorules",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-011" in pid for pid in decision.matched_policy_ids)

    # -- existing patterns still work --

    def test_claude_md_still_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/CLAUDE.md",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-011" in pid for pid in decision.matched_policy_ids)

    def test_cursorrules_still_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.cursorrules",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-fileint-011" in pid for pid in decision.matched_policy_ids)

    # -- false positive --

    def test_normal_yml_write_allowed(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/config.yml",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW
