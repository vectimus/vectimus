"""Tests for the new critical Cedar policies (phase 1).

Covers:
- database_safety.cedar (vectimus-base-040 through 046)
- agent_safety.cedar (vectimus-base-047 through 050)
- file_protection.cedar updates (020b expansion, 051, 052)
- asi06_memory_poisoning.cedar expansion (owasp-018 new patterns)

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
BASE_PACK_DIR = _PROJECT_ROOT / "policies" / "base"
OWASP_PACK_DIR = _PROJECT_ROOT / "policies" / "owasp-agentic"


@pytest.fixture()
def engine(make_event) -> PolicyEngine:
    """Return a PolicyEngine loaded with both base and OWASP policies."""
    parts: list[str] = []
    for pack_dir in [BASE_PACK_DIR, OWASP_PACK_DIR]:
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
    """Parse rules from new/modified base Cedar files for annotation testing."""
    rules = []
    for filename in ["database_safety.cedar", "agent_safety.cedar"]:
        cedar_file = BASE_PACK_DIR / filename
        text = cedar_file.read_text()
        rules.extend(
            parse_rules_from_cedar(
                text,
                pack_name="base",
                source_file=str(cedar_file),
            )
        )
    # Also grab the new rules from file_protection.cedar (051, 052)
    fp_text = (BASE_PACK_DIR / "file_protection.cedar").read_text()
    for rule in parse_rules_from_cedar(
        fp_text,
        pack_name="base",
        source_file=str(BASE_PACK_DIR / "file_protection.cedar"),
    ):
        if rule.rule_id in ("vectimus-base-051", "vectimus-base-052"):
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
        """We added 7 + 4 + 2 = 13 new base rules."""
        assert len(all_new_base_rules) == 13

    def test_no_duplicate_ids(self, all_new_base_rules) -> None:
        ids = [r.rule_id for r in all_new_base_rules]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"


# ---------------------------------------------------------------------------
# GAP 1: Database safety (vectimus-base-040 through 046) -- deny tests
# ---------------------------------------------------------------------------


class TestDatabaseSafety:
    """Test ORM/migration destructive flag detection."""

    # -- vectimus-base-040: drizzle-kit --

    def test_drizzle_push_force_denied(self, engine, make_event) -> None:
        event = make_event(command="npx drizzle-kit push --force")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-040" in pid for pid in decision.matched_policy_ids)

    def test_drizzle_drop_denied(self, engine, make_event) -> None:
        event = make_event(command="npx drizzle-kit drop")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-040" in pid for pid in decision.matched_policy_ids)

    def test_drizzle_push_without_force_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx drizzle-kit push")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    def test_drizzle_generate_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx drizzle-kit generate")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-base-041: prisma --

    def test_prisma_accept_data_loss_denied(self, engine, make_event) -> None:
        event = make_event(command="npx prisma db push --accept-data-loss")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-041" in pid for pid in decision.matched_policy_ids)

    def test_prisma_migrate_reset_denied(self, engine, make_event) -> None:
        event = make_event(command="npx prisma migrate reset")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-041" in pid for pid in decision.matched_policy_ids)

    def test_prisma_db_execute_denied(self, engine, make_event) -> None:
        event = make_event(command="npx prisma db execute --file ./migration.sql")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-041" in pid for pid in decision.matched_policy_ids)

    def test_prisma_db_push_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx prisma db push")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    def test_prisma_migrate_dev_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx prisma migrate dev")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-base-042: knex --

    def test_knex_rollback_all_denied(self, engine, make_event) -> None:
        event = make_event(command="npx knex migrate:rollback --all")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-042" in pid for pid in decision.matched_policy_ids)

    def test_knex_rollback_single_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx knex migrate:rollback")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    def test_knex_migrate_latest_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx knex migrate:latest")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-base-043: sequelize --

    def test_sequelize_db_drop_denied(self, engine, make_event) -> None:
        event = make_event(command="npx sequelize db:drop")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-043" in pid for pid in decision.matched_policy_ids)

    def test_sequelize_undo_all_denied(self, engine, make_event) -> None:
        event = make_event(command="npx sequelize db:migrate:undo:all")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-043" in pid for pid in decision.matched_policy_ids)

    def test_sequelize_migrate_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx sequelize db:migrate")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-base-044: rails --

    def test_rails_db_drop_denied(self, engine, make_event) -> None:
        event = make_event(command="rails db:drop")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-044" in pid for pid in decision.matched_policy_ids)

    def test_rails_db_reset_denied(self, engine, make_event) -> None:
        event = make_event(command="rails db:reset")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-044" in pid for pid in decision.matched_policy_ids)

    def test_rails_db_schema_load_denied(self, engine, make_event) -> None:
        event = make_event(command="rails db:schema:load")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-044" in pid for pid in decision.matched_policy_ids)

    def test_rake_db_drop_denied(self, engine, make_event) -> None:
        event = make_event(command="rake db:drop")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-044" in pid for pid in decision.matched_policy_ids)

    def test_rails_db_migrate_allowed(self, engine, make_event) -> None:
        event = make_event(command="rails db:migrate")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-base-045: django --

    def test_django_flush_no_input_denied(self, engine, make_event) -> None:
        event = make_event(command="python manage.py flush --no-input")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-045" in pid for pid in decision.matched_policy_ids)

    def test_django_flush_interactive_allowed(self, engine, make_event) -> None:
        """flush without --no-input still shows confirmation prompt."""
        event = make_event(command="python manage.py flush")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    def test_django_migrate_allowed(self, engine, make_event) -> None:
        event = make_event(command="python manage.py migrate")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-base-046: typeorm --

    def test_typeorm_schema_drop_denied(self, engine, make_event) -> None:
        event = make_event(command="npx typeorm schema:drop")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-046" in pid for pid in decision.matched_policy_ids)

    def test_typeorm_migration_revert_denied(self, engine, make_event) -> None:
        event = make_event(command="npx typeorm migration:revert")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-046" in pid for pid in decision.matched_policy_ids)

    def test_typeorm_migration_run_allowed(self, engine, make_event) -> None:
        event = make_event(command="npx typeorm migration:run")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW


# ---------------------------------------------------------------------------
# GAP 2: Agent safety (vectimus-base-047 through 050) -- deny tests
# ---------------------------------------------------------------------------


class TestAgentSafety:
    """Test AI tool permission bypass flag detection."""

    # -- vectimus-base-047: claude --dangerously-skip-permissions --

    def test_claude_skip_permissions_denied(self, engine, make_event) -> None:
        event = make_event(command="claude --dangerously-skip-permissions 'delete all files'")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-047" in pid for pid in decision.matched_policy_ids)

    def test_claude_normal_allowed(self, engine, make_event) -> None:
        event = make_event(command="claude 'fix the login bug'")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-base-048: gemini --yolo --

    def test_gemini_yolo_denied(self, engine, make_event) -> None:
        event = make_event(command="gemini --yolo 'rewrite everything'")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-048" in pid for pid in decision.matched_policy_ids)

    def test_gemini_normal_allowed(self, engine, make_event) -> None:
        event = make_event(command="gemini 'explain this function'")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-base-049: --trust-all-tools --

    def test_trust_all_tools_denied(self, engine, make_event) -> None:
        event = make_event(command="q --trust-all-tools 'scan for secrets'")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-049" in pid for pid in decision.matched_policy_ids)

    def test_amazon_q_normal_allowed(self, engine, make_event) -> None:
        event = make_event(command="q 'explain this code'")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW

    # -- vectimus-base-050: generic bypass flags --

    def test_skip_permissions_denied(self, engine, make_event) -> None:
        event = make_event(command="some-tool --skip-permissions run")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-050" in pid for pid in decision.matched_policy_ids)

    def test_no_safety_denied(self, engine, make_event) -> None:
        event = make_event(command="ai-tool --no-safety execute")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-050" in pid for pid in decision.matched_policy_ids)

    def test_normal_flag_allowed(self, engine, make_event) -> None:
        event = make_event(command="some-tool --verbose run")
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW


# ---------------------------------------------------------------------------
# GAP 3: File protection updates (020b expansion, 051, 052)
# ---------------------------------------------------------------------------


class TestFileProtectionUpdates:
    """Test expanded governance config protection and new IDE settings rules."""

    # -- vectimus-base-020b expansion --

    def test_cursor_mcp_json_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.cursor/mcp.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-020b" in pid for pid in decision.matched_policy_ids)

    def test_claude_mcp_json_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.claude/mcp.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-020b" in pid for pid in decision.matched_policy_ids)

    def test_vscode_settings_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.vscode/settings.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-020b" in pid for pid in decision.matched_policy_ids)

    def test_vscode_tasks_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.vscode/tasks.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-020b" in pid for pid in decision.matched_policy_ids)

    # -- vectimus-base-051: launch.json and extensions.json --

    def test_vscode_launch_json_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.vscode/launch.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-051" in pid for pid in decision.matched_policy_ids)

    def test_vscode_extensions_json_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.vscode/extensions.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-051" in pid for pid in decision.matched_policy_ids)

    # -- vectimus-base-052: generic MCP config --

    def test_generic_mcp_json_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/.config/some-tool/mcp.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-052" in pid for pid in decision.matched_policy_ids)

    def test_mcp_config_yaml_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/.config/tool/mcp_config.yaml",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("vectimus-base-052" in pid for pid in decision.matched_policy_ids)

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
# OWASP-018 expansion: new agent instruction files
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
        assert any("owasp-018" in pid for pid in decision.matched_policy_ids)

    def test_aider_conf_write_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.aider.conf.yml",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("owasp-018" in pid for pid in decision.matched_policy_ids)

    def test_zed_settings_write_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.zed/settings.json",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("owasp-018" in pid for pid in decision.matched_policy_ids)

    def test_roorules_write_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.roorules",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("owasp-018" in pid for pid in decision.matched_policy_ids)

    # -- existing patterns still work --

    def test_claude_md_still_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/CLAUDE.md",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("owasp-018" in pid for pid in decision.matched_policy_ids)

    def test_cursorrules_still_denied(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/.cursorrules",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert any("owasp-018" in pid for pid in decision.matched_policy_ids)

    # -- false positive --

    def test_normal_yml_write_allowed(self, engine, make_event) -> None:
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path="/home/user/project/config.yml",
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.ALLOW
