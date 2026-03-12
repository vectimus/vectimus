"""Tests for VectimusConfig read/write, pack enable/disable, rule enable/disable."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from vectimus.engine.config import VectimusConfig


@pytest.fixture()
def config_path(tmp_path: Path) -> str:
    """Return a path to a temporary config file."""
    return str(tmp_path / "config.toml")


class TestConfigDefaults:
    """Config behaviour when no file exists."""

    def test_missing_file_returns_empty_config(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.data == {}

    def test_packs_enabled_by_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.is_pack_enabled("base") is True
        assert cfg.is_pack_enabled("nonexistent") is True

    def test_no_rules_disabled_by_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.is_rule_disabled("base-001") is False
        assert cfg.disabled_rules() == []


class TestPackManagement:
    """Pack enable/disable writes to disk."""

    def test_disable_pack(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.set_pack_enabled("soc2", False)

        assert cfg.is_pack_enabled("soc2") is False
        # Verify written to disk.
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        assert data["packs"]["soc2"]["enabled"] is False

    def test_enable_pack(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.set_pack_enabled("soc2", False)
        cfg.set_pack_enabled("soc2", True)

        assert cfg.is_pack_enabled("soc2") is True

    def test_other_packs_unaffected(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.set_pack_enabled("soc2", False)

        assert cfg.is_pack_enabled("base") is True


class TestRuleManagement:
    """Rule disable/enable operations."""

    def test_disable_rule(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("base-012")

        assert cfg.is_rule_disabled("base-012") is True
        assert "base-012" in cfg.disabled_rules()

    def test_disable_rule_idempotent(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("base-012")
        cfg.disable_rule("base-012")

        assert cfg.disabled_rules().count("base-012") == 1

    def test_enable_rule(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("base-012")
        cfg.enable_rule("base-012")

        assert cfg.is_rule_disabled("base-012") is False

    def test_enable_rule_not_in_list_is_noop(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.enable_rule("nonexistent")
        assert cfg.disabled_rules() == []

    def test_multiple_rules(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("base-012")
        cfg.disable_rule("base-015")

        assert cfg.is_rule_disabled("base-012") is True
        assert cfg.is_rule_disabled("base-015") is True
        assert len(cfg.disabled_rules()) == 2


class TestCreateDefault:
    """Config file creation."""

    def test_creates_file(self, tmp_path: Path) -> None:
        path = str(tmp_path / "sub" / "config.toml")
        cfg = VectimusConfig.create_default(path)

        assert Path(path).exists()
        assert cfg.is_pack_enabled("base") is True
        assert cfg.disabled_rules() == []

    def test_does_not_overwrite_existing(self, tmp_path: Path) -> None:
        path = str(tmp_path / "config.toml")

        # Create with a disabled pack.
        cfg = VectimusConfig(path)
        cfg.set_pack_enabled("soc2", False)

        # create_default should not overwrite.
        cfg2 = VectimusConfig.create_default(path)
        assert cfg2.is_pack_enabled("soc2") is False


class TestPersistence:
    """Config round-trips through disk."""

    def test_round_trip(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.set_pack_enabled("owasp", False)
        cfg.disable_rule("base-003")

        # Reload from disk.
        cfg2 = VectimusConfig(config_path)
        assert cfg2.is_pack_enabled("owasp") is False
        assert cfg2.is_rule_disabled("base-003") is True

    def test_identity_resolver_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.get_identity_resolver() == "git"

    def test_log_dir_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert ".vectimus" in cfg.get_log_dir()


# ---------------------------------------------------------------------------
# Per-project overrides
# ---------------------------------------------------------------------------


class TestProjectOverrides:
    """Per-project rule override loading, saving and merging."""

    def test_no_override_file_returns_empty(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        result = cfg.load_project_overrides(Path("/nonexistent/project"))
        assert result == set()

    def test_disable_rule_for_project_creates_file(self, config_path: str, tmp_path: Path) -> None:
        cfg = VectimusConfig(config_path)
        project = tmp_path / "my-project"
        project.mkdir()

        cfg.disable_rule_for_project("base-010", project)

        override_path = cfg.project_config_path(project)
        assert override_path.exists()
        with open(override_path, "rb") as f:
            data = tomllib.load(f)
        assert "base-010" in data["rules"]["disabled"]

    def test_disable_rule_for_project_idempotent(self, config_path: str, tmp_path: Path) -> None:
        cfg = VectimusConfig(config_path)
        project = tmp_path / "my-project"
        project.mkdir()

        cfg.disable_rule_for_project("base-010", project)
        cfg.disable_rule_for_project("base-010", project)

        overrides = cfg.load_project_overrides(project)
        assert len(overrides) == 1

    def test_enable_rule_for_project(self, config_path: str, tmp_path: Path) -> None:
        cfg = VectimusConfig(config_path)
        project = tmp_path / "my-project"
        project.mkdir()

        cfg.disable_rule_for_project("base-010", project)
        cfg.enable_rule_for_project("base-010", project)

        overrides = cfg.load_project_overrides(project)
        assert "base-010" not in overrides

    def test_enable_rule_for_missing_project_is_noop(
        self, config_path: str, tmp_path: Path
    ) -> None:
        cfg = VectimusConfig(config_path)
        # Should not raise.
        cfg.enable_rule_for_project("base-010", tmp_path / "nonexistent")

    def test_effective_disabled_rules_global_only(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("global-001")
        result = cfg.effective_disabled_rules()
        assert "global-001" in result

    def test_effective_disabled_rules_project_only(self, config_path: str, tmp_path: Path) -> None:
        cfg = VectimusConfig(config_path)
        project = tmp_path / "proj"
        project.mkdir()
        cfg.disable_rule_for_project("proj-001", project)

        result = cfg.effective_disabled_rules(project)
        assert "proj-001" in result

    def test_effective_disabled_rules_union(self, config_path: str, tmp_path: Path) -> None:
        cfg = VectimusConfig(config_path)
        project = tmp_path / "proj"
        project.mkdir()

        cfg.disable_rule("global-001")
        cfg.disable_rule_for_project("proj-001", project)

        result = cfg.effective_disabled_rules(project)
        assert "global-001" in result
        assert "proj-001" in result

    def test_global_disabled_stays_disabled_per_project(
        self, config_path: str, tmp_path: Path
    ) -> None:
        """A globally disabled rule cannot be re-enabled per-project."""
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("global-001")

        project = tmp_path / "proj"
        project.mkdir()

        # Even though the rule is not in project overrides, effective should include it.
        result = cfg.effective_disabled_rules(project)
        assert "global-001" in result

    def test_two_projects_independent(self, config_path: str, tmp_path: Path) -> None:
        cfg = VectimusConfig(config_path)
        proj_a = tmp_path / "proj-a"
        proj_b = tmp_path / "proj-b"
        proj_a.mkdir()
        proj_b.mkdir()

        cfg.disable_rule_for_project("rule-a", proj_a)
        cfg.disable_rule_for_project("rule-b", proj_b)

        assert "rule-a" in cfg.load_project_overrides(proj_a)
        assert "rule-a" not in cfg.load_project_overrides(proj_b)
        assert "rule-b" in cfg.load_project_overrides(proj_b)
        assert "rule-b" not in cfg.load_project_overrides(proj_a)

    def test_list_project_overrides(self, config_path: str, tmp_path: Path) -> None:
        cfg = VectimusConfig(config_path)
        project = tmp_path / "proj"
        project.mkdir()

        cfg.disable_rule_for_project("z-rule", project)
        cfg.disable_rule_for_project("a-rule", project)

        result = cfg.list_project_overrides(project)
        assert result == ["a-rule", "z-rule"]  # sorted

    def test_is_rule_disabled_with_project(self, config_path: str, tmp_path: Path) -> None:
        cfg = VectimusConfig(config_path)
        project = tmp_path / "proj"
        project.mkdir()

        cfg.disable_rule_for_project("proj-only", project)

        assert cfg.is_rule_disabled("proj-only", project) is True
        assert cfg.is_rule_disabled("proj-only") is False

    def test_corrupted_override_returns_empty(self, config_path: str, tmp_path: Path) -> None:
        cfg = VectimusConfig(config_path)
        project = tmp_path / "proj"
        project.mkdir()

        # Write a corrupted override file.
        override_path = cfg.project_config_path(project)
        override_path.parent.mkdir(parents=True, exist_ok=True)
        override_path.write_text("this is [[[not valid toml")

        result = cfg.load_project_overrides(project)
        assert result == set()
