"""Tests for project-local .vectimus/config.toml support."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from vectimus.core.config import VectimusConfig, project_local_config_path


@pytest.fixture()
def config_path(tmp_path: Path) -> str:
    """Return a path to a temporary global config file."""
    return str(tmp_path / "global" / "config.toml")


class TestProjectLocalConfigPath:
    """Test the project_local_config_path() function."""

    def test_returns_correct_path(self, tmp_path: Path) -> None:
        result = project_local_config_path(tmp_path / "my-project")
        assert result == tmp_path / "my-project" / ".vectimus" / "config.toml"


class TestProjectLocalConfig:
    """Project-local config tests."""

    def test_disable_rule_writes_to_project_local(self, config_path: str, tmp_path: Path) -> None:
        cfg = VectimusConfig(config_path)
        project = tmp_path / "my-project"
        project.mkdir()

        cfg.disable_rule_for_project("test-rule", project)

        local_path = project_local_config_path(project)
        assert local_path.exists()
        with open(local_path, "rb") as f:
            data = tomllib.load(f)
        assert "test-rule" in data["rules"]["disabled"]

    def test_enable_rule_reads_from_project_local(self, config_path: str, tmp_path: Path) -> None:
        cfg = VectimusConfig(config_path)
        project = tmp_path / "my-project"
        project.mkdir()

        cfg.disable_rule_for_project("test-rule", project)
        assert "test-rule" in cfg.load_project_overrides(project)

        cfg.enable_rule_for_project("test-rule", project)
        assert "test-rule" not in cfg.load_project_overrides(project)

    def test_effective_config_merges_global_and_project(
        self, config_path: str, tmp_path: Path
    ) -> None:
        cfg = VectimusConfig(config_path)
        # Set global identity.
        cfg._data["identity"] = {"persona": "global-persona", "resolver": "git"}
        cfg._write()

        project = tmp_path / "my-project"
        project.mkdir()

        # Write project-local identity override.
        local_path = project_local_config_path(project)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        import tomli_w

        with open(local_path, "wb") as f:
            tomli_w.dump({"identity": {"persona": "project-persona"}}, f)

        effective = cfg.effective_config(project)
        # Project overrides global for persona.
        assert effective["identity"]["persona"] == "project-persona"
        # Global resolver is preserved.
        assert effective["identity"]["resolver"] == "git"

    def test_project_config_dir_created_on_disable(self, config_path: str, tmp_path: Path) -> None:
        cfg = VectimusConfig(config_path)
        project = tmp_path / "my-project"
        project.mkdir()

        # .vectimus dir should not exist yet.
        assert not (project / ".vectimus").exists()

        cfg.disable_rule_for_project("test-rule", project)

        assert (project / ".vectimus").exists()
        assert project_local_config_path(project).exists()

    def test_two_projects_independent_local_configs(self, config_path: str, tmp_path: Path) -> None:
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

        # Both use project-local paths.
        assert project_local_config_path(proj_a).exists()
        assert project_local_config_path(proj_b).exists()
