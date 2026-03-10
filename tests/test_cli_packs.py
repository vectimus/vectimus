"""Tests for CLI pack and rule commands using click's CliRunner."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from vectimus.cli.main import cli
from vectimus.core.config import VectimusConfig

SAMPLE_CEDAR = """\
@id("test-001")
@description("Block dangerous command")
@incident("test-incident-2025")
@suggested_alternative("Use a safer command")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*rm -rf /*"
};

@id("test-002")
@description("Block secret reads")
forbid (
    principal,
    action == Vectimus::Action::"file_read",
    resource
) when {
    context.file_path like "*.env"
};
"""


@pytest.fixture()
def setup(tmp_path: Path) -> tuple[str, str]:
    """Create a temporary pack directory and config file.

    Returns (policy_dir, config_path).
    """
    policy_dir = tmp_path / "policies"
    base_dir = policy_dir / "base"
    base_dir.mkdir(parents=True)
    (base_dir / "pack.toml").write_text(
        '[pack]\nname = "base"\nversion = "0.1.0"\ndescription = "Base rules"\nauthor = "Test"\n'
    )
    (base_dir / "rules.cedar").write_text(SAMPLE_CEDAR)

    config_path = str(tmp_path / "config.toml")
    return str(policy_dir), config_path


# ---------------------------------------------------------------------------
# Pack commands
# ---------------------------------------------------------------------------


class TestPackList:
    """vectimus pack list."""

    def test_lists_packs(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        runner = CliRunner()
        result = runner.invoke(
            cli, ["pack", "list", "--policy-dir", policy_dir, "--config", config_path]
        )
        assert result.exit_code == 0
        assert "base" in result.output
        assert "0.1.0" in result.output
        assert "enabled" in result.output

    def test_empty_dir(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        config_path = str(tmp_path / "config.toml")

        runner = CliRunner()
        result = runner.invoke(
            cli, ["pack", "list", "--policy-dir", str(empty), "--config", config_path]
        )
        assert result.exit_code == 0
        assert "No policy packs found" in result.output


class TestPackEnable:
    """vectimus pack enable."""

    def test_enable_pack(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup

        # Disable first.
        cfg = VectimusConfig(config_path)
        cfg.set_pack_enabled("base", False)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["pack", "enable", "base", "--policy-dir", policy_dir, "--config", config_path]
        )
        assert result.exit_code == 0
        assert "enabled" in result.output

        cfg2 = VectimusConfig(config_path)
        assert cfg2.is_pack_enabled("base") is True

    def test_enable_nonexistent(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "pack",
                "enable",
                "nonexistent",
                "--policy-dir",
                policy_dir,
                "--config",
                config_path,
            ],
        )
        assert result.exit_code != 0
        assert "not found" in result.output


class TestPackDisable:
    """vectimus pack disable."""

    def test_disable_pack(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        runner = CliRunner()
        # Use --yes to skip confirmation for base pack.
        result = runner.invoke(
            cli,
            [
                "pack",
                "disable",
                "base",
                "-y",
                "--policy-dir",
                policy_dir,
                "--config",
                config_path,
            ],
        )
        assert result.exit_code == 0
        assert "disabled" in result.output

        cfg = VectimusConfig(config_path)
        assert cfg.is_pack_enabled("base") is False

    def test_disable_base_requires_confirmation(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["pack", "disable", "base", "--policy-dir", policy_dir, "--config", config_path],
            input="n\n",
        )
        assert result.exit_code == 0
        assert "Aborted" in result.output

    def test_disable_nonexistent(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "pack",
                "disable",
                "nonexistent",
                "--policy-dir",
                policy_dir,
                "--config",
                config_path,
            ],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Rule commands
# ---------------------------------------------------------------------------


class TestRuleList:
    """vectimus rule list."""

    def test_lists_rules(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        runner = CliRunner()
        result = runner.invoke(
            cli, ["rule", "list", "--policy-dir", policy_dir, "--config", config_path]
        )
        assert result.exit_code == 0
        assert "test-001" in result.output
        assert "test-002" in result.output

    def test_shows_disabled_status(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("test-002")

        runner = CliRunner()
        result = runner.invoke(
            cli, ["rule", "list", "--policy-dir", policy_dir, "--config", config_path]
        )
        assert result.exit_code == 0
        assert "disabled" in result.output


class TestRuleDisable:
    """vectimus rule disable."""

    def test_disable_rule_global(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "rule",
                "disable",
                "test-001",
                "--global",
                "--policy-dir",
                policy_dir,
                "--config",
                config_path,
            ],
        )
        assert result.exit_code == 0
        assert "disabled" in result.output
        assert "globally" in result.output

        cfg = VectimusConfig(config_path)
        assert cfg.is_rule_disabled("test-001") is True

    def test_disable_rule_per_project(
        self, setup: tuple[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy_dir, config_path = setup
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "rule",
                "disable",
                "test-001",
                "--policy-dir",
                policy_dir,
                "--config",
                config_path,
            ],
        )
        assert result.exit_code == 0
        assert "disabled" in result.output

    def test_disable_nonexistent(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "rule",
                "disable",
                "nonexistent",
                "--global",
                "--policy-dir",
                policy_dir,
                "--config",
                config_path,
            ],
        )
        assert result.exit_code != 0


class TestRuleEnable:
    """vectimus rule enable."""

    def test_enable_rule_global(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("test-001")

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "rule",
                "enable",
                "test-001",
                "--global",
                "--policy-dir",
                policy_dir,
                "--config",
                config_path,
            ],
        )
        assert result.exit_code == 0
        assert "enabled" in result.output
        assert "globally" in result.output

        cfg2 = VectimusConfig(config_path)
        assert cfg2.is_rule_disabled("test-001") is False


class TestRuleShow:
    """vectimus rule show."""

    def test_shows_rule_details(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        runner = CliRunner()
        result = runner.invoke(
            cli, ["rule", "show", "test-001", "--policy-dir", policy_dir, "--config", config_path]
        )
        assert result.exit_code == 0
        assert "test-001" in result.output
        assert "Block dangerous command" in result.output
        assert "test-incident-2025" in result.output
        assert "Use a safer command" in result.output
        assert "forbid" in result.output

    def test_show_nonexistent(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "rule",
                "show",
                "nonexistent",
                "--policy-dir",
                policy_dir,
                "--config",
                config_path,
            ],
        )
        assert result.exit_code != 0


class TestRuleOverrides:
    """vectimus rule overrides."""

    def test_no_overrides(
        self, setup: tuple[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, config_path = setup
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["rule", "overrides", "--config", config_path])
        assert result.exit_code == 0
        assert "No project-specific overrides" in result.output

    def test_shows_overrides(
        self, setup: tuple[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, config_path = setup
        monkeypatch.chdir(tmp_path)
        cfg = VectimusConfig(config_path)
        cfg.disable_rule_for_project("test-001", Path.cwd())

        runner = CliRunner()
        result = runner.invoke(cli, ["rule", "overrides", "--config", config_path])
        assert result.exit_code == 0
        assert "test-001" in result.output


class TestRuleListGlobalVsProject:
    """vectimus rule list shows override scope."""

    def test_shows_global_disabled(self, setup: tuple[str, str]) -> None:
        policy_dir, config_path = setup
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("test-001")

        runner = CliRunner()
        result = runner.invoke(
            cli, ["rule", "list", "--policy-dir", policy_dir, "--config", config_path]
        )
        assert result.exit_code == 0
        assert "disabled (global)" in result.output


class TestRuleEnableGloballyDisabled:
    """Trying to per-project enable a globally disabled rule shows message."""

    def test_global_disabled_warns(
        self, setup: tuple[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy_dir, config_path = setup
        monkeypatch.chdir(tmp_path)
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("test-001")

        runner = CliRunner()
        result = runner.invoke(
            cli, ["rule", "enable", "test-001", "--policy-dir", policy_dir, "--config", config_path]
        )
        assert result.exit_code == 0
        assert "disabled globally" in result.output
        assert "--global" in result.output
