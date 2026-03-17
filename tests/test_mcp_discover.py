"""Tests for MCP server auto-discovery."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from vectimus.cli.detect import DetectionReport, ToolDetectionResult, ToolName
from vectimus.cli.init_cmd import init_cmd
from vectimus.cli.mcp_discover import discover_mcp_servers


def _make_report(*found_tools: ToolName) -> DetectionReport:
    """Build a DetectionReport with the given tools marked as found."""
    report = DetectionReport(platform="test")
    for tool in ToolName:
        report.results[tool] = ToolDetectionResult(tool=tool, found=tool in found_tools)
    return report


# ---------------------------------------------------------------------------
# discover_mcp_servers
# ---------------------------------------------------------------------------


class TestDiscoverMcpServers:
    """Unit tests for discover_mcp_servers()."""

    def test_claude_code_servers(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config = tmp_path / ".claude" / "settings.json"
        config.parent.mkdir(parents=True)
        config.write_text(
            json.dumps(
                {
                    "mcpServers": {"posthog": {}, "slack": {"cmd": "npx"}},
                }
            )
        )

        result = discover_mcp_servers(_make_report(ToolName.CLAUDE_CODE))
        assert result == {ToolName.CLAUDE_CODE: ["posthog", "slack"]}

    def test_claude_code_dot_claude_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Servers in ~/.claude.json (where `claude mcp add` writes) are discovered."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config = tmp_path / ".claude.json"
        config.write_text(
            json.dumps(
                {
                    "mcpServers": {"microsoft-learn": {}, "claude-history": {}},
                }
            )
        )

        result = discover_mcp_servers(_make_report(ToolName.CLAUDE_CODE))
        assert result == {ToolName.CLAUDE_CODE: ["claude-history", "microsoft-learn"]}

    def test_claude_code_project_mcp_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Servers in .mcp.json (project scope) are discovered."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        project = tmp_path / "myproject"
        project.mkdir()
        config = project / ".mcp.json"
        config.write_text(
            json.dumps(
                {
                    "mcpServers": {"sqlite": {}},
                }
            )
        )

        result = discover_mcp_servers(_make_report(ToolName.CLAUDE_CODE), project_dir=project)
        assert result == {ToolName.CLAUDE_CODE: ["sqlite"]}

    def test_claude_code_merges_all_sources(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Servers from settings.json, .claude.json and .mcp.json are merged."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({"mcpServers": {"posthog": {}}}))

        dot_claude = tmp_path / ".claude.json"
        dot_claude.write_text(json.dumps({"mcpServers": {"slack": {}}}))

        project = tmp_path / "myproject"
        project.mkdir()
        mcp_json = project / ".mcp.json"
        mcp_json.write_text(json.dumps({"mcpServers": {"sqlite": {}}}))

        result = discover_mcp_servers(_make_report(ToolName.CLAUDE_CODE), project_dir=project)
        assert result == {ToolName.CLAUDE_CODE: ["posthog", "slack", "sqlite"]}

    def test_claude_code_deduplicates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same server in multiple configs is not duplicated."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({"mcpServers": {"posthog": {}}}))

        dot_claude = tmp_path / ".claude.json"
        dot_claude.write_text(json.dumps({"mcpServers": {"posthog": {}, "slack": {}}}))

        result = discover_mcp_servers(_make_report(ToolName.CLAUDE_CODE))
        assert result == {ToolName.CLAUDE_CODE: ["posthog", "slack"]}

    def test_cursor_servers(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config = tmp_path / ".cursor" / "mcp.json"
        config.parent.mkdir(parents=True)
        config.write_text(
            json.dumps(
                {
                    "mcpServers": {"github": {}, "linear": {}},
                }
            )
        )

        result = discover_mcp_servers(_make_report(ToolName.CURSOR))
        assert result == {ToolName.CURSOR: ["github", "linear"]}

    def test_vscode_servers(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config = tmp_path / ".vscode" / "mcp.json"
        config.parent.mkdir(parents=True)
        config.write_text(
            json.dumps(
                {
                    "servers": {"copilot-mcp": {}},
                }
            )
        )

        result = discover_mcp_servers(_make_report(ToolName.COPILOT))
        assert result == {ToolName.COPILOT: ["copilot-mcp"]}

    def test_multiple_tools(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        claude_cfg = tmp_path / ".claude" / "settings.json"
        claude_cfg.parent.mkdir(parents=True)
        claude_cfg.write_text(json.dumps({"mcpServers": {"posthog": {}}}))

        cursor_cfg = tmp_path / ".cursor" / "mcp.json"
        cursor_cfg.parent.mkdir(parents=True)
        cursor_cfg.write_text(json.dumps({"mcpServers": {"github": {}}}))

        report = _make_report(ToolName.CLAUDE_CODE, ToolName.CURSOR)
        result = discover_mcp_servers(report)
        assert ToolName.CLAUDE_CODE in result
        assert ToolName.CURSOR in result

    def test_skips_undetected_tools(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Config file exists but tool was not detected -- should be ignored."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config = tmp_path / ".cursor" / "mcp.json"
        config.parent.mkdir(parents=True)
        config.write_text(json.dumps({"mcpServers": {"github": {}}}))

        result = discover_mcp_servers(_make_report())  # no tools found
        assert result == {}

    def test_missing_config_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = discover_mcp_servers(_make_report(ToolName.CLAUDE_CODE))
        assert result == {}

    def test_malformed_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config = tmp_path / ".claude" / "settings.json"
        config.parent.mkdir(parents=True)
        config.write_text("not valid json {{{")

        result = discover_mcp_servers(_make_report(ToolName.CLAUDE_CODE))
        assert result == {}

    def test_wrong_key_type(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """mcpServers is a list instead of a dict -- should be ignored."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config = tmp_path / ".claude" / "settings.json"
        config.parent.mkdir(parents=True)
        config.write_text(json.dumps({"mcpServers": ["not", "a", "dict"]}))

        result = discover_mcp_servers(_make_report(ToolName.CLAUDE_CODE))
        assert result == {}

    def test_missing_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Config exists but has no mcpServers key."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config = tmp_path / ".claude" / "settings.json"
        config.parent.mkdir(parents=True)
        config.write_text(json.dumps({"hooks": {}}))

        result = discover_mcp_servers(_make_report(ToolName.CLAUDE_CODE))
        assert result == {}

    def test_servers_are_sorted(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config = tmp_path / ".claude" / "settings.json"
        config.parent.mkdir(parents=True)
        config.write_text(
            json.dumps(
                {
                    "mcpServers": {"zeta": {}, "alpha": {}, "mid": {}},
                }
            )
        )

        result = discover_mcp_servers(_make_report(ToolName.CLAUDE_CODE))
        assert result[ToolName.CLAUDE_CODE] == ["alpha", "mid", "zeta"]


# ---------------------------------------------------------------------------
# init_cmd --allow-mcp integration
# ---------------------------------------------------------------------------


class TestInitMcpFlag:
    """Tests for the --allow-mcp flag on `vectimus init`."""

    @pytest.fixture()
    def _setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Set up isolated home and cwd for init tests."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)

        # Create Claude Code config with MCP servers.
        claude_cfg = tmp_path / ".claude" / "settings.json"
        claude_cfg.parent.mkdir(parents=True)
        claude_cfg.write_text(
            json.dumps(
                {
                    "mcpServers": {"posthog": {}, "slack": {}},
                }
            )
        )

    def test_allow_mcp_auto_approves(self, _setup, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(init_cmd, ["--allow-mcp"])

        assert result.exit_code == 0
        assert "MCP servers detected" in result.output
        assert "Approved 2 MCP server(s)" in result.output
        assert "posthog" in result.output
        assert "slack" in result.output

    def test_interactive_allow_all(self, _setup, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(init_cmd, input="y\n")

        assert result.exit_code == 0
        assert "Allow all 2 servers?" in result.output
        assert "Approved 2 MCP server(s)" in result.output

    def test_interactive_per_server(self, _setup, tmp_path: Path) -> None:
        runner = CliRunner()
        # Decline "allow all", then yes to posthog, no to slack.
        result = runner.invoke(init_cmd, input="n\ny\nn\n")

        assert result.exit_code == 0
        assert "Allow posthog?" in result.output
        assert "Allow slack?" in result.output
        assert "Approved 1 MCP server(s): posthog" in result.output

    def test_no_mcp_servers_no_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When no MCP servers are found, no MCP-related output is shown."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(init_cmd)

        assert result.exit_code == 0
        assert "MCP servers detected" not in result.output
