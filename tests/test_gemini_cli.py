"""Tests for the Gemini CLI adapter, hook command, detection and init/remove."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from vectimus.cli.hook_cmd import hook_cmd
from vectimus.engine.models import ActionType, EventType
from vectimus.engine.normaliser import normalise

# ---------------------------------------------------------------------------
# Normaliser tests
# ---------------------------------------------------------------------------


class TestGeminiCLINormaliser:
    """Tests for Gemini CLI payload normalisation."""

    def test_shell_command(self) -> None:
        payload = {
            "tool_name": "run_shell_command",
            "tool_input": {"command": "ls -la"},
            "hook_event_name": "BeforeTool",
            "session_id": "gem-123",
            "cwd": "/home/user/project",
        }
        event = normalise(payload, "gemini-cli")
        assert event.action.action_type == ActionType.SHELL_COMMAND
        assert event.action.command == "ls -la"
        assert event.source.tool == "gemini-cli"
        assert event.source.session_id == "gem-123"
        assert event.context.cwd == "/home/user/project"
        assert event.event_type == EventType.PRE_ACTION

    def test_file_write(self) -> None:
        payload = {
            "tool_name": "write_file",
            "tool_input": {"file_path": "src/main.py", "content": "print('hello')"},
            "hook_event_name": "BeforeTool",
        }
        event = normalise(payload, "gemini-cli")
        assert event.action.action_type == ActionType.FILE_WRITE
        assert event.action.file_path == "src/main.py"
        assert event.action.file_content == "print('hello')"

    def test_file_edit(self) -> None:
        payload = {
            "tool_name": "edit_file",
            "tool_input": {"file_path": "src/app.py"},
            "hook_event_name": "BeforeTool",
        }
        event = normalise(payload, "gemini-cli")
        assert event.action.action_type == ActionType.FILE_WRITE

    def test_file_read(self) -> None:
        payload = {
            "tool_name": "read_file",
            "tool_input": {"file_path": "README.md"},
            "hook_event_name": "BeforeTool",
        }
        event = normalise(payload, "gemini-cli")
        assert event.action.action_type == ActionType.FILE_READ

    def test_list_directory(self) -> None:
        payload = {
            "tool_name": "list_directory",
            "tool_input": {"path": "/home/user"},
            "hook_event_name": "BeforeTool",
        }
        event = normalise(payload, "gemini-cli")
        assert event.action.action_type == ActionType.FILE_READ

    def test_terraform_detected_as_infrastructure(self) -> None:
        payload = {
            "tool_name": "run_shell_command",
            "tool_input": {"command": "terraform plan"},
            "hook_event_name": "BeforeTool",
        }
        event = normalise(payload, "gemini-cli")
        assert event.action.action_type == ActionType.INFRASTRUCTURE

    def test_npm_detected_as_package_operation(self) -> None:
        payload = {
            "tool_name": "run_shell_command",
            "tool_input": {"command": "npm install express"},
            "hook_event_name": "BeforeTool",
        }
        event = normalise(payload, "gemini-cli")
        assert event.action.action_type == ActionType.PACKAGE_OPERATION

    def test_git_detected_as_git_operation(self) -> None:
        payload = {
            "tool_name": "run_shell_command",
            "tool_input": {"command": "git push origin main"},
            "hook_event_name": "BeforeTool",
        }
        event = normalise(payload, "gemini-cli")
        assert event.action.action_type == ActionType.GIT_OPERATION

    def test_mcp_tool_detection(self) -> None:
        payload = {
            "tool_name": "mcp__github__create_issue",
            "tool_input": {"title": "Bug report"},
            "hook_event_name": "BeforeTool",
        }
        event = normalise(payload, "gemini-cli")
        assert event.action.action_type == ActionType.MCP_TOOL
        assert event.action.mcp_server == "github"
        assert event.action.mcp_tool == "create_issue"

    def test_unknown_tool_defaults_to_shell(self) -> None:
        payload = {
            "tool_name": "some_new_tool",
            "tool_input": {},
            "hook_event_name": "BeforeTool",
        }
        event = normalise(payload, "gemini-cli")
        assert event.action.action_type == ActionType.SHELL_COMMAND
        assert event.action.raw_tool_name == "some_new_tool"

    def test_missing_fields_handled(self) -> None:
        payload = {}
        event = normalise(payload, "gemini-cli")
        assert event.action.raw_tool_name == "unknown"
        assert event.source.tool == "gemini-cli"

    def test_default_principal(self) -> None:
        payload = {
            "tool_name": "read_file",
            "tool_input": {},
            "hook_event_name": "BeforeTool",
        }
        event = normalise(payload, "gemini-cli")
        # Enrichment may resolve principal from git config; just verify it's set.
        assert event.identity.principal is not None
        assert isinstance(event.identity.principal, str)

    def test_custom_principal(self) -> None:
        payload = {
            "tool_name": "read_file",
            "tool_input": {},
            "hook_event_name": "BeforeTool",
            "principal": "alice",
        }
        event = normalise(payload, "gemini-cli")
        assert event.identity.principal == "alice"


# ---------------------------------------------------------------------------
# Hook command tests
# ---------------------------------------------------------------------------


def _run_hook(source: str, payload: dict | str | None = None) -> tuple[int, str]:
    """Invoke the hook command with the given source and optional stdin payload."""
    runner = CliRunner()
    if payload is None:
        stdin = ""
    elif isinstance(payload, dict):
        stdin = json.dumps(payload)
    else:
        stdin = payload
    result = runner.invoke(hook_cmd, ["--source", source], input=stdin)
    return result.exit_code, result.output


class TestGeminiCLIHookCommand:
    """Tests for the hook command with --source gemini-cli."""

    def test_valid_source(self) -> None:
        exit_code, _ = _run_hook("gemini-cli", payload=None)
        assert exit_code == 0

    def test_empty_stdin_allows(self) -> None:
        exit_code, _ = _run_hook("gemini-cli", "")
        assert exit_code == 0

    def test_invalid_json_denies(self) -> None:
        exit_code, output = _run_hook("gemini-cli", "not json")
        assert exit_code == 2

    def test_safe_command_allows(self) -> None:
        payload = {
            "tool_name": "run_shell_command",
            "tool_input": {"command": "echo hello"},
            "hook_event_name": "BeforeTool",
        }
        exit_code, _ = _run_hook("gemini-cli", payload)
        assert exit_code == 0

    def test_dangerous_command_denies(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        payload = {
            "tool_name": "run_shell_command",
            "tool_input": {"command": "rm -rf /"},
            "hook_event_name": "BeforeTool",
            "cwd": str(tmp_path),
        }
        exit_code, output = _run_hook("gemini-cli", payload)
        assert exit_code == 2

    def test_safe_file_read_allows(self) -> None:
        payload = {
            "tool_name": "read_file",
            "tool_input": {"file_path": "/tmp/readme.txt"},
            "hook_event_name": "BeforeTool",
        }
        exit_code, _ = _run_hook("gemini-cli", payload)
        assert exit_code == 0


class TestGeminiCLIDenyFormat:
    """Verify Gemini CLI deny output goes to stderr (not stdout JSON)."""

    def test_deny_reason_on_stderr(self, tmp_path, monkeypatch) -> None:
        """Gemini CLI deny should put reason on stderr, not JSON on stdout."""
        monkeypatch.chdir(tmp_path)
        payload = {
            "tool_name": "run_shell_command",
            "tool_input": {"command": "rm -rf /"},
            "hook_event_name": "BeforeTool",
            "cwd": str(tmp_path),
        }
        exit_code, output = _run_hook("gemini-cli", payload)
        assert exit_code == 2
        # CliRunner mixes stderr into output. The output should NOT contain
        # Claude Code style JSON keys like permissionDecision.
        assert "permissionDecision" not in output
        assert "hookEventName" not in output

    def test_escalate_denied_local(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        from unittest.mock import patch

        from vectimus.engine.models import Decision, DecisionVerdict

        escalate_decision = Decision(
            decision=DecisionVerdict.ESCALATE,
            reason="Requires human approval",
            matched_policy_ids=["test-escalate-001"],
        )
        payload = {
            "tool_name": "run_shell_command",
            "tool_input": {"command": "echo test"},
            "hook_event_name": "BeforeTool",
            "cwd": str(tmp_path),
        }
        with patch("vectimus.cli.hook_cmd.PolicyEngine") as mock_engine_cls:
            mock_engine_cls.return_value.evaluate.return_value = escalate_decision
            exit_code, output = _run_hook("gemini-cli", payload)

        assert exit_code == 2
        assert "escalate" in output.lower()


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------


class TestDetectGeminiCLI:
    """Gemini CLI detection tests."""

    def test_found_on_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from vectimus.cli.detect import DetectionMethod, _detect_gemini_cli

        monkeypatch.setattr(
            shutil, "which", lambda name: "/usr/local/bin/gemini" if name == "gemini" else None
        )
        result = _detect_gemini_cli()
        assert result.found is True
        assert result.method == DetectionMethod.PATH
        assert result.executable_path == "/usr/local/bin/gemini"

    def test_found_via_config_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from vectimus.cli.detect import DetectionMethod, _detect_gemini_cli

        monkeypatch.setattr(shutil, "which", lambda name: None)
        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_gemini_cli()
        assert result.found is True
        assert result.method == DetectionMethod.CONFIG_DIR

    def test_not_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from vectimus.cli.detect import _detect_gemini_cli

        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_gemini_cli()
        assert result.found is False
        assert result.method is None

    def test_path_takes_precedence_over_config_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from vectimus.cli.detect import DetectionMethod, _detect_gemini_cli

        monkeypatch.setattr(
            shutil, "which", lambda name: "/usr/local/bin/gemini" if name == "gemini" else None
        )
        (tmp_path / ".gemini").mkdir()
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_gemini_cli()
        assert result.method == DetectionMethod.PATH

    def test_detect_all_includes_gemini(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from vectimus.cli.detect import ToolName, detect_all

        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("vectimus.cli.detect._cursor_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._vscode_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._check_linux_appimage", lambda app: None)
        report = detect_all()
        assert ToolName.GEMINI_CLI in report.results

    def test_detect_tool_single(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from vectimus.cli.detect import ToolName, detect_tool

        monkeypatch.setattr(
            shutil, "which", lambda name: "/bin/gemini" if name == "gemini" else None
        )
        result = detect_tool(ToolName.GEMINI_CLI)
        assert result.found is True


# ---------------------------------------------------------------------------
# Init tests
# ---------------------------------------------------------------------------


class TestConfigureGeminiCLI:
    """Tests for vectimus init Gemini CLI configuration."""

    def test_creates_settings_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        from vectimus.cli.init_cmd import _configure_gemini_cli

        _configure_gemini_cli()
        settings_path = tmp_path / ".gemini" / "settings.json"
        assert settings_path.exists()
        settings = json.loads(settings_path.read_text())
        assert "hooks" in settings
        assert "BeforeTool" in settings["hooks"]
        hooks = settings["hooks"]["BeforeTool"]
        assert len(hooks) >= 1
        assert "vectimus" in hooks[0]["command"]
        assert hooks[0]["matcher"] == ".*"

    def test_preserves_existing_non_vectimus_hooks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        from vectimus.cli.init_cmd import _configure_gemini_cli

        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()
        existing = {
            "hooks": {
                "BeforeTool": [
                    {"command": "my-custom-hook", "matcher": "write_file"}
                ]
            }
        }
        (gemini_dir / "settings.json").write_text(json.dumps(existing))

        _configure_gemini_cli()
        settings = json.loads((gemini_dir / "settings.json").read_text())
        hooks = settings["hooks"]["BeforeTool"]
        assert len(hooks) == 2
        assert "vectimus" in hooks[0]["command"]
        assert hooks[1]["command"] == "my-custom-hook"

    def test_replaces_existing_vectimus_hooks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        from vectimus.cli.init_cmd import _configure_gemini_cli

        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()
        existing = {
            "hooks": {
                "BeforeTool": [
                    {"command": "old-vectimus hook --source gemini-cli", "matcher": ".*"}
                ]
            }
        }
        (gemini_dir / "settings.json").write_text(json.dumps(existing))

        _configure_gemini_cli()
        settings = json.loads((gemini_dir / "settings.json").read_text())
        hooks = settings["hooks"]["BeforeTool"]
        assert len(hooks) == 1
        assert "vectimus" in hooks[0]["command"]

    def test_handles_malformed_existing_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        from vectimus.cli.init_cmd import _configure_gemini_cli

        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()
        (gemini_dir / "settings.json").write_text("not json")

        _configure_gemini_cli()
        settings = json.loads((gemini_dir / "settings.json").read_text())
        assert "BeforeTool" in settings["hooks"]

    def test_preserves_non_hook_settings(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        from vectimus.cli.init_cmd import _configure_gemini_cli

        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()
        existing = {"model": "gemini-2.5-pro", "hooks": {}}
        (gemini_dir / "settings.json").write_text(json.dumps(existing))

        _configure_gemini_cli()
        settings = json.loads((gemini_dir / "settings.json").read_text())
        assert settings["model"] == "gemini-2.5-pro"
        assert "BeforeTool" in settings["hooks"]


# ---------------------------------------------------------------------------
# Remove tests
# ---------------------------------------------------------------------------


class TestRemoveGeminiCLI:
    """Tests for vectimus remove Gemini CLI hook removal."""

    def test_removes_vectimus_hooks(self, tmp_path: Path) -> None:
        from vectimus.cli.remove_cmd import _remove_gemini_cli

        settings_path = tmp_path / "settings.json"
        settings = {
            "hooks": {
                "BeforeTool": [
                    {"command": "vectimus hook --source gemini-cli", "matcher": ".*"}
                ]
            }
        }
        settings_path.write_text(json.dumps(settings))

        _remove_gemini_cli(settings_path)
        result = json.loads(settings_path.read_text()) if settings_path.exists() else {}
        # File should be removed when empty
        assert not settings_path.exists() or "BeforeTool" not in result.get("hooks", {})

    def test_preserves_non_vectimus_hooks(self, tmp_path: Path) -> None:
        from vectimus.cli.remove_cmd import _remove_gemini_cli

        settings_path = tmp_path / "settings.json"
        settings = {
            "hooks": {
                "BeforeTool": [
                    {"command": "vectimus hook --source gemini-cli", "matcher": ".*"},
                    {"command": "my-custom-hook", "matcher": "write_file"},
                ]
            }
        }
        settings_path.write_text(json.dumps(settings))

        _remove_gemini_cli(settings_path)
        result = json.loads(settings_path.read_text())
        hooks = result["hooks"]["BeforeTool"]
        assert len(hooks) == 1
        assert hooks[0]["command"] == "my-custom-hook"

    def test_removes_empty_file(self, tmp_path: Path) -> None:
        from vectimus.cli.remove_cmd import _remove_gemini_cli

        settings_path = tmp_path / "settings.json"
        settings = {
            "hooks": {
                "BeforeTool": [
                    {"command": "vectimus hook --source gemini-cli", "matcher": ".*"}
                ]
            }
        }
        settings_path.write_text(json.dumps(settings))

        _remove_gemini_cli(settings_path)
        assert not settings_path.exists()

    def test_preserves_non_hook_settings(self, tmp_path: Path) -> None:
        from vectimus.cli.remove_cmd import _remove_gemini_cli

        settings_path = tmp_path / "settings.json"
        settings = {
            "model": "gemini-2.5-pro",
            "hooks": {
                "BeforeTool": [
                    {"command": "vectimus hook --source gemini-cli", "matcher": ".*"}
                ]
            },
        }
        settings_path.write_text(json.dumps(settings))

        _remove_gemini_cli(settings_path)
        result = json.loads(settings_path.read_text())
        assert result["model"] == "gemini-2.5-pro"
        assert "hooks" not in result

    def test_has_vectimus_hooks_gemini(self, tmp_path: Path) -> None:
        from vectimus.cli.remove_cmd import _has_vectimus_hooks_gemini

        settings_path = tmp_path / "settings.json"
        settings = {
            "hooks": {
                "BeforeTool": [
                    {"command": "vectimus hook --source gemini-cli", "matcher": ".*"}
                ]
            }
        }
        settings_path.write_text(json.dumps(settings))
        assert _has_vectimus_hooks_gemini(settings_path) is True

    def test_has_vectimus_hooks_gemini_false(self, tmp_path: Path) -> None:
        from vectimus.cli.remove_cmd import _has_vectimus_hooks_gemini

        settings_path = tmp_path / "settings.json"
        settings = {
            "hooks": {
                "BeforeTool": [
                    {"command": "my-custom-hook", "matcher": ".*"}
                ]
            }
        }
        settings_path.write_text(json.dumps(settings))
        assert _has_vectimus_hooks_gemini(settings_path) is False
