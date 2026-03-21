"""Tests for the OpenCode adapter, hook command, detection and init."""

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


class TestOpenCodeNormaliser:
    """Tests for OpenCode payload normalisation."""

    def test_bash_command(self) -> None:
        payload = {
            "tool_name": "bash",
            "tool_input": {"command": "ls -la"},
            "hook_event_name": "PreToolUse",
            "session_id": "oc-123",
            "cwd": "/home/user/project",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.SHELL_COMMAND
        assert event.action.command == "ls -la"
        assert event.source.tool == "opencode"
        assert event.source.session_id == "oc-123"
        assert event.context.cwd == "/home/user/project"
        assert event.event_type == EventType.PRE_ACTION

    def test_file_write(self) -> None:
        payload = {
            "tool_name": "write",
            "tool_input": {"filePath": "src/main.py", "content": "print('hello')"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.FILE_WRITE
        assert event.action.file_path == "src/main.py"
        assert event.action.file_content == "print('hello')"

    def test_file_edit(self) -> None:
        payload = {
            "tool_name": "edit",
            "tool_input": {
                "filePath": "src/app.py",
                "old_string": "pass",
                "new_string": "return 42",
            },
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.FILE_WRITE
        assert event.action.file_path == "src/app.py"
        assert event.action.file_content == "return 42"

    def test_file_patch(self) -> None:
        payload = {
            "tool_name": "patch",
            "tool_input": {"filePath": "lib/utils.py", "patch": "--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.FILE_WRITE
        assert event.action.file_path == "lib/utils.py"

    def test_file_read(self) -> None:
        payload = {
            "tool_name": "read",
            "tool_input": {"filePath": "README.md"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.FILE_READ
        assert event.action.file_path == "README.md"

    def test_grep(self) -> None:
        payload = {
            "tool_name": "grep",
            "tool_input": {"pattern": "TODO"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.FILE_READ
        assert event.action.raw_tool_name == "grep"

    def test_find(self) -> None:
        payload = {
            "tool_name": "find",
            "tool_input": {"pattern": "*.py"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.FILE_READ

    def test_ls(self) -> None:
        payload = {
            "tool_name": "ls",
            "tool_input": {"path": "/home/user"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.FILE_READ

    def test_webfetch(self) -> None:
        payload = {
            "tool_name": "webfetch",
            "tool_input": {"url": "https://example.com"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.WEB_REQUEST
        assert event.action.url == "https://example.com"

    def test_terraform_detected_as_infrastructure(self) -> None:
        payload = {
            "tool_name": "bash",
            "tool_input": {"command": "terraform plan"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.INFRASTRUCTURE

    def test_npm_detected_as_package_operation(self) -> None:
        payload = {
            "tool_name": "bash",
            "tool_input": {"command": "npm install express"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.PACKAGE_OPERATION

    def test_git_detected_as_git_operation(self) -> None:
        payload = {
            "tool_name": "bash",
            "tool_input": {"command": "git push origin main"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.GIT_OPERATION

    def test_mcp_tool_detection(self) -> None:
        payload = {
            "tool_name": "mcp_github_create_issue",
            "tool_input": {"title": "Bug report"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.MCP_TOOL
        assert event.action.mcp_server == "github"
        assert event.action.mcp_tool == "create_issue"

    def test_mcp_tool_no_tool_name(self) -> None:
        payload = {
            "tool_name": "mcp_sentry",
            "tool_input": {},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.MCP_TOOL
        assert event.action.mcp_server == "sentry"
        assert event.action.mcp_tool is None

    def test_unknown_tool_defaults_to_shell(self) -> None:
        payload = {
            "tool_name": "some_new_tool",
            "tool_input": {},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.action.action_type == ActionType.SHELL_COMMAND
        assert event.action.raw_tool_name == "some_new_tool"

    def test_missing_fields_handled(self) -> None:
        payload = {}
        event = normalise(payload, "opencode")
        assert event.action.raw_tool_name == "unknown"
        assert event.source.tool == "opencode"

    def test_default_principal(self) -> None:
        payload = {
            "tool_name": "read",
            "tool_input": {},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "opencode")
        assert event.identity.principal is not None
        assert isinstance(event.identity.principal, str)

    def test_custom_principal(self) -> None:
        payload = {
            "tool_name": "read",
            "tool_input": {},
            "hook_event_name": "PreToolUse",
            "principal": "alice",
        }
        event = normalise(payload, "opencode")
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


def _parse_json_output(output: str) -> dict:
    """Extract the JSON object from mixed stdout/stderr CliRunner output."""
    for line in output.strip().split(chr(10)):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    raise ValueError(f"No JSON found in output: {output!r}")


class TestOpenCodeHookCommand:
    """Tests for the hook command with --source opencode."""

    def test_valid_source(self) -> None:
        exit_code, _ = _run_hook("opencode", payload=None)
        assert exit_code == 0

    def test_empty_stdin_allows(self) -> None:
        exit_code, _ = _run_hook("opencode", "")
        assert exit_code == 0

    def test_invalid_json_denies(self) -> None:
        """Invalid JSON causes fail-closed; for opencode this exits 0 with deny JSON."""
        exit_code, output = _run_hook("opencode", "not json")
        assert exit_code == 0
        parsed = _parse_json_output(output)
        assert parsed["decision"] == "deny"

    def test_safe_command_allows(self) -> None:
        payload = {
            "tool_name": "bash",
            "tool_input": {"command": "echo hello"},
            "hook_event_name": "PreToolUse",
        }
        exit_code, _ = _run_hook("opencode", payload)
        assert exit_code == 0

    def test_dangerous_command_denies(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        payload = {
            "tool_name": "bash",
            "tool_input": {"command": "rm -rf /"},
            "hook_event_name": "PreToolUse",
            "cwd": str(tmp_path),
        }
        exit_code, output = _run_hook("opencode", payload)
        # OpenCode deny uses exit 0 with JSON decision (same as Gemini CLI).
        assert exit_code == 0
        parsed = _parse_json_output(output)
        assert parsed["decision"] == "deny"

    def test_safe_file_read_allows(self) -> None:
        payload = {
            "tool_name": "read",
            "tool_input": {"filePath": "/tmp/readme.txt"},
            "hook_event_name": "PreToolUse",
        }
        exit_code, _ = _run_hook("opencode", payload)
        assert exit_code == 0


class TestOpenCodeDenyFormat:
    """Verify OpenCode deny output is JSON on stdout with exit 0."""

    def test_deny_json_on_stdout(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        payload = {
            "tool_name": "bash",
            "tool_input": {"command": "rm -rf /"},
            "hook_event_name": "PreToolUse",
            "cwd": str(tmp_path),
        }
        exit_code, output = _run_hook("opencode", payload)
        assert exit_code == 0
        parsed = _parse_json_output(output)
        assert parsed["decision"] == "deny"
        assert "reason" in parsed
        # Should NOT contain Claude Code style JSON keys.
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
            "tool_name": "bash",
            "tool_input": {"command": "echo test"},
            "hook_event_name": "PreToolUse",
            "cwd": str(tmp_path),
        }
        with patch("vectimus.cli.hook_cmd.PolicyEngine") as mock_engine_cls:
            mock_engine_cls.return_value.evaluate.return_value = escalate_decision
            exit_code, output = _run_hook("opencode", payload)

        assert exit_code == 0
        parsed = _parse_json_output(output)
        assert parsed["decision"] == "deny"
        assert "escalate" in parsed["reason"].lower()


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------


class TestDetectOpenCode:
    """OpenCode detection tests."""

    def test_found_on_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from vectimus.cli.detect import DetectionMethod, _detect_opencode

        monkeypatch.setattr(
            shutil, "which", lambda name: "/usr/local/bin/opencode" if name == "opencode" else None
        )
        result = _detect_opencode()
        assert result.found is True
        assert result.method == DetectionMethod.PATH
        assert result.executable_path == "/usr/local/bin/opencode"

    def test_found_via_project_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from vectimus.cli.detect import DetectionMethod, _detect_opencode

        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.chdir(tmp_path)
        (tmp_path / "opencode.json").write_text("{}")
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_opencode()
        assert result.found is True
        assert result.method == DetectionMethod.CONFIG_DIR

    def test_found_via_opencode_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from vectimus.cli.detect import DetectionMethod, _detect_opencode

        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".opencode").mkdir()
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_opencode()
        assert result.found is True
        assert result.method == DetectionMethod.CONFIG_DIR

    def test_found_via_global_config_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from vectimus.cli.detect import DetectionMethod, _detect_opencode

        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.chdir(tmp_path)
        config_dir = tmp_path / ".config" / "opencode"
        config_dir.mkdir(parents=True)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_opencode()
        assert result.found is True
        assert result.method == DetectionMethod.CONFIG_DIR

    def test_not_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from vectimus.cli.detect import _detect_opencode

        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_opencode()
        assert result.found is False
        assert result.method is None

    def test_path_takes_precedence(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from vectimus.cli.detect import DetectionMethod, _detect_opencode

        monkeypatch.setattr(
            shutil, "which", lambda name: "/usr/local/bin/opencode" if name == "opencode" else None
        )
        monkeypatch.chdir(tmp_path)
        (tmp_path / "opencode.json").write_text("{}")
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_opencode()
        assert result.method == DetectionMethod.PATH

    def test_detect_all_includes_opencode(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from vectimus.cli.detect import ToolName, detect_all

        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("vectimus.cli.detect._cursor_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._vscode_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._check_linux_appimage", lambda app: None)
        report = detect_all()
        assert ToolName.OPENCODE in report.results

    def test_detect_tool_single(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from vectimus.cli.detect import ToolName, detect_tool

        monkeypatch.setattr(
            shutil, "which", lambda name: "/bin/opencode" if name == "opencode" else None
        )
        result = detect_tool(ToolName.OPENCODE)
        assert result.found is True


# ---------------------------------------------------------------------------
# Init tests
# ---------------------------------------------------------------------------


class TestConfigureOpenCode:
    """Tests for vectimus init OpenCode configuration."""

    def test_creates_plugin_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        from vectimus.cli.init_cmd import _configure_opencode

        _configure_opencode()
        plugin_path = tmp_path / ".opencode" / "plugins" / "vectimus.ts"
        assert plugin_path.exists()
        content = plugin_path.read_text()
        assert "VectimusPlugin" in content
        assert "vectimus" in content
        assert "tool.execute.before" in content

    def test_overwrites_existing_plugin(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        from vectimus.cli.init_cmd import _configure_opencode

        plugins_dir = tmp_path / ".opencode" / "plugins"
        plugins_dir.mkdir(parents=True)
        (plugins_dir / "vectimus.ts").write_text("// old content")

        _configure_opencode()
        content = (plugins_dir / "vectimus.ts").read_text()
        assert "VectimusPlugin" in content
        assert "old content" not in content

    def test_preserves_other_plugins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        from vectimus.cli.init_cmd import _configure_opencode

        plugins_dir = tmp_path / ".opencode" / "plugins"
        plugins_dir.mkdir(parents=True)
        (plugins_dir / "other.ts").write_text("// custom plugin")

        _configure_opencode()
        assert (plugins_dir / "other.ts").read_text() == "// custom plugin"
        assert (plugins_dir / "vectimus.ts").exists()

    def test_plugin_contains_opencode_source(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        from vectimus.cli.init_cmd import _configure_opencode

        _configure_opencode()
        content = (tmp_path / ".opencode" / "plugins" / "vectimus.ts").read_text()
        assert "--source opencode" in content
