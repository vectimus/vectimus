"""Tests for the ``vectimus hook`` CLI command."""

from __future__ import annotations

import json

from click.testing import CliRunner

from vectimus.cli.hook_cmd import hook_cmd


def _run_hook(source: str, payload: dict | str | None = None) -> tuple[int, str]:
    """Invoke the hook command with the given source and optional stdin payload.

    Returns (exit_code, stdout).
    """
    runner = CliRunner()
    if payload is None:
        stdin = ""
    elif isinstance(payload, dict):
        stdin = json.dumps(payload)
    else:
        stdin = payload
    result = runner.invoke(hook_cmd, ["--source", source], input=stdin)
    return result.exit_code, result.output


class TestSourceValidation:
    """Test --source argument validation."""

    def test_missing_source(self) -> None:
        runner = CliRunner()
        result = runner.invoke(hook_cmd, [])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_invalid_source(self) -> None:
        runner = CliRunner()
        result = runner.invoke(hook_cmd, ["--source", "invalid-tool"])
        assert result.exit_code != 0

    def test_valid_sources(self) -> None:
        for source in ("claude-code", "cursor", "copilot"):
            exit_code, _ = _run_hook(source, payload=None)
            # Empty stdin should allow (exit 0)
            assert exit_code == 0, f"Expected exit 0 for empty stdin with --source {source}"


class TestEmptyStdin:
    """Empty stdin should always allow."""

    def test_empty_stdin_allows(self) -> None:
        exit_code, output = _run_hook("claude-code", "")
        assert exit_code == 0

    def test_whitespace_only_allows(self) -> None:
        exit_code, output = _run_hook("cursor", "   \n  ")
        assert exit_code == 0


class TestInvalidJson:
    """Invalid JSON should fail closed (deny)."""

    def test_invalid_json_claude_code(self) -> None:
        exit_code, output = _run_hook("claude-code", "not json")
        assert exit_code == 2
        # Output contains deny JSON (may also contain structlog lines)
        assert '"permissionDecision": "deny"' in output

    def test_invalid_json_cursor(self) -> None:
        exit_code, output = _run_hook("cursor", "{broken")
        assert exit_code == 2
        assert '"permission": "deny"' in output

    def test_invalid_json_copilot(self) -> None:
        exit_code, output = _run_hook("copilot", "<<<")
        assert exit_code == 2
        assert '"permissionDecision": "deny"' in output


class TestDenyOutputFormat:
    """Verify tool-specific deny output formats.

    Uses tmp_path to avoid project-local disabled rules affecting results.
    """

    @staticmethod
    def _extract_json(output: str) -> dict:
        """Extract the JSON object from output that may contain log lines."""
        for line in output.strip().splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        raise ValueError(f"No JSON found in output: {output!r}")

    def test_claude_code_deny_format(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "hook_event_name": "PreToolUse",
            "cwd": str(tmp_path),
        }
        exit_code, output = _run_hook("claude-code", payload)
        assert exit_code == 2
        result = self._extract_json(output)
        assert result["permissionDecision"] == "deny"
        assert "hookEventName" in result
        assert "permissionDecisionReason" in result

    def test_cursor_deny_format(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        payload = {
            "command": "rm -rf /",
            "hook_event_name": "beforeShellExecution",
            "cwd": str(tmp_path),
        }
        exit_code, output = _run_hook("cursor", payload)
        assert exit_code == 2
        result = self._extract_json(output)
        assert result["permission"] == "deny"
        assert "user_message" in result
        assert "agent_message" in result

    def test_copilot_deny_format(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "hookEventName": "PreToolUse",
            "cwd": str(tmp_path),
        }
        exit_code, output = _run_hook("copilot", payload)
        assert exit_code == 2
        result = self._extract_json(output)
        assert result["permissionDecision"] == "deny"
        assert "hookEventName" in result


class TestAllowBehaviour:
    """Safe commands should be allowed."""

    def test_safe_command_claude_code(self) -> None:
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
            "hook_event_name": "PreToolUse",
        }
        exit_code, _ = _run_hook("claude-code", payload)
        assert exit_code == 0

    def test_safe_command_cursor(self) -> None:
        payload = {
            "command": "ls -la",
            "hook_event_name": "beforeShellExecution",
            "cwd": "/tmp",
        }
        exit_code, _ = _run_hook("cursor", payload)
        assert exit_code == 0

    def test_safe_command_copilot(self) -> None:
        payload = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/readme.txt"},
            "hookEventName": "PreToolUse",
        }
        exit_code, _ = _run_hook("copilot", payload)
        assert exit_code == 0


class TestDebugMode:
    """VECTIMUS_DEBUG should produce stderr diagnostics."""

    def test_debug_logs_payload(self, monkeypatch) -> None:
        monkeypatch.setenv("VECTIMUS_DEBUG", "1")
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
            "hook_event_name": "PreToolUse",
        }
        exit_code, output = _run_hook("claude-code", payload)
        # Debug writes to stderr which CliRunner mixes into output
        assert exit_code == 0
        assert "vectimus:" in output

    def test_debug_empty_stdin(self, monkeypatch) -> None:
        monkeypatch.setenv("VECTIMUS_DEBUG", "1")
        exit_code, output = _run_hook("cursor", "")
        assert exit_code == 0
        assert "empty stdin" in output
