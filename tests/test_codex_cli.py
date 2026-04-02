"""Tests for the Codex CLI adapter, hook command and init/remove helpers."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner

from vectimus.cli.hook_cmd import hook_cmd
from vectimus.engine.models import ActionType, EventType
from vectimus.engine.normaliser import normalise


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
    for line in output.strip().splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    raise ValueError(f"No JSON found in output: {output!r}")


class TestCodexNormaliser:
    """Tests for Codex CLI payload normalisation."""

    def test_shell_command(self) -> None:
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "hook_event_name": "PreToolUse",
            "session_id": "codex-session",
            "cwd": "/tmp/project",
        }
        event = normalise(payload, "codex")
        assert event.action.action_type == ActionType.SHELL_COMMAND
        assert event.action.command == "ls -la"
        assert event.source.tool == "codex"
        assert event.source.session_id == "codex-session"
        assert event.context.cwd == "/tmp/project"
        assert event.event_type == EventType.PRE_ACTION

    def test_infrastructure_detection(self) -> None:
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "terraform plan"},
            "hook_event_name": "PreToolUse",
        }
        event = normalise(payload, "codex")
        assert event.action.action_type == ActionType.INFRASTRUCTURE


class TestCodexHookCommand:
    """Tests for the hook command with --source codex."""

    def test_safe_command_allows(self) -> None:
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
            "hook_event_name": "PreToolUse",
        }
        exit_code, output = _run_hook("codex", payload)
        assert exit_code == 0
        assert "permissionDecision" not in output

    def test_dangerous_command_denies(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "hook_event_name": "PreToolUse",
            "cwd": str(tmp_path),
        }
        exit_code, output = _run_hook("codex", payload)
        assert exit_code == 0
        parsed = _parse_json_output(output)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert parsed["hookSpecificOutput"]["hookEventName"] == "PreToolUse"

    def test_non_pretooluse_event_noops(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "hook_event_name": "PostToolUse",
            "cwd": str(tmp_path),
        }
        exit_code, output = _run_hook("codex", payload)
        assert exit_code == 0
        assert output == ""


class TestConfigureCodexCLI:
    """Tests for vectimus init Codex CLI configuration."""

    def test_creates_hooks_and_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        from vectimus.cli.init_cmd import _configure_codex_cli

        _configure_codex_cli()

        hooks_path = tmp_path / ".codex" / "hooks.json"
        config_path = tmp_path / ".codex" / "config.toml"
        assert hooks_path.exists()
        assert config_path.exists()

        hooks = json.loads(hooks_path.read_text())
        entries = hooks["hooks"]["PreToolUse"]
        assert entries[0]["matcher"] == "Bash"
        assert entries[0]["hooks"][0]["type"] == "command"
        assert "vectimus hook --source codex" in entries[0]["hooks"][0]["command"]

        with open(config_path, "rb") as f:
            config = tomllib.load(f)
        assert config["features"]["codex_hooks"] is True

    def test_preserves_non_vectimus_hooks_and_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        from vectimus.cli.init_cmd import _configure_codex_cli

        codex_dir = tmp_path / ".codex"
        codex_dir.mkdir()
        existing_hooks = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "custom-hook"}],
                    }
                ]
            }
        }
        (codex_dir / "hooks.json").write_text(json.dumps(existing_hooks))
        (codex_dir / "config.toml").write_text("[features]\nother_flag = true\n")

        _configure_codex_cli()

        hooks = json.loads((codex_dir / "hooks.json").read_text())
        entries = hooks["hooks"]["PreToolUse"]
        assert len(entries) == 2
        assert "vectimus hook --source codex" in entries[0]["hooks"][0]["command"]
        assert entries[1]["hooks"][0]["command"] == "custom-hook"

        with open(codex_dir / "config.toml", "rb") as f:
            config = tomllib.load(f)
        assert config["features"]["codex_hooks"] is True
        assert config["features"]["other_flag"] is True

    def test_invalid_codex_config_is_not_overwritten(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.chdir(tmp_path)
        from vectimus.cli.init_cmd import _configure_codex_cli

        codex_dir = tmp_path / ".codex"
        codex_dir.mkdir()
        config_path = codex_dir / "config.toml"
        config_path.write_text("not = [valid")

        _configure_codex_cli()

        captured = capsys.readouterr()
        assert "invalid TOML" in captured.err
        assert config_path.read_text() == "not = [valid"

    def test_warns_when_global_vectimus_hook_exists(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        from vectimus.cli.init_cmd import _configure_codex_cli

        user_codex = tmp_path / ".codex"
        user_codex.mkdir()
        global_hooks = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "vectimus hook --source codex"}],
                    }
                ]
            }
        }
        (user_codex / "hooks.json").write_text(json.dumps(global_hooks))

        project = tmp_path / "project"
        project.mkdir()
        monkeypatch.chdir(project)

        _configure_codex_cli()

        captured = capsys.readouterr()
        assert "already contains a Vectimus Codex hook" in captured.out


class TestRemoveCodexCLI:
    """Tests for vectimus remove Codex CLI hook removal."""

    def test_removes_vectimus_hooks(self, tmp_path: Path) -> None:
        from vectimus.cli.remove_cmd import _remove_codex_cli

        hooks_path = tmp_path / "hooks.json"
        hooks = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "vectimus hook --source codex"}],
                    }
                ]
            }
        }
        hooks_path.write_text(json.dumps(hooks))

        _remove_codex_cli(hooks_path)
        assert not hooks_path.exists()

    def test_preserves_non_vectimus_hooks(self, tmp_path: Path) -> None:
        from vectimus.cli.remove_cmd import _has_vectimus_hooks_codex, _remove_codex_cli

        hooks_path = tmp_path / "hooks.json"
        hooks = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "vectimus hook --source codex"}],
                    },
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "custom-hook"}],
                    },
                ]
            }
        }
        hooks_path.write_text(json.dumps(hooks))
        assert _has_vectimus_hooks_codex(hooks_path) is True

        _remove_codex_cli(hooks_path)

        result = json.loads(hooks_path.read_text())
        entries = result["hooks"]["PreToolUse"]
        assert len(entries) == 1
        assert entries[0]["hooks"][0]["command"] == "custom-hook"
