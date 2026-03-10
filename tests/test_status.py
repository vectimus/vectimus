"""Tests for the vectimus status CLI command."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from vectimus.cli.status_cmd import (
    _check_claude_code,
    _check_copilot,
    _check_cursor,
    _read_audit_stats,
    status_cmd,
)


class TestToolDetection:
    """Test hook config detection for each tool."""

    def test_claude_code_detected(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        config_dir = tmp_path / ".claude"
        config_dir.mkdir()
        settings = {
            "hooks": {
                "PreToolUse": [{"matcher": "", "hooks": [{"type": "command"}]}],
            },
        }
        (config_dir / "settings.json").write_text(json.dumps(settings))
        assert _check_claude_code() is not None

    def test_claude_code_not_configured(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        assert _check_claude_code() is None

    def test_cursor_detected(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        config_dir = tmp_path / ".cursor"
        config_dir.mkdir()
        hooks = {"beforeShellExecution": {"command": "python -m vectimus.shims.cursor"}}
        (config_dir / "hooks.json").write_text(json.dumps(hooks))
        assert _check_cursor() is not None

    def test_cursor_not_configured(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        assert _check_cursor() is None

    def test_copilot_detected(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        config_dir = tmp_path / ".github" / "hooks"
        config_dir.mkdir(parents=True)
        config = {"PreToolUse": {"command": "python -m vectimus.shims.copilot"}}
        (config_dir / "vectimus.json").write_text(json.dumps(config))
        assert _check_copilot() is not None

    def test_copilot_not_configured(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        assert _check_copilot() is None


class TestAuditStats:
    """Test audit log reading."""

    def test_empty_dir(self, tmp_path: Path) -> None:
        stats = _read_audit_stats(tmp_path)
        assert stats["total"] == 0
        assert stats["last_evaluation"] == "never"

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        stats = _read_audit_stats(tmp_path / "nonexistent")
        assert stats["total"] == 0

    def test_reads_audit_records(self, tmp_path: Path) -> None:
        records = [
            {"decision": {"decision": "allow"}, "recorded_at": "2026-03-09T10:00:00Z"},
            {"decision": {"decision": "deny"}, "recorded_at": "2026-03-09T10:01:00Z"},
            {"decision": {"decision": "allow"}, "recorded_at": "2026-03-09T10:02:00Z"},
        ]
        log_file = tmp_path / "audit-2026-03-09.jsonl"
        log_file.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        stats = _read_audit_stats(tmp_path)
        assert stats["total"] == 3
        assert stats["allow"] == 2
        assert stats["deny"] == 1
        assert stats["last_evaluation"] == "2026-03-09T10:02:00Z"


class TestStatusCommand:
    """Test the full status CLI command."""

    def test_runs_without_error(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(status_cmd, ["--log-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "Vectimus status" in result.output
        assert "Policies:" in result.output

    def test_shows_policy_count(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(status_cmd, ["--log-dir", str(tmp_path)])
        assert "active rule(s)" in result.output

    def test_shows_no_evaluations_when_empty(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(status_cmd, ["--log-dir", str(tmp_path)])
        assert "No evaluations recorded yet" in result.output
