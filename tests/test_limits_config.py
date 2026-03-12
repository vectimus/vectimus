"""Tests for configurable limits and thresholds (Phase 3)."""

from __future__ import annotations

from pathlib import Path

import pytest
import tomli_w

from vectimus.engine.config import VectimusConfig


@pytest.fixture()
def config_path(tmp_path: Path) -> str:
    return str(tmp_path / "config.toml")


class TestContentInspectionMaxLines:
    def test_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.get_content_inspection_max_lines() == 5000

    def test_from_config(self, config_path: str) -> None:
        path = Path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            tomli_w.dump({"limits": {"content_inspection_max_lines": 10000}}, f)
        cfg = VectimusConfig(config_path)
        assert cfg.get_content_inspection_max_lines() == 10000

    def test_env_override(self, config_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = VectimusConfig(config_path)
        monkeypatch.setenv("VECTIMUS_CONTENT_MAX_LINES", "2000")
        assert cfg.get_content_inspection_max_lines() == 2000


class TestExcessiveTurnsThreshold:
    def test_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.get_excessive_turns_threshold() == 50

    def test_from_config(self, config_path: str) -> None:
        path = Path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            tomli_w.dump({"limits": {"excessive_turns_threshold": 100}}, f)
        cfg = VectimusConfig(config_path)
        assert cfg.get_excessive_turns_threshold() == 100

    def test_env_override(self, config_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = VectimusConfig(config_path)
        monkeypatch.setenv("VECTIMUS_EXCESSIVE_TURNS", "25")
        assert cfg.get_excessive_turns_threshold() == 25


class TestGitTimeoutSeconds:
    def test_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.get_git_timeout_seconds() == 5

    def test_env_override(self, config_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = VectimusConfig(config_path)
        monkeypatch.setenv("VECTIMUS_GIT_TIMEOUT", "10")
        assert cfg.get_git_timeout_seconds() == 10


class TestSessionLimits:
    def test_spawn_limit_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.get_session_spawn_limit() == 10

    def test_message_limit_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.get_session_message_limit() == 50

    def test_ttl_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.get_session_ttl_seconds() == 3600


class TestAuditConfig:
    def test_max_file_size_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.get_audit_max_file_size_mb() == 100

    def test_log_dir_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert ".vectimus" in cfg.get_audit_log_dir()

    def test_max_file_size_env_override(
        self, config_path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = VectimusConfig(config_path)
        monkeypatch.setenv("VECTIMUS_AUDIT_MAX_MB", "50")
        assert cfg.get_audit_max_file_size_mb() == 50

    def test_log_dir_env_override(self, config_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = VectimusConfig(config_path)
        monkeypatch.setenv("VECTIMUS_LOG_DIR", "/custom/logs")
        assert cfg.get_audit_log_dir() == "/custom/logs"


class TestCustomAuditRotationSize:
    """Test that JsonlExporter respects custom max file size."""

    def test_custom_rotation_size(self, tmp_path: Path) -> None:
        from vectimus.exporters.jsonl import JsonlExporter

        exporter = JsonlExporter(log_dir=tmp_path, max_file_size_mb=1)
        assert exporter._max_file_bytes == 1 * 1024 * 1024

    def test_env_rotation_size(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from vectimus.exporters.jsonl import JsonlExporter

        monkeypatch.setenv("VECTIMUS_AUDIT_MAX_MB", "2")
        exporter = JsonlExporter(log_dir=tmp_path)
        assert exporter._max_file_bytes == 2 * 1024 * 1024

    def test_explicit_arg_takes_precedence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from vectimus.exporters.jsonl import JsonlExporter

        monkeypatch.setenv("VECTIMUS_AUDIT_MAX_MB", "99")
        exporter = JsonlExporter(log_dir=tmp_path, max_file_size_mb=5)
        assert exporter._max_file_bytes == 5 * 1024 * 1024
