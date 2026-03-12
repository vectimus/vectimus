"""Tests for cross-platform tool detection."""

from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from vectimus.cli.detect import (
    DetectionMethod,
    ToolName,
    _check_copilot_extension,
    _detect_claude_code,
    _detect_cursor,
    _detect_vscode,
    detect_all,
    detect_tool,
)

# ---------------------------------------------------------------------------
# Claude Code detection
# ---------------------------------------------------------------------------


class TestDetectClaudeCode:
    """Claude Code detection tests."""

    def test_found_on_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            shutil, "which", lambda name: "/usr/local/bin/claude" if name == "claude" else None
        )
        result = _detect_claude_code()
        assert result.found is True
        assert result.method == DetectionMethod.PATH
        assert result.executable_path == "/usr/local/bin/claude"

    def test_found_via_config_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_claude_code()
        assert result.found is True
        assert result.method == DetectionMethod.CONFIG_DIR

    def test_not_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_claude_code()
        assert result.found is False
        assert result.method is None

    def test_path_takes_precedence_over_config_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When both PATH and config dir exist, PATH wins."""
        monkeypatch.setattr(
            shutil, "which", lambda name: "/usr/local/bin/claude" if name == "claude" else None
        )
        (tmp_path / ".claude").mkdir()
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_claude_code()
        assert result.method == DetectionMethod.PATH


# ---------------------------------------------------------------------------
# Cursor detection
# ---------------------------------------------------------------------------


class TestDetectCursor:
    """Cursor detection tests."""

    def test_found_on_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            shutil, "which", lambda name: "/usr/local/bin/cursor" if name == "cursor" else None
        )
        result = _detect_cursor()
        assert result.found is True
        assert result.method == DetectionMethod.PATH

    def test_found_at_known_location(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        binary = tmp_path / "Cursor"
        binary.touch()
        monkeypatch.setattr("vectimus.cli.detect._cursor_known_locations", lambda: [binary])
        # Prevent Linux AppImage scan from interfering.
        monkeypatch.setattr("vectimus.cli.detect._check_linux_appimage", lambda app: None)
        result = _detect_cursor()
        assert result.found is True
        assert result.method == DetectionMethod.KNOWN_LOCATION
        assert result.executable_path == str(binary)

    def test_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr("vectimus.cli.detect._cursor_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._check_linux_appimage", lambda app: None)
        result = _detect_cursor()
        assert result.found is False

    def test_appimage_found_on_linux(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr("vectimus.cli.detect._cursor_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect.sys", type("sys", (), {"platform": "linux"})())
        appimage = tmp_path / "Cursor-0.50.AppImage"
        appimage.touch()
        monkeypatch.setattr("vectimus.cli.detect._check_linux_appimage", lambda app: appimage)
        result = _detect_cursor()
        assert result.found is True
        assert result.method == DetectionMethod.KNOWN_LOCATION
        assert "AppImage" in result.details


# ---------------------------------------------------------------------------
# VS Code / Copilot detection
# ---------------------------------------------------------------------------


class TestDetectVSCode:
    """VS Code and Copilot extension detection."""

    def test_found_on_path_with_copilot(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            shutil, "which", lambda name: "/usr/local/bin/code" if name == "code" else None
        )
        extensions_dir = tmp_path / ".vscode" / "extensions"
        extensions_dir.mkdir(parents=True)
        (extensions_dir / "github.copilot-1.234.567").mkdir()
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_vscode()
        assert result.found is True
        assert result.has_copilot_extension is True

    def test_found_on_path_without_copilot(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            shutil, "which", lambda name: "/usr/local/bin/code" if name == "code" else None
        )
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_vscode()
        assert result.found is True
        assert result.has_copilot_extension is False

    def test_found_at_known_location(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        binary = tmp_path / "code"
        binary.touch()
        monkeypatch.setattr("vectimus.cli.detect._vscode_known_locations", lambda: [binary])
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_vscode()
        assert result.found is True
        assert result.method == DetectionMethod.KNOWN_LOCATION

    def test_not_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr("vectimus.cli.detect._vscode_known_locations", lambda: [])
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = _detect_vscode()
        assert result.found is False


# ---------------------------------------------------------------------------
# Copilot extension check
# ---------------------------------------------------------------------------


class TestCopilotExtension:
    """Copilot extension detection in ~/.vscode/extensions/."""

    def test_extension_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        extensions_dir = tmp_path / ".vscode" / "extensions"
        extensions_dir.mkdir(parents=True)
        (extensions_dir / "github.copilot-1.234.567").mkdir()
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert _check_copilot_extension() is True

    def test_extension_absent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert _check_copilot_extension() is False

    def test_other_extensions_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        extensions_dir = tmp_path / ".vscode" / "extensions"
        extensions_dir.mkdir(parents=True)
        (extensions_dir / "ms-python.python-2024.1.0").mkdir()
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert _check_copilot_extension() is False


# ---------------------------------------------------------------------------
# detect_all() integration
# ---------------------------------------------------------------------------


class TestDetectAll:
    """Integration tests for the full detection pipeline."""

    def test_returns_all_tools(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("vectimus.cli.detect._cursor_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._vscode_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._check_linux_appimage", lambda app: None)
        report = detect_all()
        assert len(report.results) == 4
        assert ToolName.CLAUDE_CODE in report.results
        assert ToolName.CURSOR in report.results
        assert ToolName.COPILOT in report.results
        assert ToolName.GEMINI_CLI in report.results

    def test_tools_found_property(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            shutil, "which", lambda name: "/bin/claude" if name == "claude" else None
        )
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("vectimus.cli.detect._cursor_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._vscode_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._check_linux_appimage", lambda app: None)
        report = detect_all()
        found_names = [r.tool for r in report.tools_found]
        assert ToolName.CLAUDE_CODE in found_names
        assert ToolName.CURSOR not in found_names

    def test_tools_not_found_property(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("vectimus.cli.detect._cursor_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._vscode_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._check_linux_appimage", lambda app: None)
        report = detect_all()
        assert len(report.tools_not_found) == 4

    def test_platform_is_set(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("vectimus.cli.detect._cursor_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._vscode_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._check_linux_appimage", lambda app: None)
        report = detect_all()
        assert report.platform in ("darwin", "win32", "linux")


# ---------------------------------------------------------------------------
# detect_tool() single-tool API
# ---------------------------------------------------------------------------


class TestDetectTool:
    """Test the single-tool detection API."""

    def test_detect_single_tool(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            shutil, "which", lambda name: "/bin/claude" if name == "claude" else None
        )
        result = detect_tool(ToolName.CLAUDE_CODE)
        assert result.found is True
        assert result.tool == ToolName.CLAUDE_CODE


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------


class TestDetectionPerformance:
    """Detection must complete within the 2-second budget."""

    def test_completes_in_under_two_seconds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("vectimus.cli.detect._cursor_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._vscode_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._check_linux_appimage", lambda app: None)
        start = time.perf_counter()
        detect_all()
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, f"Detection took {elapsed:.2f}s, budget is 2s"
