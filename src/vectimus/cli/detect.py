"""Cross-platform detection of AI coding tools.

Detects Claude Code, Cursor and VS Code/Copilot across Windows, macOS and
Linux.  Checks PATH first for speed, then falls back to known installation
directories and config directories per platform.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class ToolName(StrEnum):
    """Canonical names for supported tools."""

    CLAUDE_CODE = "claude-code"
    CURSOR = "cursor"
    COPILOT = "copilot"
    GEMINI_CLI = "gemini-cli"
    OPENCODE = "opencode"


class DetectionMethod(StrEnum):
    """How a tool was found."""

    PATH = "path"
    KNOWN_LOCATION = "known"
    CONFIG_DIR = "config"
    EXTENSION = "extension"


@dataclass
class ToolDetectionResult:
    """Result of attempting to detect a single tool."""

    tool: ToolName
    found: bool = False
    executable_path: str | None = None
    method: DetectionMethod | None = None
    details: str = ""
    has_copilot_extension: bool = False


@dataclass
class DetectionReport:
    """Aggregate result of detecting all tools."""

    results: dict[ToolName, ToolDetectionResult] = field(default_factory=dict)
    platform: str = ""

    @property
    def tools_found(self) -> list[ToolDetectionResult]:
        """Return only detected tools."""
        return [r for r in self.results.values() if r.found]

    @property
    def tools_not_found(self) -> list[ToolDetectionResult]:
        """Return tools that were not detected."""
        return [r for r in self.results.values() if not r.found]


def detect_all() -> DetectionReport:
    """Detect all supported tools on the current platform.

    Returns a DetectionReport with results for each tool.
    """
    report = DetectionReport(platform=sys.platform)
    report.results[ToolName.CLAUDE_CODE] = _detect_claude_code()
    report.results[ToolName.CURSOR] = _detect_cursor()
    report.results[ToolName.COPILOT] = _detect_vscode()
    report.results[ToolName.GEMINI_CLI] = _detect_gemini_cli()
    report.results[ToolName.OPENCODE] = _detect_opencode()
    return report


def detect_tool(tool: ToolName) -> ToolDetectionResult:
    """Detect a single tool."""
    detectors = {
        ToolName.CLAUDE_CODE: _detect_claude_code,
        ToolName.CURSOR: _detect_cursor,
        ToolName.COPILOT: _detect_vscode,
        ToolName.GEMINI_CLI: _detect_gemini_cli,
        ToolName.OPENCODE: _detect_opencode,
    }
    return detectors[tool]()


# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------


def _detect_claude_code() -> ToolDetectionResult:
    """Detect Claude Code via PATH or config directory.

    Claude Code is installed via npm (``npm i -g @anthropic-ai/claude-code``)
    which puts a ``claude`` binary on PATH.  Users who run via ``npx`` or the
    VS Code extension will not have a PATH binary but will have ``~/.claude/``.
    """
    result = ToolDetectionResult(tool=ToolName.CLAUDE_CODE)

    which = shutil.which("claude")
    if which:
        result.found = True
        result.executable_path = which
        result.method = DetectionMethod.PATH
        result.details = f"Found on PATH: {which}"
        return result

    config_dir = Path.home() / ".claude"
    if config_dir.is_dir():
        result.found = True
        result.method = DetectionMethod.CONFIG_DIR
        result.details = f"Config directory exists: {config_dir}"
        return result

    result.details = "Not found on PATH or via ~/.claude/ directory."
    return result


# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------


def _detect_cursor() -> ToolDetectionResult:
    """Detect Cursor via PATH or known install locations.

    Cursor is a standalone Electron app.  On macOS it lives in
    /Applications/Cursor.app and optionally installs a ``cursor`` shell
    command.  On Windows it installs to %LOCALAPPDATA%\\Programs\\Cursor.
    On Linux it may be a deb, snap or AppImage.
    """
    result = ToolDetectionResult(tool=ToolName.CURSOR)

    which = shutil.which("cursor")
    if which:
        result.found = True
        result.executable_path = which
        result.method = DetectionMethod.PATH
        result.details = f"Found on PATH: {which}"
        return result

    for candidate in _cursor_known_locations():
        if candidate.exists():
            result.found = True
            result.executable_path = str(candidate)
            result.method = DetectionMethod.KNOWN_LOCATION
            result.details = f"Found at: {candidate}"
            return result

    if sys.platform == "linux":
        appimage = _check_linux_appimage("Cursor")
        if appimage:
            result.found = True
            result.executable_path = str(appimage)
            result.method = DetectionMethod.KNOWN_LOCATION
            result.details = f"Found AppImage: {appimage}"
            return result

    result.details = "Not found on PATH or known install locations."
    return result


def _cursor_known_locations() -> list[Path]:
    """Return known Cursor install paths for the current platform."""
    if sys.platform == "darwin":
        return [
            Path("/Applications/Cursor.app/Contents/MacOS/Cursor"),
        ]
    elif sys.platform == "win32":
        paths: list[Path] = []
        local = _get_env_path("LOCALAPPDATA")
        if local:
            paths.append(local / "Programs" / "Cursor" / "Cursor.exe")
        return paths
    else:
        return [
            Path("/usr/share/cursor/cursor"),
            Path("/snap/cursor/current/cursor"),
        ]


# ---------------------------------------------------------------------------
# VS Code / Copilot
# ---------------------------------------------------------------------------


def _detect_vscode() -> ToolDetectionResult:
    """Detect VS Code via PATH or known locations, then check for Copilot.

    VS Code is the host application.  The Copilot extension is checked
    separately because VS Code can exist without it, and we still configure
    hooks either way.
    """
    result = ToolDetectionResult(tool=ToolName.COPILOT)

    which = shutil.which("code")
    if which:
        result.found = True
        result.executable_path = which
        result.method = DetectionMethod.PATH
        result.details = f"Found on PATH: {which}"
    else:
        for candidate in _vscode_known_locations():
            if candidate.exists():
                result.found = True
                result.executable_path = str(candidate)
                result.method = DetectionMethod.KNOWN_LOCATION
                result.details = f"Found at: {candidate}"
                break

    if not result.found:
        result.details = "Not found on PATH or known install locations."

    result.has_copilot_extension = _check_copilot_extension()
    if result.has_copilot_extension:
        result.details += "  Copilot extension detected."

    return result


def _vscode_known_locations() -> list[Path]:
    """Return known VS Code install paths for the current platform."""
    if sys.platform == "darwin":
        return [
            Path("/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"),
        ]
    elif sys.platform == "win32":
        paths: list[Path] = []
        local = _get_env_path("LOCALAPPDATA")
        program_files = _get_env_path("ProgramFiles")
        if local:
            paths.append(local / "Programs" / "Microsoft VS Code" / "Code.exe")
        if program_files:
            paths.append(program_files / "Microsoft VS Code" / "Code.exe")
        return paths
    else:
        return [
            Path("/usr/share/code/code"),
            Path("/snap/code/current/code"),
        ]


def _check_copilot_extension() -> bool:
    """Check if the GitHub Copilot extension is installed in VS Code."""
    extensions_dir = Path.home() / ".vscode" / "extensions"
    if not extensions_dir.is_dir():
        return False
    try:
        for entry in extensions_dir.iterdir():
            if entry.name.startswith("github.copilot-") and entry.is_dir():
                return True
    except PermissionError:
        pass
    return False


# ---------------------------------------------------------------------------
# Gemini CLI
# ---------------------------------------------------------------------------


def _detect_gemini_cli() -> ToolDetectionResult:
    """Detect Gemini CLI via PATH or config directory.

    Gemini CLI is installed via npm (``npm i -g @google/gemini-cli``)
    or downloaded directly.  It puts a ``gemini`` binary on PATH.  The
    config directory is ``~/.gemini/``.
    """
    result = ToolDetectionResult(tool=ToolName.GEMINI_CLI)

    which = shutil.which("gemini")
    if which:
        result.found = True
        result.executable_path = which
        result.method = DetectionMethod.PATH
        result.details = f"Found on PATH: {which}"
        return result

    config_dir = Path.home() / ".gemini"
    if config_dir.is_dir():
        result.found = True
        result.method = DetectionMethod.CONFIG_DIR
        result.details = f"Config directory exists: {config_dir}"
        return result

    result.details = "Not found on PATH or via ~/.gemini/ directory."
    return result


# ---------------------------------------------------------------------------
# OpenCode
# ---------------------------------------------------------------------------


def _detect_opencode() -> ToolDetectionResult:
    """Detect OpenCode via PATH, project config or global config directory.

    OpenCode is installed via npm (``npm i -g opencode``) or downloaded
    directly.  It puts an ``opencode`` binary on PATH.  Project config
    lives in ``opencode.json`` or ``.opencode/``.  Global config is at
    ``~/.config/opencode/``.
    """
    result = ToolDetectionResult(tool=ToolName.OPENCODE)

    which = shutil.which("opencode")
    if which:
        result.found = True
        result.executable_path = which
        result.method = DetectionMethod.PATH
        result.details = f"Found on PATH: {which}"
        return result

    # Project-level indicators
    if Path("opencode.json").is_file():
        result.found = True
        result.method = DetectionMethod.CONFIG_DIR
        result.details = "Project config found: opencode.json"
        return result

    if Path(".opencode").is_dir():
        result.found = True
        result.method = DetectionMethod.CONFIG_DIR
        result.details = "Project directory found: .opencode/"
        return result

    # Global config directory
    config_dir = Path.home() / ".config" / "opencode"
    if config_dir.is_dir():
        result.found = True
        result.method = DetectionMethod.CONFIG_DIR
        result.details = f"Config directory exists: {config_dir}"
        return result

    result.details = "Not found on PATH or via opencode.json / .opencode/ / ~/.config/opencode/."
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_env_path(var_name: str) -> Path | None:
    """Return a Path from an environment variable, or None if unset."""
    value = os.environ.get(var_name)
    if value:
        return Path(value)
    return None


def _check_linux_appimage(app_name: str) -> Path | None:
    """Check common locations for an AppImage on Linux.

    Only scans ``~/`` and ``~/Applications/`` to keep it fast and bounded.
    """
    home = Path.home()
    for search_dir in [home, home / "Applications"]:
        if not search_dir.is_dir():
            continue
        try:
            for entry in search_dir.iterdir():
                if entry.name.startswith(app_name) and entry.name.endswith(".AppImage"):
                    return entry
        except PermissionError:
            continue
    return None
