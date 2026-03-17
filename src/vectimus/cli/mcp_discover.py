"""Auto-discover MCP servers from tool config files."""

from __future__ import annotations

import json
from pathlib import Path

from vectimus.cli.detect import DetectionReport, ToolName

# Maps each tool to a list of (config path relative to home, JSON key) pairs.
# Multiple entries per tool are checked in order; servers are merged across all.
_TOOL_MCP_CONFIGS: dict[ToolName, list[tuple[str, str]]] = {
    ToolName.CLAUDE_CODE: [
        (".claude/settings.json", "mcpServers"),
        (".claude.json", "mcpServers"),
    ],
    ToolName.CURSOR: [
        (".cursor/mcp.json", "mcpServers"),
    ],
    ToolName.COPILOT: [
        (".vscode/mcp.json", "servers"),
    ],
}

# Project-level config files checked relative to cwd.
_PROJECT_MCP_CONFIGS: dict[ToolName, list[tuple[str, str]]] = {
    ToolName.CLAUDE_CODE: [
        (".mcp.json", "mcpServers"),
    ],
}


def discover_mcp_servers(
    report: DetectionReport,
    project_dir: Path | None = None,
) -> dict[ToolName, list[str]]:
    """Read MCP server names from each detected tool's config.

    Checks both user-level configs (relative to ``$HOME``) and
    project-level configs (relative to *project_dir*, defaulting to cwd).

    Only inspects tools that were found in *report*.  Silently skips
    config files that are missing or contain invalid JSON.

    Returns a dict of ``ToolName`` -> sorted list of server names.
    """
    result: dict[ToolName, list[str]] = {}
    home = Path.home()
    project = project_dir or Path.cwd()

    for tool_name, config_entries in _TOOL_MCP_CONFIGS.items():
        tool_result = report.results.get(tool_name)
        if not tool_result or not tool_result.found:
            continue

        servers: set[str] = set()
        for rel_path, key in config_entries:
            servers.update(_read_server_names(home / rel_path, key))

        for rel_path, key in _PROJECT_MCP_CONFIGS.get(tool_name, []):
            servers.update(_read_server_names(project / rel_path, key))

        if servers:
            result[tool_name] = sorted(servers)

    return result


def _read_server_names(path: Path, key: str) -> list[str]:
    """Extract server names from a JSON config file.

    Returns an empty list if the file is missing, unreadable or the
    expected key is absent or not a dict.
    """
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, ValueError):
        return []

    servers = data.get(key)
    if not isinstance(servers, dict):
        return []
    return list(servers.keys())
