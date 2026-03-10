"""Auto-discover MCP servers from tool config files."""

from __future__ import annotations

import json
from pathlib import Path

from vectimus.cli.detect import DetectionReport, ToolName

# Maps each tool to (config path relative to home, key containing server names).
_TOOL_MCP_CONFIGS: dict[ToolName, tuple[str, str]] = {
    ToolName.CLAUDE_CODE: (".claude/settings.json", "mcpServers"),
    ToolName.CURSOR: (".cursor/mcp.json", "mcpServers"),
    ToolName.COPILOT: (".vscode/mcp.json", "servers"),
}


def discover_mcp_servers(report: DetectionReport) -> dict[ToolName, list[str]]:
    """Read MCP server names from each detected tool's config.

    Only inspects tools that were found in *report*.  Silently skips
    config files that are missing or contain invalid JSON.

    Returns a dict of ``ToolName`` -> sorted list of server names.
    """
    result: dict[ToolName, list[str]] = {}
    home = Path.home()

    for tool_name, (rel_path, key) in _TOOL_MCP_CONFIGS.items():
        tool_result = report.results.get(tool_name)
        if not tool_result or not tool_result.found:
            continue

        config_path = home / rel_path
        servers = _read_server_names(config_path, key)
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
