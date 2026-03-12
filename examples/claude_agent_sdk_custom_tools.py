"""Vectimus + Claude Agent SDK: agent with custom MCP tools.

When your SDK-built agent connects to MCP servers, Vectimus governs
those tool calls too.  MCP tool names follow the pattern
``mcp__<server>__<tool>`` and are evaluated against the MCP allowlist
and input inspection policies.

By default, Vectimus blocks all MCP tool calls unless the server is
on the approved list.  Run ``vectimus mcp allow <server>`` to approve
servers, or use ``vectimus init --allow-mcp`` to approve all detected
servers at once.

Setup:
    pip install vectimus claude-agent-sdk

    # Configure hooks and approve MCP servers:
    vectimus init
    vectimus mcp allow my-database

    # Set your API key:
    export ANTHROPIC_API_KEY=sk-ant-...

Run:
    python examples/claude_agent_sdk_custom_tools.py
"""

from __future__ import annotations


def main() -> None:
    try:
        from claude_agent_sdk import Agent
    except ImportError:
        print(
            "claude-agent-sdk is not installed.\n"
            "Install it with: pip install claude-agent-sdk\n\n"
            "This example demonstrates how Vectimus governs MCP tool calls\n"
            "made by Claude Agent SDK agents. Key behaviors:\n\n"
            "  - MCP servers must be on the approved list (vectimus mcp allow)\n"
            "  - Input parameters are inspected for credential paths and\n"
            "    dangerous commands even on approved servers\n"
            "  - All MCP calls are logged to the audit trail"
        )
        return

    # This agent uses MCP tools. The MCP server configuration lives in
    # .claude/settings.json alongside the Vectimus hooks:
    #
    # {
    #   "mcpServers": {
    #     "my-database": {
    #       "command": "npx",
    #       "args": ["-y", "@my-org/db-mcp-server"]
    #     }
    #   },
    #   "hooks": {
    #     "PreToolUse": [...]
    #   }
    # }
    #
    # When the agent calls mcp__my-database__query, Vectimus checks:
    # 1. Is "my-database" on the approved server list? (base-030)
    # 2. Do the input parameters contain credential paths? (base-031)
    # 3. Do the input parameters contain dangerous commands? (base-032)

    agent = Agent(
        model="claude-sonnet-4-20250514",
        prompt=("Query the my-database MCP server to list all users, then summarize the results."),
        allowed_tools=["Bash", "Read", "mcp__my-database__query"],
    )

    result = agent.run()
    print(result)


if __name__ == "__main__":
    main()
