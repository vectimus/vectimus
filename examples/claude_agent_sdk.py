"""Vectimus + Claude Agent SDK: governed agent via shared hook system.

The Claude Agent SDK uses the same hook mechanism as Claude Code.  Hooks
defined in .claude/settings.json fire on tool calls made by SDK-built
agents exactly as they do during interactive Claude Code sessions.

This means ``vectimus init`` already configures everything you need.
No additional adapter or integration code is required.

Setup:
    pip install vectimus claude-agent-sdk

    # Configure hooks (one-time):
    vectimus init

    # Set your API key:
    export ANTHROPIC_API_KEY=sk-ant-...

Run:
    python examples/claude_agent_sdk.py

How it works:
    1. ``vectimus init`` writes a PreToolUse hook to .claude/settings.json
    2. The Claude Agent SDK reads .claude/settings.json on startup
    3. Every tool call (Bash, Write, Edit, Agent, MCP, etc.) triggers the hook
    4. Vectimus evaluates the call against Cedar policies and returns allow/deny
    5. Denied calls are blocked before execution -- the agent sees a clear
       message and can try a different approach

The hook configuration in .claude/settings.json looks like:

    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "",
            "hooks": [
              {
                "type": "command",
                "command": "vectimus hook --source claude-code"
              }
            ]
          }
        ]
      }
    }

This is identical for both Claude Code and Claude Agent SDK because they
share the same settings file, hook system and tool call JSON format.
"""

from __future__ import annotations


def main() -> None:
    try:
        from claude_agent_sdk import Agent
    except ImportError:
        print(
            "claude-agent-sdk is not installed.\n"
            "Install it with: pip install claude-agent-sdk\n\n"
            "This example demonstrates that Vectimus governs Claude Agent SDK\n"
            "agents through the same hook mechanism as Claude Code. No additional\n"
            "adapter or configuration is needed beyond 'vectimus init'."
        )
        return

    # Create a minimal agent. The SDK reads .claude/settings.json and
    # fires PreToolUse hooks on every tool call automatically.
    agent = Agent(
        model="claude-sonnet-4-20250514",
        prompt="List the files in the current directory using the Bash tool.",
        # The allowed_tools list controls which tools the agent can use.
        # Vectimus evaluates each tool call against Cedar policies regardless.
        allowed_tools=["Bash", "Read", "Glob"],
    )

    # Run the agent. Any tool call that violates a Vectimus policy will
    # be blocked, and the agent will see a message like:
    #   "Blocked by Vectimus policy vectimus-base-015: npm publish is not permitted."
    result = agent.run()
    print(result)


if __name__ == "__main__":
    main()
