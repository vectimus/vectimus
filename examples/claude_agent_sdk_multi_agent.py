"""Vectimus + Claude Agent SDK: multi-agent system with governance.

The Claude Agent SDK supports multi-agent patterns where a primary agent
spawns sub-agents to handle subtasks.  Vectimus governs the entire tree:
every tool call from every agent passes through the same PreToolUse hook.

This is particularly important for multi-agent systems because:
- Sub-agents may be spawned with elevated permissions (bypassPermissions)
- Background agents run unsupervised and can accumulate risky actions
- Inter-agent messages can be used to exfiltrate data or hijack goals
- Vectimus policies (OWASP ASI07, ASI08) specifically target these risks

Setup:
    pip install vectimus claude-agent-sdk

    # Configure hooks (one-time):
    vectimus init

    # Set your API key:
    export ANTHROPIC_API_KEY=sk-ant-...

Run:
    python examples/claude_agent_sdk_multi_agent.py
"""

from __future__ import annotations


def main() -> None:
    try:
        from claude_agent_sdk import Agent
    except ImportError:
        print(
            "claude-agent-sdk is not installed.\n"
            "Install it with: pip install claude-agent-sdk\n\n"
            "This example demonstrates Vectimus governance in a multi-agent\n"
            "Claude Agent SDK setup. Vectimus policies block:\n"
            "  - Sub-agents spawned with bypassPermissions mode (ASI07)\n"
            "  - Excessive turn counts that could run up costs (ASI08)\n"
            "  - Broadcast messages that could hijack other agents (ASI07)\n"
            "  - Team/swarm creation without oversight (ASI08)"
        )
        return

    # Primary agent: orchestrates sub-agents.
    # Vectimus evaluates the Agent tool call itself (spawn parameters)
    # AND every tool call the sub-agent makes.
    agent = Agent(
        model="claude-sonnet-4-20250514",
        prompt=(
            "You are a code review agent. Use sub-agents to:\n"
            "1. Spawn an Explore agent to find all Python files\n"
            "2. Read the files and summarize any issues\n"
            "Do NOT use bypassPermissions mode on sub-agents."
        ),
        allowed_tools=["Bash", "Read", "Glob", "Agent"],
    )

    # Vectimus will enforce these policies automatically:
    #
    # - vectimus-owasp-023: Blocks Agent spawns with mode=bypassPermissions
    #   or mode=dontAsk to prevent privilege escalation in sub-agents.
    #
    # - vectimus-owasp-025: Blocks Agent spawns with max_turns > 50
    #   to prevent runaway cost from unbounded agent loops.
    #
    # - vectimus-owasp-026: Blocks TeamCreate calls to prevent
    #   uncontrolled swarm creation.
    #
    # - vectimus-owasp-022: Blocks broadcast SendMessage calls
    #   to prevent goal hijacking across agents.
    #
    # The sub-agents themselves are also governed: if the Explore agent
    # tries to read .env or run `rm -rf /`, those calls are blocked
    # by the same base policies that govern the primary agent.

    result = agent.run()
    print(result)


if __name__ == "__main__":
    main()
