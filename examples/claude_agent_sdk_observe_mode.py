"""Vectimus + Claude Agent SDK: observe mode for trialling policies.

Observe mode logs every policy decision to the audit trail but never
blocks tool calls.  Use this when rolling out Vectimus to see what
would be blocked before turning on enforcement.

For Claude Agent SDK agents, observe mode is configured the same way
as for Claude Code -- either via the CLI or an environment variable.

Setup:
    pip install vectimus claude-agent-sdk

    # Configure hooks:
    vectimus init

    # Turn on observe mode:
    vectimus observe on

    # Set your API key:
    export ANTHROPIC_API_KEY=sk-ant-...

Run:
    python examples/claude_agent_sdk_observe_mode.py

    # Review the audit log:
    cat ~/.vectimus/logs/audit-$(date +%Y-%m-%d).jsonl | python -m json.tool

    # When ready to enforce:
    vectimus observe off
"""

from __future__ import annotations

import os
from datetime import date


def main() -> None:
    try:
        from claude_agent_sdk import Agent
    except ImportError:
        print(
            "claude-agent-sdk is not installed.\n"
            "Install it with: pip install claude-agent-sdk\n\n"
            "This example demonstrates observe mode with Claude Agent SDK.\n"
            "In observe mode, Vectimus logs all policy decisions but never\n"
            "blocks tool calls. This lets you trial policies before enforcing."
        )
        return

    # Observe mode can also be enabled via environment variable,
    # which is useful for CI/CD pipelines:
    #   export VECTIMUS_OBSERVE=true
    #
    # Or per-project in .vectimus/config.toml:
    #   [observe]
    #   enabled = true

    agent = Agent(
        model="claude-sonnet-4-20250514",
        prompt=(
            "Try to run 'git push --force origin main' using Bash. "
            "In observe mode this will succeed but be logged as "
            "a would-be denial."
        ),
        allowed_tools=["Bash", "Read"],
    )

    result = agent.run()
    print(result)

    log_path = os.path.expanduser(f"~/.vectimus/logs/audit-{date.today().isoformat()}.jsonl")
    print(f"\nAudit log: {log_path}")
    print("Review with: cat", log_path, "| python -m json.tool")


if __name__ == "__main__":
    main()
