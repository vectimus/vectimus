"""Vectimus + LangGraph: Observe mode for trialling policies.

Observe mode logs every policy decision to the audit trail but never
blocks tool calls. Use this when rolling out Vectimus to see what
would be blocked before turning on enforcement.

Setup:
    pip install vectimus[langgraph] langchain-anthropic python-dotenv

Run:
    python examples/langgraph_observe_mode.py
    cat ~/.vectimus/logs/audit-$(date +%Y-%m-%d).jsonl | python -m json.tool
"""

from __future__ import annotations

import asyncio
import os
from datetime import date

from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent
from langgraph.prebuilt.tool_node import ToolNode

from vectimus.integrations.langgraph import VectimusMiddleware

load_dotenv()


@tool
def bash(command: str) -> str:
    """Run a shell command and return its output."""
    return f"[simulated]: {command}"


@tool
def file_read(file_path: str) -> str:
    """Read a file and return its contents."""
    return f"[simulated read of {file_path}]"


async def main() -> None:
    # observe_mode=True: everything is logged, nothing is blocked.
    middleware = VectimusMiddleware(
        observe_mode=True,
        principal="observe-agent",
        cwd=os.getcwd(),
    )

    tools = [bash, file_read]
    tool_node = ToolNode(tools, awrap_tool_call=middleware)

    model = ChatAnthropic(model="claude-sonnet-4-20250514")
    agent = create_react_agent(model=model, tools=tool_node)

    # This would normally be denied, but in observe mode it proceeds.
    result = await agent.ainvoke({"messages": [{"role": "user", "content": "Read the file .env"}]})
    print("Result:", result["messages"][-1].content[:200])

    # Check the audit log for the would-be-denied entry.
    log_path = os.path.expanduser(f"~/.vectimus/logs/audit-{date.today().isoformat()}.jsonl")
    print(f"\nAudit log: {log_path}")
    print("Review with: cat", log_path, "| python -m json.tool")


if __name__ == "__main__":
    asyncio.run(main())
