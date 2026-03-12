"""Vectimus + LangGraph: Agent governed by project-local Cedar policies.

Shows how to load custom Cedar policies alongside the built-in pack,
so your agent is governed by both the base rules and your own
project-specific rules.

Setup:
    pip install vectimus[langgraph] langchain-anthropic python-dotenv

    # Create a custom policy file:
    mkdir -p .vectimus/packs/custom
    cat > .vectimus/packs/custom/custom.cedar << 'EOF'
    @id("custom-001")
    @description("Block reading test fixtures")
    @enforcement("deny")
    forbid (
        principal,
        action == Vectimus::Action::"file_read",
        resource
    ) when {
        context.file_path like "*.fixture" ||
        context.file_path like "*test_data*"
    };
    EOF

Run:
    python examples/langgraph_custom_policies.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent
from langgraph.prebuilt.tool_node import ToolNode

from vectimus.engine.loader import PolicyLoader
from vectimus.integrations.langgraph import VectimusMiddleware

load_dotenv()


@tool
def file_read(file_path: str) -> str:
    """Read a file and return its contents."""
    return f"[simulated read of {file_path}]"


@tool
def bash(command: str) -> str:
    """Run a shell command and return its output."""
    return f"[simulated]: {command}"


async def main() -> None:
    # Point the loader at the project root so it discovers
    # .vectimus/packs/custom/ alongside the built-in policies.
    project_root = Path.cwd()
    loader = PolicyLoader(project_path=project_root)

    middleware = VectimusMiddleware(
        loader=loader,
        observe_mode=False,
        principal="custom-policy-agent",
        cwd=str(project_root),
    )

    tools = [file_read, bash]
    tool_node = ToolNode(tools, awrap_tool_call=middleware)

    model = ChatAnthropic(model="claude-sonnet-4-20250514")
    agent = create_react_agent(model=model, tools=tool_node)

    # This will be allowed (normal file)
    result = await agent.ainvoke(
        {"messages": [{"role": "user", "content": "Read the file README.md"}]}
    )
    print("README.md:", result["messages"][-1].content[:120])

    # This will be denied by the custom policy (if you created custom.cedar)
    # or by built-in policies (.env files)
    result = await agent.ainvoke({"messages": [{"role": "user", "content": "Read the file .env"}]})
    print(".env:", result["messages"][-1].content[:120])


if __name__ == "__main__":
    asyncio.run(main())
