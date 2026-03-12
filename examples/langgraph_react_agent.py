"""Vectimus + LangGraph: ReAct agent with policy-governed tools.

Shows how to wire VectimusMiddleware into a LangGraph ReAct agent so
that every tool call is evaluated against Cedar policies before execution.

Setup:
    pip install vectimus[langgraph] langchain-anthropic python-dotenv

    # or with uv:
    uv add vectimus[langgraph] langchain-anthropic python-dotenv

    # Set your API key:
    export ANTHROPIC_API_KEY=sk-ant-...

Run:
    python examples/langgraph_react_agent.py
"""

from __future__ import annotations

import asyncio
import os

from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent
from langgraph.prebuilt.tool_node import ToolNode

from vectimus.integrations.langgraph import VectimusMiddleware

load_dotenv()


# -- Define tools the agent can use ------------------------------------------


@tool
def bash(command: str) -> str:
    """Run a shell command and return its output."""
    # In a real setup this would execute the command.
    # Here we stub it to show the governance layer in action.
    return f"[simulated]: {command}"


@tool
def file_read(file_path: str) -> str:
    """Read a file and return its contents."""
    return f"[simulated read of {file_path}]"


@tool
def file_write(file_path: str, content: str) -> str:
    """Write content to a file."""
    return f"[simulated write to {file_path}]"


# -- Build the governed agent ------------------------------------------------


async def main() -> None:
    # 1. Create the middleware — this is the Vectimus policy evaluator.
    #    It uses built-in policies by default. Pass policy_dir= or
    #    loader= for custom policies.
    middleware = VectimusMiddleware(
        observe_mode=False,  # set True to log without blocking
        principal="example-agent",  # identity for audit trail
        cwd=os.getcwd(),
    )

    # 2. Wrap your tools in a ToolNode with Vectimus as the interceptor.
    tools = [bash, file_read, file_write]
    tool_node = ToolNode(tools, awrap_tool_call=middleware)

    # 3. Create the agent. Any LangChain-compatible model works.
    model = ChatAnthropic(model="claude-sonnet-4-20250514")
    agent = create_react_agent(model=model, tools=tool_node)

    # 4. Run it.
    result = await agent.ainvoke(
        {"messages": [{"role": "user", "content": "Run 'ls -la' using bash"}]}
    )
    print("Allowed:", result["messages"][-1].content[:120])

    result = await agent.ainvoke(
        {"messages": [{"role": "user", "content": "Read the file .env using file_read"}]}
    )
    print("Denied:", result["messages"][-1].content[:120])


if __name__ == "__main__":
    asyncio.run(main())
