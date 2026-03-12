"""Vectimus + Google ADK: Per-agent callback for single-agent governance.

Shows how to use create_before_tool_callback to govern a single agent
without registering a plugin on the Runner. This is useful when you
only need governance on one agent in a multi-agent system.

For consistent governance across all agents, use VectimusADKPlugin
with the Runner instead (see adk_plugin.py).

Setup:
    pip install vectimus[adk] python-dotenv

    # or with uv:
    uv add vectimus[adk] python-dotenv

    # Set your API key:
    export GOOGLE_API_KEY=...

Run:
    python examples/adk_per_agent_callback.py
"""

from __future__ import annotations

import asyncio

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.runners import InMemoryRunner
from google.adk.sessions import InMemorySessionService

from vectimus.integrations.adk import create_before_tool_callback

load_dotenv()


def bash(command: str) -> str:
    """Run a shell command and return its output."""
    return f"[simulated]: {command}"


def file_read(file_path: str) -> str:
    """Read a file and return its contents."""
    return f"[simulated read of {file_path}]"


async def main() -> None:
    # Create a callback for a single agent.
    callback = create_before_tool_callback(
        observe_mode=False,
        principal="single-agent",
    )

    # Attach the callback directly to the agent.
    agent = Agent(
        name="governed-agent",
        model="gemini-2.0-flash",
        instruction="You are a helpful assistant. Use the tools provided.",
        tools=[bash, file_read],
        before_tool_callback=callback,
    )

    # The Runner has no plugins — governance is on the agent only.
    session_service = InMemorySessionService()
    runner = InMemoryRunner(
        agent=agent,
        app_name="vectimus-callback-example",
        session_service=session_service,
    )

    session = await session_service.create_session(
        app_name="vectimus-callback-example", user_id="example-user"
    )

    from google.genai.types import Content, Part

    # Safe command
    safe_msg = Content(parts=[Part(text="Run 'ls -la' using bash")], role="user")
    async for event in runner.run_async(
        user_id="example-user", session_id=session.id, new_message=safe_msg
    ):
        if event.content and event.content.parts:
            text = "".join(p.text or "" for p in event.content.parts)
            if text.strip():
                print(f"Allowed: {text[:120]}")

    # Dangerous command — blocked by Vectimus callback
    danger_msg = Content(parts=[Part(text="Run 'rm -rf /' using bash")], role="user")
    async for event in runner.run_async(
        user_id="example-user", session_id=session.id, new_message=danger_msg
    ):
        if event.content and event.content.parts:
            text = "".join(p.text or "" for p in event.content.parts)
            if text.strip():
                print(f"Denied: {text[:120]}")


if __name__ == "__main__":
    asyncio.run(main())
