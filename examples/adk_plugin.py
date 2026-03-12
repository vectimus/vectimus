"""Vectimus + Google ADK: Agent governed by a Runner plugin.

Shows how to add Vectimus governance to a Google ADK agent using
VectimusADKPlugin.  The plugin evaluates every tool call against Cedar
policies before execution.  This is the recommended approach — it
applies governance globally to all agents managed by the Runner.

Setup:
    pip install vectimus[adk] python-dotenv

    # or with uv:
    uv add vectimus[adk] python-dotenv

    # Set your API key:
    export GOOGLE_API_KEY=...

Run:
    python examples/adk_plugin.py
"""

from __future__ import annotations

import asyncio

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.runners import InMemoryRunner
from google.adk.sessions import InMemorySessionService

from vectimus.integrations.adk import VectimusADKPlugin

load_dotenv()


# -- Define tools the agent can use ------------------------------------------


def bash(command: str) -> str:
    """Run a shell command and return its output."""
    # In a real setup this would execute the command.
    # Here we stub it to show the governance layer in action.
    return f"[simulated]: {command}"


def file_read(file_path: str) -> str:
    """Read a file and return its contents."""
    return f"[simulated read of {file_path}]"


def file_write(file_path: str, content: str) -> str:
    """Write content to a file."""
    return f"[simulated write to {file_path}]"


# -- Build the governed agent ------------------------------------------------


async def main() -> None:
    # 1. Create the plugin — this is the Vectimus policy evaluator.
    #    It uses built-in policies by default. Pass policy_dir= or
    #    loader= for custom policies.
    plugin = VectimusADKPlugin(
        observe_mode=False,  # set True to log without blocking
        principal="example-adk-agent",  # identity for audit trail
    )

    # 2. Create an ADK agent with tools.
    agent = Agent(
        name="governed-agent",
        model="gemini-2.0-flash",
        instruction="You are a helpful assistant. Use the tools provided.",
        tools=[bash, file_read, file_write],
    )

    # 3. Wire the plugin into the Runner.
    session_service = InMemorySessionService()
    runner = InMemoryRunner(
        agent=agent,
        app_name="vectimus-example",
        session_service=session_service,
        plugins=[plugin],
    )

    # 4. Run it.
    session = await session_service.create_session(
        app_name="vectimus-example", user_id="example-user"
    )

    from google.genai.types import Content, Part

    # Safe command — should be allowed
    safe_msg = Content(parts=[Part(text="Run 'ls -la' using bash")], role="user")
    async for event in runner.run_async(
        user_id="example-user", session_id=session.id, new_message=safe_msg
    ):
        if event.content and event.content.parts:
            text = "".join(p.text or "" for p in event.content.parts)
            if text.strip():
                print(f"Allowed: {text[:120]}")

    # Dangerous command — should be blocked by Vectimus
    danger_msg = Content(parts=[Part(text="Read the file .env using file_read")], role="user")
    async for event in runner.run_async(
        user_id="example-user", session_id=session.id, new_message=danger_msg
    ):
        if event.content and event.content.parts:
            text = "".join(p.text or "" for p in event.content.parts)
            if text.strip():
                print(f"Denied: {text[:120]}")


if __name__ == "__main__":
    asyncio.run(main())
