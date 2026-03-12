"""Vectimus + Google ADK: Agent governed by project-local Cedar policies.

Shows how to load custom Cedar policies alongside the built-in pack,
so your agent is governed by both the base rules and your own
project-specific rules.

Setup:
    pip install vectimus[adk] python-dotenv

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
    python examples/adk_custom_policies.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.runners import InMemoryRunner
from google.adk.sessions import InMemorySessionService

from vectimus.engine.loader import PolicyLoader
from vectimus.integrations.adk import VectimusADKPlugin

load_dotenv()


def file_read(file_path: str) -> str:
    """Read a file and return its contents."""
    return f"[simulated read of {file_path}]"


def bash(command: str) -> str:
    """Run a shell command and return its output."""
    return f"[simulated]: {command}"


async def main() -> None:
    # Point the loader at the project root so it discovers
    # .vectimus/packs/custom/ alongside the built-in policies.
    project_root = Path.cwd()
    loader = PolicyLoader(project_path=project_root)

    plugin = VectimusADKPlugin(
        loader=loader,
        observe_mode=False,
        principal="custom-policy-agent",
        cwd=str(project_root),
    )

    agent = Agent(
        name="custom-governed-agent",
        model="gemini-2.0-flash",
        instruction="You are a helpful assistant. Use the tools provided.",
        tools=[file_read, bash],
    )

    session_service = InMemorySessionService()
    runner = InMemoryRunner(
        agent=agent,
        app_name="vectimus-custom-example",
        session_service=session_service,
        plugins=[plugin],
    )

    session = await session_service.create_session(
        app_name="vectimus-custom-example", user_id="example-user"
    )

    from google.genai.types import Content, Part

    # This will be allowed (normal file)
    safe_msg = Content(parts=[Part(text="Read the file README.md")], role="user")
    async for event in runner.run_async(
        user_id="example-user", session_id=session.id, new_message=safe_msg
    ):
        if event.content and event.content.parts:
            text = "".join(p.text or "" for p in event.content.parts)
            if text.strip():
                print(f"README.md: {text[:120]}")

    # This will be denied by built-in policies (.env files)
    deny_msg = Content(parts=[Part(text="Read the file .env")], role="user")
    async for event in runner.run_async(
        user_id="example-user", session_id=session.id, new_message=deny_msg
    ):
        if event.content and event.content.parts:
            text = "".join(p.text or "" for p in event.content.parts)
            if text.strip():
                print(f".env: {text[:120]}")


if __name__ == "__main__":
    asyncio.run(main())
