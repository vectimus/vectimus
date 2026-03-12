"""Vectimus + Google ADK: Observe mode for trialling policies.

Observe mode logs every policy decision to the audit trail but never
blocks tool calls. Use this when rolling out Vectimus to see what
would be blocked before turning on enforcement.

Setup:
    pip install vectimus[adk] python-dotenv

Run:
    python examples/adk_observe_mode.py
    cat ~/.vectimus/logs/audit-$(date +%Y-%m-%d).jsonl | python -m json.tool
"""

from __future__ import annotations

import asyncio
import os
from datetime import date

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.runners import InMemoryRunner
from google.adk.sessions import InMemorySessionService

from vectimus.integrations.adk import VectimusADKPlugin

load_dotenv()


def bash(command: str) -> str:
    """Run a shell command and return its output."""
    return f"[simulated]: {command}"


def file_read(file_path: str) -> str:
    """Read a file and return its contents."""
    return f"[simulated read of {file_path}]"


async def main() -> None:
    # observe_mode=True: everything is logged, nothing is blocked.
    plugin = VectimusADKPlugin(
        observe_mode=True,
        principal="observe-agent",
        cwd=os.getcwd(),
    )

    agent = Agent(
        name="observe-agent",
        model="gemini-2.0-flash",
        instruction="You are a helpful assistant. Use the tools provided.",
        tools=[bash, file_read],
    )

    session_service = InMemorySessionService()
    runner = InMemoryRunner(
        agent=agent,
        app_name="vectimus-observe-example",
        session_service=session_service,
        plugins=[plugin],
    )

    session = await session_service.create_session(
        app_name="vectimus-observe-example", user_id="example-user"
    )

    from google.genai.types import Content, Part

    # This would normally be denied, but in observe mode it proceeds.
    msg = Content(parts=[Part(text="Read the file .env")], role="user")
    async for event in runner.run_async(
        user_id="example-user", session_id=session.id, new_message=msg
    ):
        if event.content and event.content.parts:
            text = "".join(p.text or "" for p in event.content.parts)
            if text.strip():
                print(f"Result: {text[:200]}")

    # Check the audit log for the would-be-denied entry.
    log_path = os.path.expanduser(f"~/.vectimus/logs/audit-{date.today().isoformat()}.jsonl")
    print(f"\nAudit log: {log_path}")
    print("Review with: cat", log_path, "| python -m json.tool")


if __name__ == "__main__":
    asyncio.run(main())
