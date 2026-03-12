"""Shared pytest fixtures for Vectimus tests."""

from __future__ import annotations

import pytest

from vectimus.engine.evaluator import PolicyEngine
from vectimus.engine.models import (
    ActionInfo,
    ActionType,
    ContextInfo,
    IdentityInfo,
    SourceInfo,
    VectimusEvent,
)


@pytest.fixture()
def engine() -> PolicyEngine:
    """Return a PolicyEngine loaded with built-in policies."""
    return PolicyEngine()


@pytest.fixture()
def make_event():
    """Factory fixture to build VectimusEvent objects quickly."""

    def _make(
        action_type: str = ActionType.SHELL_COMMAND,
        tool_name: str = "Bash",
        command: str | None = None,
        file_path: str | None = None,
        url: str | None = None,
        cwd: str | None = "/home/user/project",
        principal: str = "test@example.com",
        version: str | None = None,
        hostname: str | None = None,
        repository: str | None = None,
        branch: str | None = None,
        file_content: str | None = None,
        script_content: str | None = None,
        mcp_server: str | None = None,
        mcp_tool: str | None = None,
    ) -> VectimusEvent:
        return VectimusEvent(
            source=SourceInfo(tool="claude-code", version=version),
            identity=IdentityInfo(principal=principal),
            action=ActionInfo(
                action_type=action_type,
                raw_tool_name=tool_name,
                command=command,
                file_path=file_path,
                url=url,
                file_content=file_content,
                script_content=script_content,
                mcp_server=mcp_server,
                mcp_tool=mcp_tool,
            ),
            context=ContextInfo(
                cwd=cwd,
                hostname=hostname,
                repository=repository,
                branch=branch,
            ),
        )

    return _make
