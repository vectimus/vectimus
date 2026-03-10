"""Tests for the FastAPI server.

These tests require the ``server`` extra: ``pip install vectimus[server]``.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi", reason="requires vectimus[server]")
httpx = pytest.importorskip("httpx", reason="requires httpx (dev dependency)")

from httpx import ASGITransport, AsyncClient  # noqa: E402

from vectimus.server.app import create_app  # noqa: E402
from vectimus.server.config import ServerConfig  # noqa: E402

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_BASE_PACK = _PROJECT_ROOT / "src" / "vectimus" / "policies" / "base"
_OWASP_PACK = _PROJECT_ROOT / "src" / "vectimus" / "policies" / "owasp-agentic"


@pytest.fixture()
def app():
    config = ServerConfig()
    return create_app(config)


@pytest.fixture()
def flood_app():
    """App with low session limits and both base + OWASP policies for flood testing."""
    parts: list[str] = []
    for pack_dir in [_BASE_PACK, _OWASP_PACK]:
        for cedar_file in sorted(pack_dir.glob("*.cedar")):
            parts.append(cedar_file.read_text())

    tmpdir = tempfile.mkdtemp()
    combined = Path(tmpdir) / "all_policies.cedar"
    combined.write_text("\n\n".join(parts))

    config = ServerConfig(
        session_spawn_limit=3,
        session_message_limit=3,
        policy_dir=tmpdir,
    )
    return create_app(config)


@pytest.fixture()
async def flood_client(flood_app):
    transport = ASGITransport(app=flood_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture()
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health(client: AsyncClient) -> None:
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["policy_count"] > 0


@pytest.mark.asyncio
async def test_policies_endpoint(client: AsyncClient) -> None:
    resp = await client.get("/policies")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] > 0


@pytest.mark.asyncio
async def test_evaluate_deny(client: AsyncClient) -> None:
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "hook_event_name": "PreToolUse",
        "session_id": "test-session",
        "cwd": "/home/user/project",
    }
    resp = await client.post(
        "/evaluate",
        json=payload,
        headers={"X-Vectimus-Source": "claude-code"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "deny"
    assert "hookSpecificOutput" in data
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.asyncio
async def test_evaluate_allow(client: AsyncClient) -> None:
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "echo hello"},
        "hook_event_name": "PreToolUse",
        "cwd": "/home/user/project",
    }
    resp = await client.post(
        "/evaluate",
        json=payload,
        headers={"X-Vectimus-Source": "claude-code"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "allow"


@pytest.mark.asyncio
async def test_evaluate_terraform_destroy(client: AsyncClient) -> None:
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "terraform destroy"},
        "hook_event_name": "PreToolUse",
    }
    resp = await client.post(
        "/evaluate",
        json=payload,
        headers={"X-Vectimus-Source": "claude-code"},
    )
    data = resp.json()
    assert data["decision"] == "deny"


@pytest.mark.asyncio
async def test_evaluate_secret_read(client: AsyncClient) -> None:
    payload = {
        "tool_name": "Read",
        "tool_input": {"file_path": "~/.ssh/id_rsa"},
        "hook_event_name": "PreToolUse",
    }
    resp = await client.post(
        "/evaluate",
        json=payload,
        headers={"X-Vectimus-Source": "claude-code"},
    )
    data = resp.json()
    assert data["decision"] == "deny"


@pytest.mark.asyncio
async def test_evaluate_cursor_source(client: AsyncClient) -> None:
    payload = {
        "hook_event_name": "beforeShellExecution",
        "command": "npm publish",
        "cwd": "/home/user/project",
    }
    resp = await client.post(
        "/evaluate",
        json=payload,
        headers={"X-Vectimus-Source": "cursor"},
    )
    data = resp.json()
    assert data["decision"] == "deny"


# ---------------------------------------------------------------------------
# Session tracking / flood detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_spawn_flood_denied(flood_client: AsyncClient) -> None:
    """After exceeding spawn_limit, further spawns should be denied."""
    payload = {
        "tool_name": "Agent",
        "tool_input": {
            "prompt": "do something",
            "subagent_type": "Explore",
            "description": "test",
        },
        "hook_event_name": "PreToolUse",
        "session_id": "flood-session",
    }
    # First 3 should be allowed (at limit).
    for _ in range(3):
        resp = await flood_client.post(
            "/evaluate",
            json=payload,
            headers={"X-Vectimus-Source": "claude-code"},
        )
        assert resp.json()["decision"] == "allow"

    # 4th should be denied (over limit).
    resp = await flood_client.post(
        "/evaluate",
        json=payload,
        headers={"X-Vectimus-Source": "claude-code"},
    )
    assert resp.json()["decision"] == "deny"


@pytest.mark.asyncio
async def test_session_message_flood_denied(flood_client: AsyncClient) -> None:
    """After exceeding message_limit, further messages should be denied."""
    payload = {
        "tool_name": "SendMessage",
        "tool_input": {
            "type": "message",
            "recipient": "researcher",
            "content": "hello",
            "summary": "greeting",
        },
        "hook_event_name": "PreToolUse",
        "session_id": "msg-flood-session",
    }
    for _ in range(3):
        resp = await flood_client.post(
            "/evaluate",
            json=payload,
            headers={"X-Vectimus-Source": "claude-code"},
        )
        assert resp.json()["decision"] == "allow"

    resp = await flood_client.post(
        "/evaluate",
        json=payload,
        headers={"X-Vectimus-Source": "claude-code"},
    )
    assert resp.json()["decision"] == "deny"


@pytest.mark.asyncio
async def test_session_tracking_no_session_id(flood_client: AsyncClient) -> None:
    """Requests without session_id should skip tracking and not be denied."""
    payload = {
        "tool_name": "Agent",
        "tool_input": {
            "prompt": "do something",
            "subagent_type": "Explore",
            "description": "test",
        },
        "hook_event_name": "PreToolUse",
        # No session_id
    }
    for _ in range(5):
        resp = await flood_client.post(
            "/evaluate",
            json=payload,
            headers={"X-Vectimus-Source": "claude-code"},
        )
        assert resp.json()["decision"] == "allow"


@pytest.mark.asyncio
async def test_session_tracking_different_sessions(flood_client: AsyncClient) -> None:
    """Different session_ids should track independently."""
    for session_id in ("sess-a", "sess-b"):
        payload = {
            "tool_name": "Agent",
            "tool_input": {
                "prompt": "do something",
                "subagent_type": "Explore",
                "description": "test",
            },
            "hook_event_name": "PreToolUse",
            "session_id": session_id,
        }
        for _ in range(3):
            resp = await flood_client.post(
                "/evaluate",
                json=payload,
                headers={"X-Vectimus-Source": "claude-code"},
            )
            assert resp.json()["decision"] == "allow"
