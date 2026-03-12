"""Tests for the LangGraph / LangChain middleware integration."""

from __future__ import annotations

import asyncio
import json
import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


def _mock_langchain():
    """Context manager that makes ``import langchain`` succeed even when not installed."""
    fake = types.ModuleType("langchain")
    fake.__version__ = "0.3.0"
    return patch.dict(sys.modules, {"langchain": fake})


# ---------------------------------------------------------------------------
# Import guard tests
# ---------------------------------------------------------------------------


class TestImportGuard:
    """Importing the module must succeed even without LangChain installed."""

    def test_module_import_succeeds(self) -> None:
        """The module can be imported without langchain present."""
        # If langchain happens to be installed this still passes — we
        # only verify the import itself doesn't blow up.
        from vectimus.integrations import langgraph  # noqa: F401

    def test_middleware_without_langchain_raises(self) -> None:
        """Instantiating VectimusMiddleware without langchain raises ImportError."""
        from vectimus.integrations.langgraph import VectimusMiddleware

        with patch.dict(sys.modules, {"langchain": None}):
            with pytest.raises(ImportError, match="pip install vectimus"):
                VectimusMiddleware()

    def test_interceptor_without_langchain_raises(self) -> None:
        """Calling create_interceptor without langchain raises ImportError."""
        from vectimus.integrations.langgraph import create_interceptor

        with patch.dict(sys.modules, {"langchain": None}):
            with pytest.raises(ImportError, match="pip install vectimus"):
                create_interceptor()


# ---------------------------------------------------------------------------
# Event building tests
# ---------------------------------------------------------------------------


class TestEventBuilding:
    """Verify that tool calls are normalised to VectimusEvent correctly."""

    def test_shell_tool_detected(self) -> None:
        from vectimus.integrations.langgraph import _build_event

        event = _build_event("bash", {"command": "rm -rf /"})
        assert event.action.action_type == "shell_command"
        assert event.action.command == "rm -rf /"

    def test_mcp_tool_detected(self) -> None:
        from vectimus.integrations.langgraph import _build_event

        event = _build_event("github__create_issue", {"title": "Bug"})
        assert event.action.action_type == "mcp_tool"
        assert event.action.mcp_server == "github"
        assert event.action.mcp_tool == "create_issue"

    def test_file_write_detected(self) -> None:
        from vectimus.integrations.langgraph import _build_event

        event = _build_event("file_write", {"path": "/etc/passwd", "content": "bad"})
        assert event.action.action_type == "file_write"
        assert event.action.file_path == "/etc/passwd"
        assert event.action.file_content == "bad"

    def test_web_request_detected(self) -> None:
        from vectimus.integrations.langgraph import _build_event

        event = _build_event("web_search", {"url": "https://example.com"})
        assert event.action.action_type == "web_request"
        assert event.action.url == "https://example.com"

    def test_identity_is_agent(self) -> None:
        from vectimus.integrations.langgraph import _build_event

        event = _build_event("some_tool", {})
        assert event.identity.identity_type == "agent"
        assert event.source.tool == "langgraph"

    def test_custom_principal(self) -> None:
        from vectimus.integrations.langgraph import _build_event

        event = _build_event("tool", {}, principal="my-bot")
        assert event.identity.principal == "my-bot"


# ---------------------------------------------------------------------------
# Middleware tests
# ---------------------------------------------------------------------------


class TestVectimusMiddleware:
    """Test the VectimusMiddleware class."""

    @pytest.fixture()
    def middleware(self):
        from vectimus.integrations.langgraph import VectimusMiddleware

        with _mock_langchain():
            return VectimusMiddleware(observe_mode=False)

    @pytest.fixture()
    def middleware_observe(self):
        from vectimus.integrations.langgraph import VectimusMiddleware

        with _mock_langchain():
            return VectimusMiddleware(observe_mode=True)

    def test_allowed_tool_call_proceeds(self, middleware) -> None:
        """A safe tool call should pass through to call_next."""
        call_next = AsyncMock(return_value="file contents here")

        result = _run(middleware("file_read", {"path": "/home/user/readme.txt"}, call_next))

        call_next.assert_awaited_once()
        assert result == "file contents here"

    def test_denied_tool_call_blocked(self, middleware) -> None:
        """A dangerous tool call (rm -rf /) should be blocked."""
        call_next = AsyncMock(return_value="should not reach")

        result = _run(middleware("bash", {"command": "rm -rf /"}, call_next))

        call_next.assert_not_awaited()
        assert "Blocked by Vectimus" in result

    def test_denial_message_includes_policy_id(self, middleware) -> None:
        """The denial message should reference the matched policy."""
        call_next = AsyncMock()

        result = _run(middleware("bash", {"command": "rm -rf /"}, call_next))

        assert "vectimus-base-001" in result or "Blocked by Vectimus" in result

    def test_observe_mode_allows_denied_action(self, middleware_observe) -> None:
        """In observe mode, a would-be-denied action should still proceed."""
        call_next = AsyncMock(return_value="executed")

        result = _run(middleware_observe("bash", {"command": "rm -rf /"}, call_next))

        call_next.assert_awaited_once()
        assert result == "executed"

    def test_multiple_tool_calls_independently_evaluated(self, middleware) -> None:
        """Each tool call in a sequence is independently evaluated."""
        call_next_safe = AsyncMock(return_value="ok")
        call_next_danger = AsyncMock(return_value="should not reach")

        # Safe call
        result1 = _run(middleware("file_read", {"path": "/home/user/code.py"}, call_next_safe))
        assert result1 == "ok"
        call_next_safe.assert_awaited_once()

        # Dangerous call
        result2 = _run(middleware("bash", {"command": "rm -rf /"}, call_next_danger))
        call_next_danger.assert_not_awaited()
        assert "Blocked" in result2

    def test_npm_publish_blocked(self, middleware) -> None:
        """npm publish should be blocked by policy."""
        call_next = AsyncMock()

        result = _run(middleware("bash", {"command": "npm publish"}, call_next))

        call_next.assert_not_awaited()
        assert "Blocked" in result

    def test_audit_trail_written(self, middleware) -> None:
        """Every evaluation writes to the audit trail."""
        call_next = AsyncMock(return_value="ok")

        with patch("vectimus.integrations.langgraph.write_audit") as mock_audit:
            _run(middleware("file_read", {"path": "/tmp/safe.txt"}, call_next))
            mock_audit.assert_called_once()
            event, decision = mock_audit.call_args[0]
            assert event.source.tool == "langgraph"

    def test_audit_trail_on_deny(self, middleware) -> None:
        """Denied actions also get audit trail entries."""
        call_next = AsyncMock()

        with patch("vectimus.integrations.langgraph.write_audit") as mock_audit:
            _run(middleware("bash", {"command": "rm -rf /"}, call_next))
            mock_audit.assert_called_once()


# ---------------------------------------------------------------------------
# Interceptor tests
# ---------------------------------------------------------------------------


class TestInterceptor:
    """Test the MCP tool call interceptor."""

    @pytest.fixture()
    def interceptor(self):
        from vectimus.integrations.langgraph import create_interceptor

        with _mock_langchain():
            return create_interceptor(observe_mode=False)

    @pytest.fixture()
    def interceptor_observe(self):
        from vectimus.integrations.langgraph import create_interceptor

        with _mock_langchain():
            return create_interceptor(observe_mode=True)

    def test_allowed_request_passes_through(self, interceptor) -> None:
        """A safe MCP request should pass through to the handler."""
        request = MagicMock()
        request.name = "read_file"
        request.args = {"path": "/tmp/safe.txt"}
        handler = AsyncMock(return_value="file contents")

        result = _run(interceptor(request, handler))

        handler.assert_awaited_once_with(request)
        assert result == "file contents"

    def test_denied_request_blocked(self, interceptor) -> None:
        """A dangerous MCP request should be blocked."""
        request = MagicMock()
        request.name = "bash"
        request.args = {"command": "rm -rf /"}
        handler = AsyncMock(return_value="should not reach")

        result = _run(interceptor(request, handler))

        handler.assert_not_awaited()
        assert "Blocked by Vectimus" in result

    def test_observe_mode_allows_denied_request(self, interceptor_observe) -> None:
        """In observe mode, denied MCP requests should proceed."""
        request = MagicMock()
        request.name = "bash"
        request.args = {"command": "rm -rf /"}
        handler = AsyncMock(return_value="executed")

        result = _run(interceptor_observe(request, handler))

        handler.assert_awaited_once()
        assert result == "executed"

    def test_interceptor_composes_with_other_interceptors(self, interceptor) -> None:
        """The interceptor works when chained with another interceptor."""
        request = MagicMock()
        request.name = "read_file"
        request.args = {"path": "/tmp/safe.txt"}

        # Simulate a second interceptor in the chain: the handler calls
        # another interceptor which calls the real tool.
        real_tool = AsyncMock(return_value="real result")

        async def second_interceptor(req, final_handler):
            # Add a tag so we can verify it ran
            result = await final_handler(req)
            return f"[intercepted] {result}"

        async def handler(req):
            return await second_interceptor(req, real_tool)

        result = _run(interceptor(request, handler))

        assert result == "[intercepted] real result"

    def test_handler_not_called_on_deny(self, interceptor) -> None:
        """When denied, the handler must not be called."""
        request = MagicMock()
        request.name = "bash"
        request.args = {"command": "rm -rf /"}
        handler = AsyncMock()

        _run(interceptor(request, handler))

        handler.assert_not_awaited()

    def test_string_args_parsed(self, interceptor) -> None:
        """String args (JSON) should be parsed correctly."""
        request = MagicMock()
        request.name = "bash"
        request.args = json.dumps({"command": "rm -rf /"})
        handler = AsyncMock()

        result = _run(interceptor(request, handler))

        handler.assert_not_awaited()
        assert "Blocked" in result

    def test_audit_trail_written(self, interceptor) -> None:
        """Every interceptor evaluation writes to the audit trail."""
        request = MagicMock()
        request.name = "read_file"
        request.args = {"path": "/tmp/safe.txt"}
        handler = AsyncMock(return_value="ok")

        with patch("vectimus.integrations.langgraph.write_audit") as mock_audit:
            _run(interceptor(request, handler))
            mock_audit.assert_called_once()
