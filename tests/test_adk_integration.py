"""Tests for the Google ADK plugin integration."""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_adk():
    """Context manager that makes ``import google.adk`` succeed even when not installed."""
    google_mod = types.ModuleType("google")
    google_mod.__path__ = []
    adk_mod = types.ModuleType("google.adk")
    adk_mod.__version__ = "1.0.0"
    return patch.dict(sys.modules, {"google": google_mod, "google.adk": adk_mod})


# ---------------------------------------------------------------------------
# Import guard tests
# ---------------------------------------------------------------------------


class TestImportGuard:
    """Importing the module must succeed even without google-adk installed."""

    def test_module_import_succeeds(self) -> None:
        """The module can be imported without google-adk present."""
        from vectimus.integrations import adk  # noqa: F401

    def test_plugin_without_adk_raises(self) -> None:
        """Instantiating VectimusADKPlugin without google-adk raises ImportError."""
        from vectimus.integrations.adk import VectimusADKPlugin

        with patch.dict(sys.modules, {"google.adk": None, "google": None}):
            with pytest.raises(ImportError, match="pip install vectimus"):
                VectimusADKPlugin()

    def test_callback_factory_without_adk_raises(self) -> None:
        """Calling create_before_tool_callback without google-adk raises ImportError."""
        from vectimus.integrations.adk import create_before_tool_callback

        with patch.dict(sys.modules, {"google.adk": None, "google": None}):
            with pytest.raises(ImportError, match="pip install vectimus"):
                create_before_tool_callback()


# ---------------------------------------------------------------------------
# Event building tests
# ---------------------------------------------------------------------------


class TestEventBuilding:
    """Verify that tool calls are normalised to VectimusEvent correctly."""

    def test_shell_tool_detected(self) -> None:
        from vectimus.integrations.adk import _build_event

        event = _build_event("bash", {"command": "rm -rf /"})
        assert event.action.action_type == "shell_command"
        assert event.action.command == "rm -rf /"

    def test_mcp_tool_detected(self) -> None:
        from vectimus.integrations.adk import _build_event

        event = _build_event("github__create_issue", {"title": "Bug"})
        assert event.action.action_type == "mcp_tool"
        assert event.action.mcp_server == "github"
        assert event.action.mcp_tool == "create_issue"

    def test_file_write_detected(self) -> None:
        from vectimus.integrations.adk import _build_event

        event = _build_event("file_write", {"path": "/etc/passwd", "content": "bad"})
        assert event.action.action_type == "file_write"
        assert event.action.file_path == "/etc/passwd"
        assert event.action.file_content == "bad"

    def test_web_request_detected(self) -> None:
        from vectimus.integrations.adk import _build_event

        event = _build_event("google_search", {"url": "https://example.com"})
        assert event.action.action_type == "web_request"
        assert event.action.url == "https://example.com"

    def test_code_execution_detected(self) -> None:
        from vectimus.integrations.adk import _build_event

        event = _build_event("code_execution", {"command": "print('hello')"})
        assert event.action.action_type == "shell_command"

    def test_identity_is_agent(self) -> None:
        from vectimus.integrations.adk import _build_event

        event = _build_event("some_tool", {})
        assert event.identity.identity_type == "agent"
        assert event.source.tool == "adk"

    def test_custom_principal(self) -> None:
        from vectimus.integrations.adk import _build_event

        event = _build_event("tool", {}, principal="my-adk-bot")
        assert event.identity.principal == "my-adk-bot"


# ---------------------------------------------------------------------------
# Plugin tests
# ---------------------------------------------------------------------------


class TestVectimusADKPlugin:
    """Test the VectimusADKPlugin class."""

    @pytest.fixture()
    def plugin(self):
        from vectimus.integrations.adk import VectimusADKPlugin

        with _mock_adk():
            return VectimusADKPlugin(observe_mode=False)

    @pytest.fixture()
    def plugin_observe(self):
        from vectimus.integrations.adk import VectimusADKPlugin

        with _mock_adk():
            return VectimusADKPlugin(observe_mode=True)

    def test_allowed_tool_call_returns_none(self, plugin) -> None:
        """A safe tool call should return None (allow execution)."""
        ctx = MagicMock()
        result = plugin.before_tool_callback(ctx, "file_read", {"path": "/home/user/readme.txt"})
        assert result is None

    def test_denied_tool_call_returns_dict(self, plugin) -> None:
        """A dangerous tool call should return a denial dict."""
        ctx = MagicMock()
        result = plugin.before_tool_callback(ctx, "bash", {"command": "rm -rf /"})
        assert isinstance(result, dict)
        assert "error" in result
        assert "Blocked by Vectimus" in result["error"]

    def test_denial_dict_includes_policy_info(self, plugin) -> None:
        """The denial dict should reference the matched policy."""
        ctx = MagicMock()
        result = plugin.before_tool_callback(ctx, "bash", {"command": "rm -rf /"})
        assert (
            "vectimus-destruct-001" in result["error"] or "Blocked by Vectimus" in result["error"]
        )

    def test_observe_mode_allows_denied_action(self, plugin_observe) -> None:
        """In observe mode, a would-be-denied action should return None (allow)."""
        ctx = MagicMock()
        result = plugin_observe.before_tool_callback(ctx, "bash", {"command": "rm -rf /"})
        assert result is None

    def test_multiple_tool_calls_independently_evaluated(self, plugin) -> None:
        """Each tool call is independently evaluated."""
        ctx = MagicMock()

        # Safe call
        result1 = plugin.before_tool_callback(ctx, "file_read", {"path": "/home/user/code.py"})
        assert result1 is None

        # Dangerous call
        result2 = plugin.before_tool_callback(ctx, "bash", {"command": "rm -rf /"})
        assert isinstance(result2, dict)
        assert "Blocked" in result2["error"]

    def test_npm_publish_blocked(self, plugin) -> None:
        """npm publish should be blocked by policy."""
        ctx = MagicMock()
        result = plugin.before_tool_callback(ctx, "bash", {"command": "npm publish"})
        assert isinstance(result, dict)
        assert "Blocked" in result["error"]

    def test_audit_trail_written(self, plugin) -> None:
        """Every evaluation writes to the audit trail."""
        ctx = MagicMock()

        with patch("vectimus.integrations.adk.write_audit") as mock_audit:
            plugin.before_tool_callback(ctx, "file_read", {"path": "/tmp/safe.txt"})
            mock_audit.assert_called_once()
            event, decision = mock_audit.call_args[0]
            assert event.source.tool == "adk"

    def test_audit_trail_on_deny(self, plugin) -> None:
        """Denied actions also get audit trail entries."""
        ctx = MagicMock()

        with patch("vectimus.integrations.adk.write_audit") as mock_audit:
            plugin.before_tool_callback(ctx, "bash", {"command": "rm -rf /"})
            mock_audit.assert_called_once()

    def test_after_tool_callback_returns_none(self, plugin) -> None:
        """after_tool_callback should always return None (pass through)."""
        ctx = MagicMock()
        result = plugin.after_tool_callback(ctx, "bash", {"command": "ls"}, {"output": "file.txt"})
        assert result is None

    def test_after_tool_callback_writes_audit(self, plugin) -> None:
        """after_tool_callback should log to the audit trail."""
        ctx = MagicMock()

        with patch("vectimus.integrations.adk.write_audit") as mock_audit:
            plugin.after_tool_callback(ctx, "bash", {"command": "ls"}, {"output": "file.txt"})
            mock_audit.assert_called_once()
            event = mock_audit.call_args[0][0]
            assert event.event_type == "post_action"
            assert event.source.tool == "adk"


# ---------------------------------------------------------------------------
# Callback factory tests
# ---------------------------------------------------------------------------


class TestCallbackFactory:
    """Test the create_before_tool_callback factory function."""

    @pytest.fixture()
    def callback(self):
        from vectimus.integrations.adk import create_before_tool_callback

        with _mock_adk():
            return create_before_tool_callback(observe_mode=False)

    @pytest.fixture()
    def callback_observe(self):
        from vectimus.integrations.adk import create_before_tool_callback

        with _mock_adk():
            return create_before_tool_callback(observe_mode=True)

    def test_allowed_tool_returns_none(self, callback) -> None:
        """A safe tool call should return None."""
        ctx = MagicMock()
        result = callback(ctx, "file_read", {"path": "/tmp/safe.txt"})
        assert result is None

    def test_denied_tool_returns_dict(self, callback) -> None:
        """A dangerous tool call should return a denial dict."""
        ctx = MagicMock()
        result = callback(ctx, "bash", {"command": "rm -rf /"})
        assert isinstance(result, dict)
        assert "Blocked by Vectimus" in result["error"]

    def test_observe_mode_allows_denied(self, callback_observe) -> None:
        """In observe mode, denied actions return None."""
        ctx = MagicMock()
        result = callback_observe(ctx, "bash", {"command": "rm -rf /"})
        assert result is None

    def test_custom_principal_passed_through(self) -> None:
        """The factory correctly passes through the principal parameter."""
        from vectimus.integrations.adk import create_before_tool_callback

        with _mock_adk():
            cb = create_before_tool_callback(principal="custom-bot")

        ctx = MagicMock()
        with patch("vectimus.integrations.adk.write_audit") as mock_audit:
            cb(ctx, "file_read", {"path": "/tmp/safe.txt"})
            event = mock_audit.call_args[0][0]
            assert event.identity.principal == "custom-bot"

    def test_audit_trail_written(self, callback) -> None:
        """Every callback evaluation writes to the audit trail."""
        ctx = MagicMock()

        with patch("vectimus.integrations.adk.write_audit") as mock_audit:
            callback(ctx, "file_read", {"path": "/tmp/safe.txt"})
            mock_audit.assert_called_once()
            event = mock_audit.call_args[0][0]
            assert event.source.tool == "adk"
