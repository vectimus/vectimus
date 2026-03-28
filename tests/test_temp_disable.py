"""Tests for temporary rule disable feature."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from vectimus.cli.rule_cmd import _format_remaining, _parse_duration


class TestParseDuration:
    """Test the _parse_duration helper."""

    def test_minutes(self) -> None:
        assert _parse_duration("30m") == 1800.0

    def test_hours(self) -> None:
        assert _parse_duration("2h") == 7200.0

    def test_seconds(self) -> None:
        assert _parse_duration("90s") == 90.0

    def test_combined_hours_minutes(self) -> None:
        assert _parse_duration("1h30m") == 5400.0

    def test_combined_all(self) -> None:
        assert _parse_duration("1h30m15s") == 5415.0

    def test_whitespace_stripped(self) -> None:
        assert _parse_duration("  5m  ") == 300.0

    def test_case_insensitive(self) -> None:
        assert _parse_duration("5M") == 300.0

    def test_invalid_raises(self) -> None:
        from click import BadParameter

        with pytest.raises(BadParameter):
            _parse_duration("abc")

    def test_empty_raises(self) -> None:
        from click import BadParameter

        with pytest.raises(BadParameter):
            _parse_duration("")

    def test_zero_raises(self) -> None:
        from click import BadParameter

        with pytest.raises(BadParameter):
            _parse_duration("0m")


class TestFormatRemaining:
    """Test the _format_remaining helper."""

    def test_seconds_only(self) -> None:
        assert _format_remaining(45) == "45s"

    def test_minutes(self) -> None:
        assert _format_remaining(300) == "5m"

    def test_hours(self) -> None:
        assert _format_remaining(3600) == "1h"

    def test_hours_and_minutes(self) -> None:
        assert _format_remaining(5400) == "1h30m"

    def test_zero(self) -> None:
        assert _format_remaining(0) == "0s"


class TestDaemonTempDisables:
    """Test DaemonServer temp disable state management."""

    def _make_server(self):
        from vectimus.engine.daemon import DaemonServer

        return DaemonServer()

    def test_handle_temp_disable(self) -> None:
        server = self._make_server()
        resp = server._handle_temp_disable(
            {
                "temp_disable": "secret-in-env",
                "project": "/tmp/myproject",
                "duration_s": 1800,
            }
        )
        assert resp["status"] == "ok"
        assert resp["rule_id"] == "secret-in-env"
        assert ("/tmp/myproject", "secret-in-env") in server._temp_disables

    def test_handle_temp_disable_missing_fields(self) -> None:
        server = self._make_server()
        resp = server._handle_temp_disable(
            {
                "temp_disable": "",
                "project": "/tmp/myproject",
                "duration_s": 0,
            }
        )
        assert resp["status"] == "error"

    def test_active_temp_disables(self) -> None:
        server = self._make_server()
        # Add a disable that expires in the future.
        server._temp_disables[("/tmp/proj", "rule-a")] = time.monotonic() + 1000
        # Add a disable that already expired.
        server._temp_disables[("/tmp/proj", "rule-b")] = time.monotonic() - 1

        active = server._active_temp_disables("/tmp/proj")
        assert active == {"rule-a"}
        # Expired entry should be cleaned up.
        assert ("/tmp/proj", "rule-b") not in server._temp_disables

    def test_active_temp_disables_project_isolation(self) -> None:
        server = self._make_server()
        server._temp_disables[("/tmp/proj1", "rule-a")] = time.monotonic() + 1000
        server._temp_disables[("/tmp/proj2", "rule-b")] = time.monotonic() + 1000

        assert server._active_temp_disables("/tmp/proj1") == {"rule-a"}
        assert server._active_temp_disables("/tmp/proj2") == {"rule-b"}

    def test_clear_temp_disable(self) -> None:
        server = self._make_server()
        server._temp_disables[("/tmp/proj", "rule-a")] = time.monotonic() + 1000

        resp = server._handle_clear_temp_disable(
            {
                "clear_temp_disable": "rule-a",
                "project": "/tmp/proj",
            }
        )
        assert resp["status"] == "ok"
        assert ("/tmp/proj", "rule-a") not in server._temp_disables

    def test_clear_temp_disable_not_found(self) -> None:
        server = self._make_server()
        resp = server._handle_clear_temp_disable(
            {
                "clear_temp_disable": "nonexistent",
                "project": "/tmp/proj",
            }
        )
        assert resp["status"] == "not_found"

    def test_query_temp_disables(self) -> None:
        server = self._make_server()
        server._temp_disables[("/tmp/proj", "rule-a")] = time.monotonic() + 600
        server._temp_disables[("/tmp/proj", "rule-b")] = time.monotonic() + 1200

        resp = server._handle_query_temp_disables(
            {
                "query_temp_disables": True,
                "project": "/tmp/proj",
            }
        )
        assert resp["status"] == "ok"
        rule_ids = {e["rule_id"] for e in resp["temp_disables"]}
        assert rule_ids == {"rule-a", "rule-b"}

    def test_query_temp_disables_filters_expired(self) -> None:
        server = self._make_server()
        server._temp_disables[("/tmp/proj", "rule-a")] = time.monotonic() + 600
        server._temp_disables[("/tmp/proj", "rule-b")] = time.monotonic() - 1

        resp = server._handle_query_temp_disables(
            {
                "query_temp_disables": True,
                "project": "/tmp/proj",
            }
        )
        rule_ids = {e["rule_id"] for e in resp["temp_disables"]}
        assert rule_ids == {"rule-a"}

    def test_temp_disable_invalidates_engine_cache(self) -> None:
        server = self._make_server()
        # Simulate a cached engine for the project.
        server._engines[("/tmp/proj", False)] = MagicMock()

        server._handle_temp_disable(
            {
                "temp_disable": "rule-a",
                "project": "/tmp/proj",
                "duration_s": 600,
            }
        )

        # Engine cache should be cleared for that project.
        assert ("/tmp/proj", False) not in server._engines

    def test_temp_disable_overwrite_extends(self) -> None:
        """Calling temp_disable again for the same rule updates the expiry."""
        server = self._make_server()
        server._handle_temp_disable(
            {
                "temp_disable": "rule-a",
                "project": "/tmp/proj",
                "duration_s": 60,
            }
        )
        first_expiry = server._temp_disables[("/tmp/proj", "rule-a")]

        server._handle_temp_disable(
            {
                "temp_disable": "rule-a",
                "project": "/tmp/proj",
                "duration_s": 3600,
            }
        )
        second_expiry = server._temp_disables[("/tmp/proj", "rule-a")]
        assert second_expiry > first_expiry


class TestLoaderExtraDisabledRules:
    """Test that PolicyLoader respects extra_disabled_rules."""

    def test_extra_disabled_rules_merged(self, tmp_path) -> None:
        """Extra disabled rules should be merged with config-based disables."""
        from vectimus.engine.loader import PolicyLoader

        loader = PolicyLoader(
            policy_dirs=[str(tmp_path)],
            project_path=tmp_path,
            extra_disabled_rules={"test-rule"},
        )
        assert "test-rule" in loader._extra_disabled_rules

    def test_extra_disabled_rules_default_empty(self, tmp_path) -> None:
        from vectimus.engine.loader import PolicyLoader

        loader = PolicyLoader(policy_dirs=[str(tmp_path)], project_path=tmp_path)
        assert loader._extra_disabled_rules == set()
