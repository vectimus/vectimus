"""Tests for policy_sync: cache inspection, sync, auto-update and error handling."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vectimus.engine import policy_sync
from vectimus.engine.policy_sync import (
    SyncResult,
    SyncStatus,
    _api_get,
    _read_sync_meta,
    _should_check_updates,
    _write_sync_meta,
    check_for_updates,
    get_policy_cache_dir,
    get_sync_status,
    sync_policies,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_API_RESPONSE = {
    "version": "1.2.0",
    "total_policies": 3,
    "total_rules": 5,
    "policies": [
        {"pack": "base", "source": '@id("rule-001")\nforbid(principal, action, resource);'},
        {"pack": "base", "source": '@id("rule-002")\nforbid(principal, action, resource);'},
        {"pack": "owasp", "source": '@id("owasp-001")\nforbid(principal, action, resource);'},
    ],
}


def _make_urlopen_response(data: dict) -> MagicMock:
    """Build a mock that behaves like urllib.request.urlopen().__enter__()."""
    body = json.dumps(data).encode()
    resp = MagicMock()
    resp.read.return_value = body
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


@pytest.fixture(autouse=True)
def _isolate_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect module-level _CACHE_DIR and _SYNC_META_PATH to tmp_path."""
    cache_dir = tmp_path / "policy-cache"
    meta_path = tmp_path / "policy-sync.json"
    monkeypatch.setattr(policy_sync, "_CACHE_DIR", cache_dir)
    monkeypatch.setattr(policy_sync, "_SYNC_META_PATH", meta_path)


# ---------------------------------------------------------------------------
# get_policy_cache_dir
# ---------------------------------------------------------------------------


class TestGetPolicyCacheDir:
    """Test cache directory detection."""

    def test_returns_none_when_dir_missing(self) -> None:
        assert get_policy_cache_dir() is None

    def test_returns_none_when_empty(self, tmp_path: Path) -> None:
        cache = tmp_path / "policy-cache"
        cache.mkdir()
        assert get_policy_cache_dir() is None

    def test_returns_none_when_no_pack_toml(self, tmp_path: Path) -> None:
        cache = tmp_path / "policy-cache"
        subdir = cache / "stale"
        subdir.mkdir(parents=True)
        (subdir / "random.txt").write_text("not a pack")
        assert get_policy_cache_dir() is None

    def test_returns_path_when_valid_pack_exists(self, tmp_path: Path) -> None:
        cache = tmp_path / "policy-cache"
        pack = cache / "base"
        pack.mkdir(parents=True)
        (pack / "pack.toml").write_text('[pack]\nname = "base"\n')
        result = get_policy_cache_dir()
        assert result == cache


# ---------------------------------------------------------------------------
# get_sync_status
# ---------------------------------------------------------------------------


class TestGetSyncStatus:
    """Test sync status reporting."""

    def test_returns_bundled_version(self) -> None:
        status = get_sync_status()
        assert isinstance(status, SyncStatus)
        assert isinstance(status.bundled_version, str)
        assert status.bundled_version != ""

    def test_no_cache(self) -> None:
        status = get_sync_status()
        assert status.cached_version is None
        assert status.last_check is None
        assert status.has_cache is False

    def test_with_existing_cache(self, tmp_path: Path) -> None:
        # Write sync metadata.
        _write_sync_meta(
            {
                "version": "1.0.0",
                "last_check": "2026-03-10T12:00:00Z",
                "total_policies": 10,
                "total_rules": 20,
            }
        )
        # Create a valid cache directory.
        cache = tmp_path / "policy-cache"
        pack = cache / "base"
        pack.mkdir(parents=True)
        (pack / "pack.toml").write_text('[pack]\nname = "base"\n')

        status = get_sync_status()
        assert status.cached_version == "1.0.0"
        assert status.has_cache is True
        assert status.last_check is not None
        assert status.last_check.year == 2026

    def test_corrupt_metadata_handled(self, tmp_path: Path) -> None:
        meta_path = tmp_path / "policy-sync.json"
        meta_path.write_text("{invalid json!!")
        status = get_sync_status()
        # Should not raise — falls back to empty metadata.
        assert status.cached_version is None

    def test_corrupt_last_check_handled(self) -> None:
        _write_sync_meta(
            {
                "version": "1.0.0",
                "last_check": "not-a-date",
            }
        )
        status = get_sync_status()
        assert status.cached_version == "1.0.0"
        assert status.last_check is None


# ---------------------------------------------------------------------------
# sync_policies
# ---------------------------------------------------------------------------


class TestSyncPolicies:
    """Test synchronous policy download and caching."""

    @patch("vectimus.engine.policy_sync._api_get")
    def test_creates_pack_directories(self, mock_get: MagicMock, tmp_path: Path) -> None:
        mock_get.return_value = FAKE_API_RESPONSE
        result = sync_policies(api_url="https://fake.api")

        assert isinstance(result, SyncResult)
        assert result.version == "1.2.0"
        assert result.total_policies == 3
        assert result.total_rules == 5
        assert result.error is None

        cache = tmp_path / "policy-cache"
        assert (cache / "base").is_dir()
        assert (cache / "owasp").is_dir()

    @patch("vectimus.engine.policy_sync._api_get")
    def test_writes_pack_toml(self, mock_get: MagicMock, tmp_path: Path) -> None:
        mock_get.return_value = FAKE_API_RESPONSE
        sync_policies(api_url="https://fake.api")

        toml_text = (tmp_path / "policy-cache" / "base" / "pack.toml").read_text()
        assert 'name = "base"' in toml_text
        assert 'version = "1.2.0"' in toml_text

    @patch("vectimus.engine.policy_sync._api_get")
    def test_writes_cedar_file(self, mock_get: MagicMock, tmp_path: Path) -> None:
        mock_get.return_value = FAKE_API_RESPONSE
        sync_policies(api_url="https://fake.api")

        cedar = (tmp_path / "policy-cache" / "base" / "policies.cedar").read_text()
        assert "rule-001" in cedar
        assert "rule-002" in cedar

        owasp_cedar = (tmp_path / "policy-cache" / "owasp" / "policies.cedar").read_text()
        assert "owasp-001" in owasp_cedar

    @patch("vectimus.engine.policy_sync._api_get")
    def test_updates_metadata(self, mock_get: MagicMock, tmp_path: Path) -> None:
        mock_get.return_value = FAKE_API_RESPONSE
        sync_policies(api_url="https://fake.api")

        meta = json.loads((tmp_path / "policy-sync.json").read_text())
        assert meta["version"] == "1.2.0"
        assert meta["total_policies"] == 3
        assert "last_check" in meta

    @patch("vectimus.engine.policy_sync._api_get")
    def test_packs_updated_counts(self, mock_get: MagicMock) -> None:
        mock_get.return_value = FAKE_API_RESPONSE
        result = sync_policies(api_url="https://fake.api")

        assert result.packs_updated == {"base": 2, "owasp": 1}

    @patch("vectimus.engine.policy_sync._api_get")
    def test_is_update_false_on_first_sync(self, mock_get: MagicMock) -> None:
        mock_get.return_value = FAKE_API_RESPONSE
        result = sync_policies(api_url="https://fake.api")
        assert result.is_update is False

    @patch("vectimus.engine.policy_sync._api_get")
    def test_is_update_true_on_version_change(self, mock_get: MagicMock) -> None:
        # Seed existing metadata with an older version.
        _write_sync_meta({"version": "1.0.0", "last_check": "2026-01-01T00:00:00Z"})

        mock_get.return_value = FAKE_API_RESPONSE  # version 1.2.0
        result = sync_policies(api_url="https://fake.api")
        assert result.is_update is True

    @patch("vectimus.engine.policy_sync._api_get")
    def test_policies_without_pack_field_use_default(
        self, mock_get: MagicMock, tmp_path: Path
    ) -> None:
        mock_get.return_value = {
            "version": "1.0.0",
            "total_policies": 1,
            "total_rules": 1,
            "policies": [
                {"source": '@id("no-pack")\nforbid(principal, action, resource);'},
            ],
        }
        sync_policies(api_url="https://fake.api")
        assert (tmp_path / "policy-cache" / "default" / "pack.toml").exists()

    @patch("vectimus.engine.policy_sync._api_get")
    def test_empty_source_skipped(self, mock_get: MagicMock) -> None:
        mock_get.return_value = {
            "version": "1.0.0",
            "total_policies": 1,
            "total_rules": 0,
            "policies": [
                {"pack": "base", "source": ""},
            ],
        }
        result = sync_policies(api_url="https://fake.api")
        # Empty source should not create a pack.
        assert result.packs_updated == {}


# ---------------------------------------------------------------------------
# check_for_updates
# ---------------------------------------------------------------------------


class TestShouldCheckUpdates:
    """Test the interval-based check logic."""

    def test_returns_true_when_no_metadata(self) -> None:
        assert _should_check_updates(check_interval_hours=24) is True

    def test_returns_false_when_recently_checked(self) -> None:
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        _write_sync_meta({"version": "1.0.0", "last_check": now})
        assert _should_check_updates(check_interval_hours=24) is False

    def test_returns_true_when_check_expired(self) -> None:
        _write_sync_meta({"version": "1.0.0", "last_check": "2020-01-01T00:00:00Z"})
        assert _should_check_updates(check_interval_hours=1) is True

    def test_returns_true_when_corrupted_timestamp(self) -> None:
        _write_sync_meta({"version": "1.0.0", "last_check": "not-a-date"})
        assert _should_check_updates(check_interval_hours=24) is True


class TestCheckForUpdates:
    """Test non-blocking background update checks."""

    @patch("subprocess.Popen")
    def test_spawns_subprocess_when_check_needed(self, mock_popen: MagicMock) -> None:
        # No metadata and auto_sync caller — check should be triggered.
        check_for_updates(api_url="https://fake.api")
        mock_popen.assert_called_once()

    @patch("subprocess.Popen")
    def test_auto_sync_disabled_by_default_in_config(self, mock_popen: MagicMock) -> None:
        """Config.is_auto_sync_enabled() defaults to False — hook callers
        should gate on this before invoking check_for_updates()."""
        from vectimus.engine.config import VectimusConfig

        with patch.object(VectimusConfig, "_load"):
            cfg = VectimusConfig.__new__(VectimusConfig)
            cfg._data = {}
            cfg._path = Path("/dev/null")
            assert cfg.is_auto_sync_enabled() is False

    @patch("subprocess.Popen")
    def test_skips_when_recently_checked(self, mock_popen: MagicMock) -> None:
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        _write_sync_meta({"version": "1.0.0", "last_check": now})

        check_for_updates(api_url="https://fake.api", check_interval_hours=24)
        mock_popen.assert_not_called()

    @patch("subprocess.Popen", side_effect=OSError("spawn failed"))
    def test_error_silently_caught(self, mock_popen: MagicMock) -> None:
        # Should not raise even though Popen fails.
        check_for_updates(api_url="https://fake.api")


# ---------------------------------------------------------------------------
# _api_get
# ---------------------------------------------------------------------------


class TestApiGet:
    """Test the low-level HTTP helper."""

    @patch("urllib.request.urlopen")
    def test_returns_parsed_json(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response({"status": "ok"})
        result = _api_get("https://api.example.com/test")
        assert result == {"status": "ok"}

    @patch("urllib.request.urlopen")
    def test_sends_accept_header(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response({})
        _api_get("https://api.example.com/test")

        # Inspect the Request object that was passed.
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.get_header("Accept") == "application/json"

    @patch("urllib.request.urlopen")
    def test_sets_timeout(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response({})
        _api_get("https://api.example.com/test")

        call_args = mock_urlopen.call_args
        assert call_args[1].get("timeout") == 5 or call_args[0][1] == 5


# ---------------------------------------------------------------------------
# _read_sync_meta / _write_sync_meta
# ---------------------------------------------------------------------------


class TestSyncMeta:
    """Test metadata read/write helpers."""

    def test_read_returns_empty_when_missing(self) -> None:
        assert _read_sync_meta() == {}

    def test_roundtrip(self) -> None:
        data = {"version": "1.0.0", "last_check": "2026-03-15T00:00:00Z"}
        _write_sync_meta(data)
        assert _read_sync_meta() == data

    def test_read_corrupt_returns_empty(self, tmp_path: Path) -> None:
        meta_path = tmp_path / "policy-sync.json"
        meta_path.write_text("{{broken")
        assert _read_sync_meta() == {}

    def test_write_creates_parent_dirs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        nested = tmp_path / "deep" / "nested" / "policy-sync.json"
        monkeypatch.setattr(policy_sync, "_SYNC_META_PATH", nested)
        _write_sync_meta({"version": "1.0.0"})
        assert nested.exists()
        assert json.loads(nested.read_text())["version"] == "1.0.0"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Test graceful error recovery."""

    @patch("vectimus.engine.policy_sync._api_get")
    def test_network_failure_returns_error_result(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = ConnectionError("DNS resolution failed")
        result = sync_policies(api_url="https://fake.api")

        assert isinstance(result, SyncResult)
        assert result.error is not None
        assert "DNS resolution" in result.error
        assert result.version == ""
        assert result.total_policies == 0

    @patch("vectimus.engine.policy_sync._api_get")
    def test_timeout_returns_error_result(self, mock_get: MagicMock) -> None:
        import urllib.error

        mock_get.side_effect = urllib.error.URLError("timed out")
        result = sync_policies(api_url="https://fake.api")

        assert result.error is not None
        assert "timed out" in result.error

    @patch("vectimus.engine.policy_sync._api_get")
    def test_malformed_response_returns_error(self, mock_get: MagicMock) -> None:
        # Return something that will cause a KeyError or similar downstream.
        mock_get.return_value = "not a dict"
        result = sync_policies(api_url="https://fake.api")
        # The module should catch any exception.
        assert result.error is not None or result.version == ""

    @patch("vectimus.engine.policy_sync._api_get")
    def test_empty_policies_list(self, mock_get: MagicMock) -> None:
        mock_get.return_value = {
            "version": "1.0.0",
            "total_policies": 0,
            "total_rules": 0,
            "policies": [],
        }
        result = sync_policies(api_url="https://fake.api")
        assert result.error is None
        assert result.total_policies == 0
        assert result.packs_updated == {}
