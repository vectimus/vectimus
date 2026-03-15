"""Automatic policy updates from the Vectimus API.

Three update paths exist:
1. Bundled policies ship with the pip package (handled by PolicyLoader).
2. ``vectimus policy update`` CLI command for manual sync (calls sync_policies()).
3. Auto-updater triggered by hook fires (calls check_for_updates()).

Downloaded policies are stored in ``~/.vectimus/policy-cache/`` and override
bundled policies when present. Sync metadata lives in
``~/.vectimus/policy-sync.json``.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

try:
    import structlog

    logger = structlog.get_logger(__name__)
except ImportError:  # pragma: no cover
    import logging

    logger = logging.getLogger(__name__)  # type: ignore[assignment]

DEFAULT_API_URL = "https://api.vectimus.com"
_CACHE_DIR = Path.home() / ".vectimus" / "policy-cache"
_SYNC_META_PATH = Path.home() / ".vectimus" / "policy-sync.json"
_REQUEST_TIMEOUT = 5  # seconds


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SyncResult:
    """Result of a policy sync operation."""

    version: str
    total_policies: int
    total_rules: int
    packs_updated: dict[str, int] = field(default_factory=dict)
    is_update: bool = False
    error: str | None = None


@dataclass
class SyncStatus:
    """Current state of policy synchronisation."""

    bundled_version: str
    cached_version: str | None
    last_check: datetime | None
    cache_dir: Path
    has_cache: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_bundled_version() -> str:
    """Return the version string from the installed vectimus package."""
    try:
        from vectimus import __version__

        return __version__
    except Exception:
        return "0.0.0"


def _api_get(url: str) -> dict:
    """Perform a GET request and return parsed JSON.

    Uses urllib from the stdlib so we avoid adding a dependency.
    """
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": f"vectimus/{_get_bundled_version()}",
        },
    )
    with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def _read_sync_meta() -> dict:
    """Read sync metadata from disk. Returns empty dict on any error."""
    try:
        return json.loads(_SYNC_META_PATH.read_text())
    except Exception:
        return {}


def _write_sync_meta(meta: dict) -> None:
    """Atomically write sync metadata to disk."""
    _SYNC_META_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _SYNC_META_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, indent=2))
    os.replace(tmp, _SYNC_META_PATH)


def _write_pack(pack_dir: Path, pack_name: str, version: str, cedar_source: str) -> None:
    """Write a single pack directory with pack.toml and policies.cedar.

    Uses atomic writes: content is written to a .tmp file first, then
    moved into place with os.replace().
    """
    pack_dir.mkdir(parents=True, exist_ok=True)

    # pack.toml
    toml_content = (
        "[pack]\n"
        f'name = "{pack_name}"\n'
        f'version = "{version}"\n'
        'description = "Vectimus official policies"\n'
    )
    toml_tmp = pack_dir / "pack.toml.tmp"
    toml_tmp.write_text(toml_content)
    os.replace(toml_tmp, pack_dir / "pack.toml")

    # policies.cedar
    cedar_tmp = pack_dir / "policies.cedar.tmp"
    cedar_tmp.write_text(cedar_source)
    os.replace(cedar_tmp, pack_dir / "policies.cedar")


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def _download_policies(*, api_url: str = DEFAULT_API_URL) -> SyncResult:
    """Fetch policies from the API and write them into the cache directory.

    Groups policies by pack name and writes each pack as a directory
    containing a ``pack.toml`` manifest and a single ``.cedar`` file with
    all rules concatenated.
    """
    data = _api_get(f"{api_url}/api/policies")

    version: str = data.get("version", "0.0.0")
    policies: list[dict] = data.get("policies", [])
    total_policies: int = data.get("total_policies", len(policies))
    total_rules: int = data.get("total_rules", 0)

    # Group policies by pack name.
    packs: dict[str, list[str]] = {}
    for policy in policies:
        pack_name = policy.get("pack", "default")
        source = policy.get("source", "")
        if source:
            packs.setdefault(pack_name, []).append(source)

    # Read existing metadata to determine if this is an update.
    old_meta = _read_sync_meta()
    is_update = old_meta.get("version") is not None and old_meta.get("version") != version

    # Write each pack to disk.
    packs_updated: dict[str, int] = {}
    for pack_name, sources in packs.items():
        pack_dir = _CACHE_DIR / pack_name
        cedar_text = "\n\n".join(sources)
        _write_pack(pack_dir, pack_name, version, cedar_text)
        packs_updated[pack_name] = len(sources)

    # Update sync metadata.
    _write_sync_meta(
        {
            "version": version,
            "last_check": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_policies": total_policies,
            "total_rules": total_rules,
        }
    )

    return SyncResult(
        version=version,
        total_policies=total_policies,
        total_rules=total_rules,
        packs_updated=packs_updated,
        is_update=is_update,
    )


def sync_policies(*, api_url: str = DEFAULT_API_URL) -> SyncResult:
    """Synchronously fetch and cache policies from the Vectimus API.

    Intended for the ``vectimus policy update`` CLI command. Fetches all
    policies, reconstructs pack directories in ``~/.vectimus/policy-cache/``
    and returns a :class:`SyncResult` describing what changed.
    """
    try:
        return _download_policies(api_url=api_url)
    except Exception as exc:
        logger.error("policy_sync_failed", error=str(exc))
        return SyncResult(
            version="",
            total_policies=0,
            total_rules=0,
            error=str(exc),
        )


def check_for_updates(
    *,
    api_url: str = DEFAULT_API_URL,
    check_interval_hours: int = 24,
) -> None:
    """Non-blocking check for policy updates.

    Spawns a daemon thread that:
    1. Reads ``~/.vectimus/policy-sync.json``. If the last check was within
       *check_interval_hours*, returns immediately.
    2. Hits ``/api/policies/stats`` and compares the reported version to the
       cached version.
    3. If a newer version is available, downloads the full policy set.

    All errors are silently caught and logged so this never disrupts
    normal hook evaluation.
    """

    def _run() -> None:
        try:
            meta = _read_sync_meta()
            last_check_str = meta.get("last_check")
            if last_check_str:
                try:
                    last_check = datetime.fromisoformat(last_check_str.replace("Z", "+00:00"))
                    elapsed = datetime.now(UTC) - last_check
                    if elapsed.total_seconds() < check_interval_hours * 3600:
                        return
                except (ValueError, TypeError):
                    pass  # Corrupted timestamp — proceed with check.

            stats = _api_get(f"{api_url}/api/policies/stats")
            remote_version = stats.get("version", "")
            cached_version = meta.get("version", "")

            if remote_version and remote_version != cached_version:
                logger.info(
                    "policy_update_available",
                    cached=cached_version,
                    remote=remote_version,
                )
                _download_policies(api_url=api_url)
            else:
                # No update needed — just touch last_check.
                meta["last_check"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                _write_sync_meta(meta)
        except Exception as exc:
            logger.debug("policy_update_check_failed", error=str(exc))

    t = threading.Thread(target=_run, daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Status / cache inspection
# ---------------------------------------------------------------------------


def get_sync_status() -> SyncStatus:
    """Return the current sync status.

    Provides the bundled package version, the cached version (if any),
    last check timestamp, cache directory path and whether a valid cache
    exists.
    """
    meta = _read_sync_meta()
    cached_version = meta.get("version")

    last_check: datetime | None = None
    last_check_str = meta.get("last_check")
    if last_check_str:
        try:
            last_check = datetime.fromisoformat(last_check_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass

    return SyncStatus(
        bundled_version=_get_bundled_version(),
        cached_version=cached_version,
        last_check=last_check,
        cache_dir=_CACHE_DIR,
        has_cache=get_policy_cache_dir() is not None,
    )


def get_policy_cache_dir() -> Path | None:
    """Return the policy cache directory if it exists and contains valid packs.

    Returns the path to ``~/.vectimus/policy-cache/`` when the directory
    exists and has at least one subdirectory containing a ``pack.toml`` file.
    Returns ``None`` otherwise, signalling that the loader should fall back
    to the bundled policies.
    """
    if not _CACHE_DIR.is_dir():
        return None

    # Require at least one pack.toml to treat the cache as valid.
    for subdir in _CACHE_DIR.iterdir():
        if subdir.is_dir() and (subdir / "pack.toml").exists():
            return _CACHE_DIR

    return None
