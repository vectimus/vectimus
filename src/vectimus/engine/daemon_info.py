"""Centralized daemon info file management.

The daemon writes a JSON file with its PID, TCP port and auth token
on startup.  The client reads it to connect.  This module eliminates
the 3-file duplication of path constants and provides cross-platform
helpers for daemon lifecycle management.

Daemon info file: ``~/.vectimus/daemon.json``
"""

from __future__ import annotations

import json
import os
from pathlib import Path

DAEMON_INFO_PATH = Path.home() / ".vectimus" / "daemon.json"


def write_daemon_info(pid: int, port: int, token: str) -> None:
    """Write daemon info to disk with user-only permissions.

    Uses os.open with 0o600 at creation time to avoid a TOCTOU window
    where the auth token would be briefly world-readable.
    """
    DAEMON_INFO_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps({"pid": pid, "port": port, "token": token})
    fd = os.open(str(DAEMON_INFO_PATH), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        f = os.fdopen(fd, "w")
    except BaseException:
        os.close(fd)
        raise
    with f:
        f.write(data)


def read_daemon_info() -> dict | None:
    """Read daemon info.  Returns None if file missing or corrupt."""
    try:
        data = json.loads(DAEMON_INFO_PATH.read_text())
        if "pid" in data and "port" in data and "token" in data:
            return data
        return None
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def remove_daemon_info() -> None:
    """Remove the daemon info file."""
    DAEMON_INFO_PATH.unlink(missing_ok=True)


def is_daemon_alive(info: dict | None = None) -> bool:
    """Check if the daemon process is still running."""
    if info is None:
        info = read_daemon_info()
    if info is None:
        return False
    try:
        os.kill(info["pid"], 0)
        return True
    except (ProcessLookupError, OSError):
        return False
