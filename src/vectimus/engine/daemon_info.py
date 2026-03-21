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
import stat
from pathlib import Path

DAEMON_INFO_PATH = Path.home() / ".vectimus" / "daemon.json"


def write_daemon_info(pid: int, port: int, token: str) -> None:
    """Write daemon info to disk with user-only permissions."""
    DAEMON_INFO_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps({"pid": pid, "port": port, "token": token})
    DAEMON_INFO_PATH.write_text(data)
    try:
        DAEMON_INFO_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # best-effort on platforms where chmod is limited


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
