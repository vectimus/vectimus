"""Centralized daemon info file management.

On Unix/macOS the daemon uses a Unix domain socket at
``/tmp/vectimus-{uid}.sock`` with a PID file for lifecycle checks.
Filesystem permissions handle authentication — no token required.

On Windows the daemon uses TCP localhost with an auth token.  The
info file at ``~/.vectimus/daemon.json`` stores the PID, port and
token.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

_IS_WINDOWS = os.name == "nt"

# Windows: single JSON info file with PID, port and auth token.
DAEMON_INFO_PATH = Path.home() / ".vectimus" / "daemon.json"

# Unix: socket and PID file in /tmp, scoped to the current user.
if not _IS_WINDOWS:
    SOCKET_PATH = Path(f"/tmp/vectimus-{os.getuid()}.sock")
    PID_PATH = Path(f"/tmp/vectimus-{os.getuid()}.pid")
else:
    SOCKET_PATH = None  # type: ignore[assignment]
    PID_PATH = None  # type: ignore[assignment]


def write_daemon_info(pid: int, port: int, token: str) -> None:
    """Write daemon info to disk with user-only permissions (Windows only).

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


def write_pid_file(pid: int) -> None:
    """Write the daemon PID file (Unix only)."""
    PID_PATH.write_text(str(pid))


def read_daemon_info() -> dict | None:
    """Read daemon connection info.

    On Unix, returns ``{"pid": int}`` from the PID file (socket path is
    a module constant).  On Windows, returns ``{"pid", "port", "token"}``
    from the JSON info file.  Returns ``None`` if missing or corrupt.
    """
    if _IS_WINDOWS:
        try:
            data = json.loads(DAEMON_INFO_PATH.read_text())
            if "pid" in data and "port" in data and "token" in data:
                return data
            return None
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None
    else:
        try:
            pid = int(PID_PATH.read_text().strip())
            return {"pid": pid}
        except (FileNotFoundError, ValueError, OSError):
            return None


def remove_daemon_info() -> None:
    """Remove daemon info / socket / PID files."""
    if _IS_WINDOWS:
        DAEMON_INFO_PATH.unlink(missing_ok=True)
    else:
        SOCKET_PATH.unlink(missing_ok=True)
        PID_PATH.unlink(missing_ok=True)


def is_daemon_alive(info: dict | None = None) -> bool:
    """Check if the daemon process is still running."""
    if info is None:
        info = read_daemon_info()
    if info is None:
        return False
    pid = info["pid"]
    if _IS_WINDOWS:
        import ctypes
        import ctypes.wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.wintypes.DWORD()
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return exit_code.value == STILL_ACTIVE
            return False
        finally:
            kernel32.CloseHandle(handle)
    else:
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, OSError):
            return False
