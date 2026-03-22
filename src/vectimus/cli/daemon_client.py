"""Thin client for the Vectimus evaluation daemon.

On Unix/macOS connects via Unix domain socket.  On Windows connects
via TCP localhost with auth token.  Falls back to ``None`` if the
daemon is unavailable so the caller can use inline evaluation instead.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

from vectimus.engine.daemon_info import _IS_WINDOWS, is_daemon_alive, read_daemon_info

if not _IS_WINDOWS:
    from vectimus.engine.daemon_info import SOCKET_PATH

# Timeout for the entire round-trip (connect + send + recv).
_SOCKET_TIMEOUT = 2.0

# How long to wait for the daemon to start on cold boot.
_STARTUP_WAIT = 1.0
_STARTUP_POLL_INTERVAL = 0.05


def daemon_evaluate(source: str, payload: dict, cwd: str) -> dict | None:
    """Evaluate via the daemon.  Returns ``None`` if unavailable.

    When the daemon is not running and ``VECTIMUS_NO_DAEMON`` is not set,
    an auto-start is attempted.  If auto-start fails or times out the
    caller should fall back to inline evaluation.
    """
    if os.environ.get("VECTIMUS_NO_DAEMON", "").lower() in ("1", "true", "yes"):
        return None

    if _IS_WINDOWS:
        info = read_daemon_info()
        if info is None or not is_daemon_alive(info):
            if not _try_auto_start():
                return None
            info = read_daemon_info()
            if info is None:
                return None
        return _send_request_tcp(source, payload, cwd, info)
    else:
        if not SOCKET_PATH.exists():
            if not _try_auto_start():
                return None
        return _send_request_unix(source, payload, cwd)


def _send_request_unix(source: str, payload: dict, cwd: str) -> dict | None:
    """Connect to the daemon Unix socket, send request, return response."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(_SOCKET_TIMEOUT)
        sock.connect(str(SOCKET_PATH))

        request = json.dumps({"source": source, "payload": payload, "cwd": cwd}) + "\n"
        sock.sendall(request.encode())

        data = b""
        while b"\n" not in data:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk

        sock.close()

        if not data.strip():
            return None

        return json.loads(data.decode())
    except Exception:
        return None


def _send_request_tcp(source: str, payload: dict, cwd: str, info: dict) -> dict | None:
    """Connect to the daemon TCP server, send request, return response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_SOCKET_TIMEOUT)
        sock.connect(("127.0.0.1", info["port"]))

        request = (
            json.dumps(
                {
                    "token": info["token"],
                    "source": source,
                    "payload": payload,
                    "cwd": cwd,
                }
            )
            + "\n"
        )
        sock.sendall(request.encode())

        data = b""
        while b"\n" not in data:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk

        sock.close()

        if not data.strip():
            return None

        return json.loads(data.decode())
    except Exception:
        return None


def _try_auto_start() -> bool:
    """Spawn the daemon in the background.  Returns True if daemon becomes ready."""
    if _IS_WINDOWS:
        info = read_daemon_info()
        if info and is_daemon_alive(info):
            return True
    else:
        from vectimus.engine.daemon_info import PID_PATH

        if PID_PATH.exists():
            try:
                pid = int(PID_PATH.read_text().strip())
                os.kill(pid, 0)
                return _wait_for_daemon()
            except (ProcessLookupError, ValueError, OSError):
                PID_PATH.unlink(missing_ok=True)

    try:
        kwargs: dict = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if _IS_WINDOWS:
            kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP
                | subprocess.CREATE_NO_WINDOW
            )
        else:
            kwargs["start_new_session"] = True

        subprocess.Popen(
            [sys.executable, "-m", "vectimus", "daemon", "start", "--foreground"],
            **kwargs,
        )
    except Exception:
        return False

    return _wait_for_daemon()


def _wait_for_daemon() -> bool:
    """Poll for the daemon to become ready."""
    deadline = time.monotonic() + _STARTUP_WAIT
    while time.monotonic() < deadline:
        if _IS_WINDOWS:
            info = read_daemon_info()
            if info and is_daemon_alive(info):
                return True
        else:
            if SOCKET_PATH.exists():
                return True
        time.sleep(_STARTUP_POLL_INTERVAL)
    return False
