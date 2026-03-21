"""Thin TCP client for the Vectimus evaluation daemon.

Connects to the persistent daemon over TCP localhost, sends an
evaluation request with auth token and returns the decision.  Falls
back to ``None`` if the daemon is unavailable so the caller can use
inline evaluation instead.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

from vectimus.engine.daemon_info import is_daemon_alive, read_daemon_info

# Timeout for the entire TCP round-trip (connect + send + recv).
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

    info = read_daemon_info()
    if info is None or not is_daemon_alive(info):
        if not _try_auto_start():
            return None
        info = read_daemon_info()
        if info is None:
            return None

    return _send_request(source, payload, cwd, info)


def _send_request(source: str, payload: dict, cwd: str, info: dict) -> dict | None:
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

        # Read until newline
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
    """Spawn the daemon in the background.  Returns True if daemon info appears."""
    # Check for a running daemon with stale info
    info = read_daemon_info()
    if info and is_daemon_alive(info):
        return True

    try:
        kwargs: dict = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if sys.platform == "win32":
            kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            )
        else:
            kwargs["start_new_session"] = True

        subprocess.Popen(
            [sys.executable, "-m", "vectimus", "daemon", "start"],
            **kwargs,
        )
    except Exception:
        return False

    return _wait_for_daemon()


def _wait_for_daemon() -> bool:
    """Poll for the daemon info file to appear with a live process."""
    deadline = time.monotonic() + _STARTUP_WAIT
    while time.monotonic() < deadline:
        info = read_daemon_info()
        if info and is_daemon_alive(info):
            return True
        time.sleep(_STARTUP_POLL_INTERVAL)
    return False
