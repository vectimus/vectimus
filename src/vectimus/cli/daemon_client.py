"""Thin Unix socket client for the Vectimus evaluation daemon.

Connects to the persistent daemon, sends an evaluation request and
returns the decision.  Falls back to ``None`` if the daemon is
unavailable so the caller can use inline evaluation instead.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

SOCKET_PATH = Path(f"/tmp/vectimus-{os.getuid()}.sock")
PID_PATH = Path(f"/tmp/vectimus-{os.getuid()}.pid")

# Timeout for the entire socket round-trip (connect + send + recv).
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

    if not SOCKET_PATH.exists():
        if not _try_auto_start():
            return None

    return _send_request(source, payload, cwd)


def _send_request(source: str, payload: dict, cwd: str) -> dict | None:
    """Connect to the daemon socket, send request, return response."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(_SOCKET_TIMEOUT)
        sock.connect(str(SOCKET_PATH))

        request = json.dumps({"source": source, "payload": payload, "cwd": cwd}) + "\n"
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
    """Spawn the daemon in the background.  Returns True if socket appears."""
    # Check for a running daemon with a stale socket
    if PID_PATH.exists():
        try:
            pid = int(PID_PATH.read_text().strip())
            os.kill(pid, 0)
            # Process is alive but socket missing — wait briefly
            return _wait_for_socket()
        except (ProcessLookupError, ValueError, OSError):
            # Stale PID file — clean up
            PID_PATH.unlink(missing_ok=True)

    try:
        subprocess.Popen(
            [sys.executable, "-m", "vectimus", "daemon", "start"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        return False

    return _wait_for_socket()


def _wait_for_socket() -> bool:
    """Poll for the socket file to appear."""
    deadline = time.monotonic() + _STARTUP_WAIT
    while time.monotonic() < deadline:
        if SOCKET_PATH.exists():
            return True
        time.sleep(_STARTUP_POLL_INTERVAL)
    return False
