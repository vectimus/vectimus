"""Thin client for the Vectimus evaluation daemon.

On Unix/macOS connects via Unix domain socket.  On Windows connects
via TCP localhost with auth token.  Falls back to ``None`` if the
daemon is unavailable so the caller can use inline evaluation instead.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import sys
import time

from vectimus.engine.daemon_info import _IS_WINDOWS, is_daemon_alive, read_daemon_info

if not _IS_WINDOWS:
    from vectimus.engine.daemon_info import SOCKET_PATH

_log = logging.getLogger(__name__)

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
        _log.debug("Unix socket request to daemon failed", exc_info=True)
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
        _log.debug("TCP request to daemon failed", exc_info=True)
        return None


def daemon_temp_disable(rule_id: str, project: str, duration_s: float) -> dict | None:
    """Send a temp_disable request to the daemon.

    Auto-starts the daemon if it is not running.  Returns the daemon
    response dict or ``None`` if the daemon is unavailable.
    """
    return _send_control_message(
        {"temp_disable": rule_id, "project": project, "duration_s": duration_s},
        auto_start=True,
    )


def daemon_clear_temp_disable(rule_id: str, project: str) -> dict | None:
    """Clear a temporary rule disable early.  Returns response or None."""
    return _send_control_message(
        {"clear_temp_disable": rule_id, "project": project},
        auto_start=False,
    )


def daemon_query_temp_disables(project: str | None = None) -> dict | None:
    """Query active temp disables from the daemon.  Returns response or None."""
    msg: dict = {"query_temp_disables": True}
    if project:
        msg["project"] = project
    return _send_control_message(msg, auto_start=False)


def _send_control_message(message: dict, *, auto_start: bool = False) -> dict | None:
    """Send a control message to the daemon and return the response.

    If *auto_start* is True and the daemon is not running, starts it first.
    """
    alive = is_daemon_alive(read_daemon_info() or {})

    if not alive:
        if auto_start:
            if not _try_auto_start():
                return None
        else:
            return None

    try:
        if _IS_WINDOWS:
            info = read_daemon_info()
            if info is None:
                return None
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(_SOCKET_TIMEOUT)
            sock.connect(("127.0.0.1", info["port"]))
            message["token"] = info["token"]
        else:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(_SOCKET_TIMEOUT)
            sock.connect(str(SOCKET_PATH))

        sock.sendall((json.dumps(message) + "\n").encode())

        data = b""
        while b"\n" not in data:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
        sock.close()

        if data.strip():
            return json.loads(data.decode())
    except Exception:
        _log.debug("Control message to daemon failed", exc_info=True)
    return None


def daemon_reload() -> bool:
    """Send a reload request to the daemon.  Returns True if successful."""
    if not is_daemon_alive(read_daemon_info() or {}):
        return False

    try:
        if _IS_WINDOWS:
            info = read_daemon_info()
            if info is None:
                return False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(_SOCKET_TIMEOUT)
            sock.connect(("127.0.0.1", info["port"]))
            request = json.dumps({"token": info["token"], "reload": True}) + "\n"
        else:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(_SOCKET_TIMEOUT)
            sock.connect(str(SOCKET_PATH))
            request = json.dumps({"reload": True}) + "\n"

        sock.sendall(request.encode())

        data = b""
        while b"\n" not in data:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
        sock.close()

        if data.strip():
            resp = json.loads(data.decode())
            return resp.get("status") == "reloaded"
    except Exception:
        _log.debug("Daemon reload request failed", exc_info=True)
    return False


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
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
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
