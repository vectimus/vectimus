"""Thin client for the Vectimus evaluation daemon.

On Unix/macOS connects via Unix domain socket.  On Windows connects
via TCP localhost with auth token.  Falls back to ``None`` if the
daemon is unavailable so the caller can use inline evaluation instead.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from vectimus.engine.daemon_info import _IS_WINDOWS, is_daemon_alive, read_daemon_info

if not _IS_WINDOWS:
    import fcntl

    from vectimus.engine.daemon_info import SOCKET_PATH

_log = logging.getLogger(__name__)

# Timeout for the entire round-trip (connect + send + recv).
_SOCKET_TIMEOUT = 2.0

# How long to wait for the daemon to start on cold boot.
_STARTUP_WAIT = 1.0
_STARTUP_POLL_INTERVAL = 0.05


class _DaemonConnectError(Exception):
    """Could not connect to the daemon socket (dead daemon or stale socket).

    Distinct from a post-connect failure (slow or busy daemon): a connect
    failure means restarting can help, a read timeout means it will not.
    """


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
        if SOCKET_PATH.exists():
            try:
                return _finalize_unix_response(_send_request_unix(source, payload, cwd))
            except _DaemonConnectError:
                # Stale socket left by a dead daemon.  Restart below and
                # retry once.
                pass
        if not _try_auto_start():
            return None
        try:
            return _finalize_unix_response(_send_request_unix(source, payload, cwd))
        except _DaemonConnectError:
            return None


def _finalize_unix_response(response: dict | None) -> dict | None:
    """Common post-processing for every daemon response.

    An internal daemon failure (``daemon_error``, e.g. its cwd was
    deleted from under it) is not a policy decision: fall back to inline
    evaluation for this request and replace the daemon for subsequent
    calls.  A ``None`` (post-connect timeout or empty reply) means the
    daemon is slow or busy -- fall back inline without restarting it.
    """
    if response is not None and response.get("daemon_error"):
        _log.warning(
            "Daemon reported an internal error; replacing it: %s",
            response.get("reason"),
        )
        _replace_broken_daemon()
        return None
    return response


def _send_request_unix(source: str, payload: dict, cwd: str) -> dict | None:
    """Connect to the daemon Unix socket, send request, return response.

    Raises :class:`_DaemonConnectError` when the connection itself cannot be
    established; returns ``None`` for post-connect failures.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(_SOCKET_TIMEOUT)
    try:
        sock.connect(str(SOCKET_PATH))
    except OSError as exc:
        sock.close()
        raise _DaemonConnectError from exc

    try:
        request = json.dumps({"source": source, "payload": payload, "cwd": cwd}) + "\n"
        sock.sendall(request.encode())

        data = b""
        while b"\n" not in data:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk

        if not data.strip():
            return None

        return json.loads(data.decode())
    except Exception:
        _log.debug("Unix socket request to daemon failed", exc_info=True)
        return None
    finally:
        sock.close()


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
    """Spawn the daemon in the background.  Returns True if daemon becomes ready.

    A daemon process that is alive but not answering on its socket cannot
    serve requests, so it is stopped and replaced rather than waited on.
    The whole stop/clean/spawn sequence runs under a start lock so
    concurrent hook processes cannot kill each other's replacement.
    """
    if _IS_WINDOWS:
        info = read_daemon_info()
        if info and is_daemon_alive(info):
            return True
        return _spawn_daemon()

    from vectimus.engine.daemon_info import PID_PATH

    lock_fd = _acquire_start_lock()
    if lock_fd is None:
        # Another process is already starting or replacing the daemon.
        return _wait_for_daemon()
    try:
        if PID_PATH.exists():
            alive_pid: int | None = None
            try:
                pid = int(PID_PATH.read_text().strip())
                os.kill(pid, 0)
                alive_pid = pid
            except (ProcessLookupError, ValueError, OSError):
                PID_PATH.unlink(missing_ok=True)
            if alive_pid is not None:
                if SOCKET_PATH.exists() and _wait_for_daemon():
                    return True
                # Alive but not serving.  Verify the PID still belongs to
                # a vectimus process before signalling it -- PID files in
                # /tmp can go stale and PIDs get reused.
                if _pid_is_vectimus_daemon(alive_pid):
                    _stop_unhealthy_daemon(alive_pid)
                else:
                    PID_PATH.unlink(missing_ok=True)
        SOCKET_PATH.unlink(missing_ok=True)
        return _spawn_daemon()
    finally:
        _release_start_lock(lock_fd)


def _replace_broken_daemon() -> None:
    """Best-effort stop-and-respawn of a daemon that answers but reports
    internal errors.  Never raises."""
    if _IS_WINDOWS:
        return
    from vectimus.engine.daemon_info import PID_PATH

    lock_fd = _acquire_start_lock()
    if lock_fd is None:
        return  # someone else is already on it
    try:
        try:
            pid: int | None = int(PID_PATH.read_text().strip())
        except (FileNotFoundError, ValueError, OSError):
            pid = None
        if pid is not None:
            if _pid_is_vectimus_daemon(pid):
                _stop_unhealthy_daemon(pid)
            else:
                PID_PATH.unlink(missing_ok=True)
        SOCKET_PATH.unlink(missing_ok=True)
        _spawn_daemon()
    except Exception:
        _log.debug("Replacing broken daemon failed", exc_info=True)
    finally:
        _release_start_lock(lock_fd)


def _spawn_daemon() -> bool:
    """Spawn a new daemon process and wait for it to become ready."""
    try:
        kwargs: dict = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            # Never inherit the caller's cwd: hook processes run in
            # project directories that may be deleted later (e.g.
            # ephemeral agent worktrees), which would break the daemon's
            # os.getcwd() for its whole lifetime.
            "cwd": "/",
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


def _pid_is_vectimus_daemon(pid: int) -> bool:
    """Best-effort check that *pid* is actually a vectimus daemon.

    Guards against PID reuse: a stale PID file must never cause a
    SIGTERM/SIGKILL to land on an unrelated process.  Matches the
    daemon's argv shape ("vectimus daemon start"), not just the word
    "vectimus", so reused PIDs running hooks, tests or editors with the
    repo path in their arguments are not signalled.  When in doubt
    (no /proc, ``ps`` unavailable, lookup fails) returns False so the
    caller skips signalling and only cleans up the stale files.
    """
    cmdline = ""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        cmdline = raw.replace(b"\0", b" ").decode(errors="replace")
    except OSError:
        try:
            cmdline = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                capture_output=True,
                text=True,
                timeout=2.0,
            ).stdout
        except Exception:
            return False
    return "vectimus daemon start" in cmdline


def _stop_unhealthy_daemon(pid: int) -> None:
    """Stop a daemon that is alive but can no longer serve requests.

    Waits for the process to exit before returning so its shutdown
    cleanup cannot race the replacement daemon's startup.  Escalates to
    SIGKILL if it does not exit in time.
    """
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            break
        time.sleep(_STARTUP_POLL_INTERVAL)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    from vectimus.engine.daemon_info import PID_PATH

    PID_PATH.unlink(missing_ok=True)
    SOCKET_PATH.unlink(missing_ok=True)


def _acquire_start_lock() -> int | None:
    """Take the exclusive daemon-start lock (Unix only).

    Returns an open fd on success, ``None`` if another process holds the
    lock.  Uses ``flock`` so the kernel releases the lock automatically
    when the holder exits or crashes -- no TTL or stale-lock breaking,
    which would be racy.  The lock file itself is never unlinked
    (unlink + flock on the same path is a classic race).
    """
    lock_path = SOCKET_PATH.with_suffix(".lock")
    try:
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _release_start_lock(fd: int) -> None:
    try:
        os.close(fd)  # closing the fd releases the flock
    except OSError:
        pass


def _wait_for_daemon() -> bool:
    """Poll for the daemon to become ready.

    On Unix readiness means the socket actually accepts a connection --
    a socket file merely existing can be a stale leftover from a crashed
    daemon.
    """
    deadline = time.monotonic() + _STARTUP_WAIT
    while time.monotonic() < deadline:
        if _IS_WINDOWS:
            info = read_daemon_info()
            if info and is_daemon_alive(info):
                return True
        else:
            if _daemon_answers():
                return True
        time.sleep(_STARTUP_POLL_INTERVAL)
    return False


def _daemon_answers() -> bool:
    """True if something accepts connections on the daemon socket."""
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(_STARTUP_POLL_INTERVAL * 4)
    try:
        probe.connect(str(SOCKET_PATH))
        return True
    except OSError:
        return False
    finally:
        probe.close()
