"""``vectimus daemon`` -- manage the persistent evaluation daemon."""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

import click

PID_PATH = Path(f"/tmp/vectimus-{os.getuid()}.pid")
SOCKET_PATH = Path(f"/tmp/vectimus-{os.getuid()}.sock")


@click.group("daemon")
def daemon_cmd() -> None:
    """Manage the persistent evaluation daemon.

    The daemon keeps the Cedar policy engine warm in memory so
    subsequent hook evaluations skip the Python startup cost.
    It is auto-started on the first hook call if not already running.
    """


@daemon_cmd.command("start")
@click.option("--foreground", is_flag=True, help="Run in the foreground (for debugging).")
@click.option(
    "--idle-timeout",
    default=1800,
    type=int,
    show_default=True,
    help="Shut down after this many seconds of inactivity.",
)
def daemon_start(foreground: bool, idle_timeout: int) -> None:
    """Start the evaluation daemon."""
    import asyncio

    from vectimus.engine.daemon import DaemonServer

    if not foreground:
        # Double-fork to detach from the parent process
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError:
            # Fork not available (shouldn't happen on macOS/Linux)
            pass
        else:
            os.setsid()
            try:
                pid = os.fork()
                if pid > 0:
                    sys.exit(0)
            except OSError:
                pass

            # Redirect stdio to /dev/null
            devnull = os.open(os.devnull, os.O_RDWR)
            os.dup2(devnull, 0)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            os.close(devnull)

    server = DaemonServer(idle_timeout=idle_timeout)
    asyncio.run(server.start())


@daemon_cmd.command("stop")
def daemon_stop() -> None:
    """Stop the running daemon."""
    if not PID_PATH.exists():
        click.echo("Daemon is not running.")
        return

    try:
        pid = int(PID_PATH.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        click.echo(f"Sent SIGTERM to daemon (pid {pid}).")
    except ProcessLookupError:
        click.echo("Daemon is not running (stale PID file).")
        PID_PATH.unlink(missing_ok=True)
        SOCKET_PATH.unlink(missing_ok=True)
    except ValueError:
        click.echo("Invalid PID file.")
        PID_PATH.unlink(missing_ok=True)


@daemon_cmd.command("status")
def daemon_status() -> None:
    """Show daemon status."""
    if not PID_PATH.exists():
        click.echo("Daemon: not running")
        return

    try:
        pid = int(PID_PATH.read_text().strip())
        os.kill(pid, 0)
        socket_ok = SOCKET_PATH.exists()
        click.echo(f"Daemon: running (pid {pid})")
        click.echo(f"Socket: {'ready' if socket_ok else 'not found'} ({SOCKET_PATH})")
    except ProcessLookupError:
        click.echo("Daemon: not running (stale PID file)")
        PID_PATH.unlink(missing_ok=True)
        SOCKET_PATH.unlink(missing_ok=True)
    except ValueError:
        click.echo("Daemon: invalid PID file")
