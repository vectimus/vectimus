"""``vectimus daemon`` -- manage the persistent evaluation daemon."""

from __future__ import annotations

import os
import signal
import subprocess
import sys

import click

from vectimus.engine.daemon_info import (
    is_daemon_alive,
    read_daemon_info,
    remove_daemon_info,
)


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
        if sys.platform == "win32":
            # Windows: spawn a detached child process running in foreground mode
            kwargs: dict = {
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "creationflags": (
                    subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
                ),
            }
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "vectimus",
                    "daemon",
                    "start",
                    "--foreground",
                    f"--idle-timeout={idle_timeout}",
                ],
                **kwargs,
            )
            return
        else:
            # Unix: double-fork to detach from the parent process
            try:
                pid = os.fork()
                if pid > 0:
                    sys.exit(0)
            except OSError:
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
    info = read_daemon_info()
    if info is None:
        click.echo("Daemon is not running.")
        return

    if not is_daemon_alive(info):
        click.echo("Daemon is not running (stale info file).")
        remove_daemon_info()
        return

    try:
        os.kill(info["pid"], signal.SIGTERM)
        click.echo(f"Sent SIGTERM to daemon (pid {info['pid']}).")
    except ProcessLookupError:
        click.echo("Daemon is not running (stale info file).")
        remove_daemon_info()


@daemon_cmd.command("status")
def daemon_status() -> None:
    """Show daemon status."""
    info = read_daemon_info()
    if info is None:
        click.echo("Daemon: not running")
        return

    if not is_daemon_alive(info):
        click.echo("Daemon: not running (stale info file)")
        remove_daemon_info()
        return

    click.echo(f"Daemon: running (pid {info['pid']})")
    click.echo(f"Port:   {info['port']}")
