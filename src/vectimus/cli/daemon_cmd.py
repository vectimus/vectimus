"""``vectimus daemon`` -- manage the persistent evaluation daemon."""

from __future__ import annotations

import os
import signal
import subprocess
import sys

import click

from vectimus.engine.daemon_info import (
    _IS_WINDOWS,
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
        if _IS_WINDOWS:
            # Windows: spawn a detached child process running in foreground mode
            kwargs: dict = {
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "creationflags": (
                    subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
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

    pid = info["pid"]
    if _IS_WINDOWS:
        # Windows: os.kill(SIGTERM) calls TerminateProcess which skips
        # cleanup.  Send a shutdown request over TCP instead.
        import json
        import socket

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(("127.0.0.1", info["port"]))
            request = json.dumps({"token": info["token"], "shutdown": True}) + "\n"
            sock.sendall(request.encode())
            sock.recv(1024)
            sock.close()
            click.echo(f"Sent shutdown to daemon (pid {pid}).")
        except Exception:
            # Fallback: force kill + clean up info file
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            remove_daemon_info()
            click.echo(f"Force-stopped daemon (pid {pid}).")
    else:
        try:
            os.kill(pid, signal.SIGTERM)
            click.echo(f"Sent SIGTERM to daemon (pid {pid}).")
        except ProcessLookupError:
            click.echo("Daemon is not running (stale info file).")
            remove_daemon_info()


@daemon_cmd.command("reload")
def daemon_reload() -> None:
    """Reload policies and config in the running daemon.

    Flushes cached policy engines so the next evaluation picks up
    changes from disk (rule disable/enable, pack changes, etc.).
    """
    from vectimus.cli.daemon_client import daemon_reload as _reload

    if _reload():
        click.echo("Daemon reloaded.")
    else:
        click.echo("Daemon is not running (nothing to reload).")


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
    if _IS_WINDOWS:
        click.echo(f"Port:   {info['port']}")
    else:
        from vectimus.engine.daemon_info import SOCKET_PATH

        socket_ok = SOCKET_PATH.exists()
        click.echo(f"Socket: {'ready' if socket_ok else 'not found'} ({SOCKET_PATH})")
