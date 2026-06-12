"""Tests for daemon resilience against deleted working directories.

Regression tests for the incident where the auto-started daemon
inherited an ephemeral agent worktree as its cwd; when the worktree
was deleted, ``os.getcwd()`` raised ``FileNotFoundError`` on every
request and the daemon denied all tool calls in every project until
manually restarted.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import tempfile
from pathlib import Path

import pytest

from vectimus.cli import daemon_client
from vectimus.engine import daemon as daemon_mod
from vectimus.engine import daemon_info


@pytest.fixture
def fake_paths(monkeypatch):
    """Point the client and daemon_info at private socket/PID paths so
    tests never touch a real daemon on the host.

    Uses a short directory under /tmp because AF_UNIX socket paths are
    limited to ~104 bytes on macOS and pytest tmp_path can exceed that.
    """
    short_dir = Path(tempfile.mkdtemp(prefix="vtms-test-", dir="/tmp"))
    sock = short_dir / "d.sock"
    pid_file = short_dir / "d.pid"
    monkeypatch.setattr(daemon_client, "SOCKET_PATH", sock)
    monkeypatch.setattr(daemon_info, "SOCKET_PATH", sock)
    monkeypatch.setattr(daemon_info, "PID_PATH", pid_file)
    yield sock, pid_file
    shutil.rmtree(short_dir, ignore_errors=True)


def _listening_popen_factory(sock_path: Path, calls: list[dict], listeners: list):
    """A fake subprocess.Popen whose 'daemon' really listens on the socket,
    so the client's connect-probe readiness check is satisfied honestly."""

    def fake_popen(cmd, **kwargs):
        calls.append({"cmd": cmd, **kwargs})
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(sock_path))
        listener.listen(1)
        listeners.append(listener)

        class _P:
            pid = 999999

        return _P()

    return fake_popen


class TestDaemonDetachesFromSpawningDirectory:
    def test_start_chdirs_to_root(self, monkeypatch, tmp_path) -> None:
        """start() must not keep the (possibly ephemeral) spawn directory."""
        monkeypatch.chdir(tmp_path)

        async def _noop_start(self) -> None:
            return None

        monkeypatch.setattr(daemon_mod.DaemonServer, "_start_unix", _noop_start)
        monkeypatch.setattr(daemon_mod.DaemonServer, "_start_tcp", _noop_start)
        monkeypatch.setattr(daemon_mod, "remove_daemon_info", lambda: None)

        server = daemon_mod.DaemonServer(idle_timeout=1)
        server._shutdown_event.set()
        asyncio.run(server.start())

        assert os.getcwd() == "/"

    def test_evaluate_uses_request_cwd_when_process_cwd_deleted(
        self, monkeypatch, tmp_path
    ) -> None:
        """A request carrying its own cwd must evaluate even when the
        daemon process's cwd no longer exists (the eager
        ``request.get("cwd", os.getcwd())`` default used to raise here).
        """
        monkeypatch.setattr(daemon_mod, "write_audit", lambda *a, **k: None)

        project = tmp_path / "project"
        project.mkdir()
        doomed = tmp_path / "doomed"
        doomed.mkdir()
        monkeypatch.chdir(doomed)
        doomed.rmdir()

        with pytest.raises(FileNotFoundError):
            os.getcwd()  # precondition: process cwd really is gone

        server = daemon_mod.DaemonServer()
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "echo ok"},
            "cwd": str(project),
        }
        response = server._evaluate(
            {"source": "claude-code", "payload": payload, "cwd": str(project)}
        )

        assert "Daemon error" not in (response.get("reason") or "")
        assert response["decision"] == "allow"

    def test_handle_connection_with_deleted_cwd_returns_decision(
        self, monkeypatch, tmp_path
    ) -> None:
        """Full request path: _handle_connection must not produce a
        daemon_error response when the process cwd is deleted but the
        request carries its own cwd."""
        monkeypatch.setattr(daemon_mod, "write_audit", lambda *a, **k: None)

        project = tmp_path / "project"
        project.mkdir()
        doomed = tmp_path / "doomed"
        doomed.mkdir()
        monkeypatch.chdir(doomed)
        doomed.rmdir()

        request = {
            "source": "claude-code",
            "cwd": str(project),
            "payload": {
                "tool_name": "Bash",
                "tool_input": {"command": "echo ok"},
                "cwd": str(project),
            },
        }

        written: list[bytes] = []

        class _FakeWriter:
            def write(self, data: bytes) -> None:
                written.append(data)

            async def drain(self) -> None:
                return None

            def close(self) -> None:
                return None

            async def wait_closed(self) -> None:
                return None

        class _FakeReader:
            async def readline(self) -> bytes:
                return json.dumps(request).encode() + b"\n"

        async def _run() -> None:
            server = daemon_mod.DaemonServer()
            await server._handle_connection(_FakeReader(), _FakeWriter())

        asyncio.run(_run())

        response = json.loads(b"".join(written).decode())
        assert not response.get("daemon_error")
        assert "Daemon error" not in (response.get("reason") or "")
        assert response["decision"] == "allow"

    def test_handle_connection_marks_internal_errors(self, monkeypatch) -> None:
        """Unexpected daemon failures must carry the daemon_error marker
        so the client can distinguish them from policy denials."""

        def _boom(self, request: dict) -> dict:
            raise FileNotFoundError(2, "No such file or directory")

        monkeypatch.setattr(daemon_mod.DaemonServer, "_evaluate", _boom)

        request = {"source": "claude-code", "cwd": "/x", "payload": {}}
        written: list[bytes] = []

        class _FakeWriter:
            def write(self, data: bytes) -> None:
                written.append(data)

            async def drain(self) -> None:
                return None

            def close(self) -> None:
                return None

            async def wait_closed(self) -> None:
                return None

        class _FakeReader:
            async def readline(self) -> bytes:
                return json.dumps(request).encode() + b"\n"

        async def _run() -> None:
            server = daemon_mod.DaemonServer()
            await server._handle_connection(_FakeReader(), _FakeWriter())

        asyncio.run(_run())

        response = json.loads(b"".join(written).decode())
        assert response["daemon_error"] is True
        assert response["decision"] == "deny"

    def test_shutdown_does_not_remove_successor_files(self, monkeypatch, fake_paths) -> None:
        """A replaced daemon exiting late must not delete the PID file
        now owned by its successor."""
        _sock, pid_file = fake_paths
        pid_file.write_text("424242")  # successor's pid, not ours

        removed = {"value": False}

        def fake_remove() -> None:
            removed["value"] = True

        monkeypatch.setattr(daemon_mod, "remove_daemon_info", fake_remove)
        monkeypatch.setattr(daemon_mod, "PID_PATH", pid_file)

        server = daemon_mod.DaemonServer()
        asyncio.run(server.shutdown())

        assert removed["value"] is False

        pid_file.write_text(str(os.getpid()))  # now we own it
        asyncio.run(server.shutdown())
        assert removed["value"] is True


class TestClientAutoRestart:
    def test_auto_start_replaces_alive_daemon_with_missing_socket(
        self, monkeypatch, fake_paths
    ) -> None:
        """PID alive + socket missing means the daemon cannot serve; it
        must be stopped and a replacement spawned, not waited on."""
        sock, pid_file = fake_paths
        pid_file.write_text("424242")

        sent_signals: list[tuple[int, int]] = []
        dead = {"value": False}

        def fake_kill(pid: int, sig: int) -> None:
            if dead["value"]:
                raise ProcessLookupError(pid)
            sent_signals.append((pid, sig))
            if sig == 15:  # SIGTERM: process exits
                dead["value"] = True

        popen_calls: list[dict] = []
        listeners: list = []

        monkeypatch.setattr(daemon_client.os, "kill", fake_kill)
        monkeypatch.setattr(daemon_client, "_pid_is_vectimus_daemon", lambda pid: True)
        monkeypatch.setattr(
            daemon_client.subprocess,
            "Popen",
            _listening_popen_factory(sock, popen_calls, listeners),
        )

        try:
            assert daemon_client._try_auto_start() is True
        finally:
            for listener in listeners:
                listener.close()

        assert (424242, 15) in sent_signals
        assert len(popen_calls) == 1
        assert not pid_file.exists() or pid_file.read_text() != "424242"

    def test_auto_start_never_signals_non_vectimus_pid(self, monkeypatch, fake_paths) -> None:
        """A stale PID file pointing at a reused (non-vectimus) PID must
        not get the unrelated process killed."""
        sock, pid_file = fake_paths
        pid_file.write_text("424242")

        sent_signals: list[tuple[int, int]] = []

        def fake_kill(pid: int, sig: int) -> None:
            sent_signals.append((pid, sig))

        popen_calls: list[dict] = []
        listeners: list = []

        monkeypatch.setattr(daemon_client.os, "kill", fake_kill)
        monkeypatch.setattr(daemon_client, "_pid_is_vectimus_daemon", lambda pid: False)
        monkeypatch.setattr(
            daemon_client.subprocess,
            "Popen",
            _listening_popen_factory(sock, popen_calls, listeners),
        )

        try:
            assert daemon_client._try_auto_start() is True
        finally:
            for listener in listeners:
                listener.close()

        # Only the liveness probe (signal 0) is allowed, never TERM/KILL.
        assert all(sig == 0 for _pid, sig in sent_signals)
        assert not pid_file.exists()
        assert len(popen_calls) == 1

    def test_auto_start_spawns_daemon_with_root_cwd(self, monkeypatch, fake_paths) -> None:
        """The spawned daemon must not inherit the hook's cwd."""
        sock, _pid_file = fake_paths
        popen_calls: list[dict] = []
        listeners: list = []

        monkeypatch.setattr(
            daemon_client.subprocess,
            "Popen",
            _listening_popen_factory(sock, popen_calls, listeners),
        )

        try:
            assert daemon_client._try_auto_start() is True
        finally:
            for listener in listeners:
                listener.close()

        assert popen_calls[0]["cwd"] == "/"

    def test_concurrent_auto_start_respects_lock(self, monkeypatch, fake_paths) -> None:
        """A start lock held elsewhere means: wait, don't spawn a second
        daemon or signal anything."""
        sock, _pid_file = fake_paths
        held = daemon_client._acquire_start_lock()  # someone else holds it
        assert held is not None

        def fail_popen(*a, **k):  # pragma: no cover - must not run
            raise AssertionError("must not spawn while another start holds the lock")

        monkeypatch.setattr(daemon_client.subprocess, "Popen", fail_popen)
        monkeypatch.setattr(daemon_client, "_STARTUP_WAIT", 0.1)

        try:
            assert daemon_client._try_auto_start() is False  # nobody ever binds
        finally:
            daemon_client._release_start_lock(held)

        # Released lock can be re-acquired (flock freed on close).
        again = daemon_client._acquire_start_lock()
        assert again is not None
        daemon_client._release_start_lock(again)

    def test_pid_identity_requires_daemon_argv(self, monkeypatch) -> None:
        """Only the daemon's argv shape counts -- a reused PID running
        hooks, tests or an editor with 'vectimus' in its arguments must
        not be treated as the daemon."""

        def fake_ps(out: str):
            class _R:
                stdout = out

            def run(*a, **k):
                return _R()

            return run

        cases = {
            "/usr/bin/python -m vectimus daemon start --foreground": True,
            "/Users/x/.local/bin/vectimus daemon start --foreground": True,
            "/usr/bin/python -m vectimus hook claude-code": False,
            "pytest tests/test_daemon_resilience.py": False,
            "vim /Users/x/Development/vectimus/vectimus/README.md": False,
        }
        for cmdline, expected in cases.items():
            monkeypatch.setattr(daemon_client.subprocess, "run", fake_ps(cmdline))
            assert daemon_client._pid_is_vectimus_daemon(99999999) is expected, cmdline

    def test_evaluate_restarts_when_socket_is_stale(self, monkeypatch, fake_paths) -> None:
        """A socket file nobody answers on (crashed daemon) must trigger
        an auto-start and a single retry instead of an inline fallback
        forever."""
        sock, _pid_file = fake_paths
        sock.touch()  # stale socket file, no listener

        attempts = {"count": 0}

        def fake_send(source, payload, cwd):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise daemon_client._DaemonConnectError()
            return {"decision": "allow"}

        started = {"value": False}

        def fake_auto_start() -> bool:
            started["value"] = True
            return True

        monkeypatch.setattr(daemon_client, "_send_request_unix", fake_send)
        monkeypatch.setattr(daemon_client, "_try_auto_start", fake_auto_start)

        result = daemon_client.daemon_evaluate("claude-code", {}, "/some/project")

        assert result == {"decision": "allow"}
        assert started["value"] is True
        assert attempts["count"] == 2

    def test_evaluate_does_not_restart_busy_daemon(self, monkeypatch, fake_paths) -> None:
        """A connected daemon that times out (None response) is busy, not
        dead -- fall back inline without killing or restarting it."""
        sock, _pid_file = fake_paths
        sock.touch()

        def fake_send(source, payload, cwd):
            return None  # post-connect timeout

        def fail_auto_start() -> bool:  # pragma: no cover - must not run
            raise AssertionError("auto-start must not run for a busy daemon")

        monkeypatch.setattr(daemon_client, "_send_request_unix", fake_send)
        monkeypatch.setattr(daemon_client, "_try_auto_start", fail_auto_start)

        assert daemon_client.daemon_evaluate("claude-code", {}, "/p") is None

    def test_evaluate_replaces_daemon_reporting_internal_errors(
        self, monkeypatch, fake_paths
    ) -> None:
        """A daemon_error response (e.g. wedged cwd) must fall back to
        inline evaluation for this request and replace the daemon."""
        sock, _pid_file = fake_paths
        sock.touch()

        def fake_send(source, payload, cwd):
            return {
                "decision": "deny",
                "reason": "Daemon error (fail closed): [Errno 2] ...",
                "daemon_error": True,
            }

        replaced = {"value": False}

        monkeypatch.setattr(daemon_client, "_send_request_unix", fake_send)
        monkeypatch.setattr(
            daemon_client,
            "_replace_broken_daemon",
            lambda: replaced.__setitem__("value", True),
        )

        assert daemon_client.daemon_evaluate("claude-code", {}, "/p") is None
        assert replaced["value"] is True

    def test_daemon_error_is_caught_on_retry_and_cold_start_paths(
        self, monkeypatch, fake_paths
    ) -> None:
        """daemon_error responses must trigger inline fallback on every
        path, including the post-restart retry and the cold start."""
        sock, _pid_file = fake_paths

        broken = {
            "decision": "deny",
            "reason": "Daemon error (fail closed): boom",
            "daemon_error": True,
        }
        replaced = {"count": 0}
        monkeypatch.setattr(
            daemon_client,
            "_replace_broken_daemon",
            lambda: replaced.__setitem__("count", replaced["count"] + 1),
        )
        monkeypatch.setattr(daemon_client, "_try_auto_start", lambda: True)

        # Retry path: stale socket, restart, then the replacement reports broken.
        sock.touch()
        attempts = {"count": 0}

        def fail_then_broken(source, payload, cwd):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise daemon_client._DaemonConnectError()
            return dict(broken)

        monkeypatch.setattr(daemon_client, "_send_request_unix", fail_then_broken)
        assert daemon_client.daemon_evaluate("claude-code", {}, "/p") is None
        assert replaced["count"] == 1

        # Cold start path: no socket at all, fresh daemon reports broken.
        sock.unlink()
        monkeypatch.setattr(daemon_client, "_send_request_unix", lambda *a: dict(broken))
        assert daemon_client.daemon_evaluate("claude-code", {}, "/p") is None
        assert replaced["count"] == 2

    def test_evaluate_returns_healthy_response_untouched(self, monkeypatch, fake_paths) -> None:
        sock, _pid_file = fake_paths
        sock.touch()

        def fake_send(source, payload, cwd):
            return {"decision": "deny", "reason": "policy"}

        def fail_auto_start() -> bool:  # pragma: no cover - must not run
            raise AssertionError("auto-start must not run for a healthy daemon")

        monkeypatch.setattr(daemon_client, "_send_request_unix", fake_send)
        monkeypatch.setattr(daemon_client, "_try_auto_start", fail_auto_start)

        result = daemon_client.daemon_evaluate("claude-code", {}, "/some/project")
        assert result == {"decision": "deny", "reason": "policy"}
