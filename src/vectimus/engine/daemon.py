"""Persistent evaluation daemon.

Keeps the PolicyEngine warm in memory and accepts evaluation requests
over a Unix domain socket (Unix/macOS) or TCP localhost with auth token
(Windows).  Eliminates the ~200ms Python startup cost on every hook
invocation.

Protocol: one JSON line per connection (request), one JSON line back
(response), then close.  On Windows every request must include the
auth token.  On Unix the socket's filesystem permissions handle auth.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import signal
import sys
import time
from pathlib import Path

import structlog

from vectimus.engine.audit import write_audit
from vectimus.engine.daemon_info import (
    _IS_WINDOWS,
    is_daemon_alive,
    read_daemon_info,
    remove_daemon_info,
    write_daemon_info,
    write_pid_file,
)
from vectimus.engine.evaluator import PolicyEngine
from vectimus.engine.loader import PolicyLoader
from vectimus.engine.models import DecisionVerdict
from vectimus.engine.normaliser import normalise

if not _IS_WINDOWS:
    from vectimus.engine.daemon_info import PID_PATH, SOCKET_PATH

logger = structlog.get_logger(__name__)

DEFAULT_IDLE_TIMEOUT = 1800  # 30 minutes
ENGINE_CACHE_TTL = 300  # 5 minutes


class _CachedEngine:
    """PolicyEngine with a creation timestamp for TTL-based invalidation."""

    __slots__ = ("engine", "loader", "created_at")

    def __init__(self, engine: PolicyEngine, loader: PolicyLoader) -> None:
        self.engine = engine
        self.loader = loader
        self.created_at = time.monotonic()


class DaemonServer:
    """Asyncio server for persistent policy evaluation.

    Uses Unix domain sockets on Unix/macOS and TCP localhost on Windows.
    """

    def __init__(self, idle_timeout: int = DEFAULT_IDLE_TIMEOUT) -> None:
        self._engines: dict[tuple[str, bool], _CachedEngine] = {}
        self._idle_timeout = idle_timeout
        self._last_activity = time.monotonic()
        self._server: asyncio.Server | None = None
        self._shutdown_event = asyncio.Event()
        self._cleaned_projects: set[Path] = set()
        self._token: str = ""

    async def start(self) -> None:
        """Start the daemon server."""
        if _IS_WINDOWS:
            await self._start_tcp()
        else:
            await self._start_unix()

        # Install signal handlers
        loop = asyncio.get_running_loop()
        if _IS_WINDOWS:
            signal.signal(signal.SIGTERM, lambda *_: self._shutdown_event.set())
            signal.signal(signal.SIGINT, lambda *_: self._shutdown_event.set())
        else:
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, lambda: self._shutdown_event.set())

        # Run until shutdown
        idle_task = asyncio.create_task(self._idle_watchdog())
        await self._shutdown_event.wait()
        idle_task.cancel()
        await self.shutdown()

    async def _start_unix(self) -> None:
        """Start Unix domain socket server."""
        # Check for existing daemon
        if SOCKET_PATH.exists():
            if PID_PATH.exists():
                try:
                    pid = int(PID_PATH.read_text().strip())
                    os.kill(pid, 0)
                    print(
                        f"vectimus: daemon already running (pid {pid})",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                except (ProcessLookupError, ValueError, OSError):
                    pass  # stale
            SOCKET_PATH.unlink(missing_ok=True)

        # Write PID file
        write_pid_file(os.getpid())

        # Start server with deferred serving so we can set permissions
        # before accepting connections (avoids TOCTOU window in /tmp).
        self._server = await asyncio.start_unix_server(
            self._handle_connection,
            path=str(SOCKET_PATH),
            start_serving=False,
        )
        SOCKET_PATH.chmod(0o600)
        await self._server.start_serving()

        logger.info("daemon_started", socket=str(SOCKET_PATH), pid=os.getpid())

    async def _start_tcp(self) -> None:
        """Start TCP localhost server (Windows)."""
        # Check for existing daemon
        info = read_daemon_info()
        if info and is_daemon_alive(info):
            print(
                f"vectimus: daemon already running (pid {info['pid']})",
                file=sys.stderr,
            )
            sys.exit(1)

        # Clean up stale info
        remove_daemon_info()

        # Generate auth token
        self._token = secrets.token_hex(32)

        # Start TCP server on localhost with OS-assigned port
        self._server = await asyncio.start_server(
            self._handle_connection,
            host="127.0.0.1",
            port=0,
        )

        # Read the assigned port
        port = self._server.sockets[0].getsockname()[1]

        # Write daemon info
        write_daemon_info(os.getpid(), port, self._token)

        logger.info("daemon_started", port=port, pid=os.getpid())

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single client connection."""
        self._last_activity = time.monotonic()
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not line:
                writer.close()
                await writer.wait_closed()
                return

            request = json.loads(line.decode())

            # Verify auth token on Windows (Unix uses socket permissions)
            if _IS_WINDOWS and request.get("token") != self._token:
                error_resp = {
                    "decision": "deny",
                    "reason": "Invalid daemon auth token",
                    "matched_policy_ids": [],
                    "receipt_id": None,
                    "evaluation_time_ms": 0,
                }
                writer.write(json.dumps(error_resp).encode() + b"\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # Handle shutdown request
            if request.get("shutdown"):
                writer.write(json.dumps({"status": "stopping"}).encode() + b"\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                self._shutdown_event.set()
                return

            # Handle reload request -- flush cached engines so the next
            # evaluation picks up config/policy changes from disk.
            if request.get("reload"):
                self._engines.clear()
                logger.info("daemon_reload", reason="reload request received")
                writer.write(json.dumps({"status": "reloaded"}).encode() + b"\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            response = await asyncio.to_thread(self._evaluate, request)

            # Schedule receipt cleanup on first request per project
            cwd = request.get("cwd", os.getcwd())
            project_path = Path(cwd).resolve()
            if project_path not in self._cleaned_projects:
                self._cleaned_projects.add(project_path)
                asyncio.get_event_loop().call_later(
                    30, self._schedule_receipt_cleanup, project_path
                )

            writer.write(json.dumps(response).encode() + b"\n")
            await writer.drain()
        except Exception as exc:
            # Fail closed — deny on unexpected errors, consistent with inline path
            try:
                error_resp = {
                    "decision": "deny",
                    "reason": f"Daemon error (fail closed): {exc}",
                    "matched_policy_ids": [],
                    "receipt_id": None,
                    "evaluation_time_ms": 0,
                }
                writer.write(json.dumps(error_resp).encode() + b"\n")
                await writer.drain()
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _evaluate(self, request: dict) -> dict:
        """Run policy evaluation synchronously (called via to_thread)."""
        source = request.get("source", "claude-code")
        payload = request.get("payload", {})
        cwd = request.get("cwd", os.getcwd())
        project_path = Path(cwd).resolve()

        try:
            event = normalise(payload, source)
        except Exception as exc:
            return {
                "decision": "deny",
                "reason": f"Normalisation error (fail closed): {exc}",
                "matched_policy_ids": [],
                "receipt_id": None,
                "evaluation_time_ms": 0,
            }

        cached = self._get_engine(project_path)
        loader = cached.loader
        engine = cached.engine

        # Apply identity from config
        if event.identity.persona == "default":
            event.identity.persona = loader.config.get_persona(project_path)
        if not event.identity.groups:
            event.identity.groups = loader.config.get_groups(project_path)
        if event.identity.identity_type == "human":
            configured_type = loader.config.get_identity_type(project_path)
            if configured_type != "human":
                event.identity.identity_type = configured_type

        decision = engine.evaluate(event)

        # Generate receipt
        receipt_id: str | None = None
        try:
            from vectimus.engine.receipts import generate_receipt_id

            if loader.config.is_receipts_enabled(project_path):
                receipt_id = generate_receipt_id()
        except Exception:
            pass

        # Write audit log
        write_audit(
            event,
            decision,
            log_dir=loader.config.get_audit_log_dir(project_path),
            max_file_size_mb=loader.config.get_audit_max_file_size_mb(project_path),
            receipt_id=receipt_id,
        )

        # Write receipt synchronously — daemon stays alive so no race condition
        if receipt_id:
            try:
                self._write_receipt(
                    receipt_id=receipt_id,
                    event=event,
                    decision=decision,
                    engine=engine,
                    loader=loader,
                    project_path=project_path,
                    observe=engine._observe,
                )
            except Exception as exc:
                print(f"vectimus: receipt write failed: {exc}", file=sys.stderr)

        return {
            "decision": decision.decision,
            "reason": decision.reason,
            "suggested_alternative": decision.suggested_alternative,
            "matched_policy_ids": decision.matched_policy_ids,
            "receipt_id": receipt_id,
            "evaluation_time_ms": decision.evaluation_time_ms,
        }

    def _write_receipt(
        self,
        *,
        receipt_id: str,
        event: VectimusEvent,  # noqa: F821
        decision: Decision,  # noqa: F821
        engine: PolicyEngine,
        loader: PolicyLoader,
        project_path: Path,
        observe: bool,
    ) -> None:
        """Build, sign and write a receipt synchronously."""
        from vectimus.engine.keys import load_signing_key
        from vectimus.engine.receipts import (
            _write_receipt_sync,
            build_receipt,
            compute_context_hash,
            compute_policy_set_hash,
            sign_receipt,
        )

        # Determine outcome
        if observe and decision.decision in (DecisionVerdict.DENY, DecisionVerdict.ESCALATE):
            outcome = "OBSERVE"
        elif decision.decision == DecisionVerdict.DENY:
            outcome = "DENY"
        elif decision.decision == DecisionVerdict.ESCALATE:
            outcome = "DENY"
        else:
            outcome = "ALLOW"

        command_summary = event.action.command or event.action.file_path or event.action.url or ""

        action_context: dict = {
            "action_type": event.action.action_type,
            "raw_tool_name": event.action.raw_tool_name,
        }
        if event.action.command:
            action_context["command"] = event.action.command
        if event.action.file_path:
            action_context["file_path"] = event.action.file_path
        if event.action.url:
            action_context["url"] = event.action.url

        context_hash = compute_context_hash(action_context)
        policy_set_hash = compute_policy_set_hash(engine._policies_text)

        pack_version = "0.0.0"
        try:
            packs = loader.discover_packs()
            if packs:
                pack_version = packs[0].version
        except Exception:
            pass

        matched_policy_id = decision.matched_policy_ids[0] if decision.matched_policy_ids else None
        principal_type = "agent" if event.identity.identity_type == "agent" else "developer"

        receipt = build_receipt(
            receipt_id=receipt_id,
            principal_type=principal_type,
            principal_id=event.identity.principal,
            tool=event.action.raw_tool_name,
            normalised_tool=event.action.action_type,
            command_summary=command_summary,
            context_hash=context_hash,
            policy_set_hash=policy_set_hash,
            policy_pack_version=pack_version,
            matched_policy_id=matched_policy_id,
            outcome=outcome,
            reason=decision.reason or "All checks passed",
            evaluation_time_ms=decision.evaluation_time_ms,
        )

        try:
            key_id, signing_key = load_signing_key()
            receipt = sign_receipt(receipt, signing_key, key_id)
        except FileNotFoundError:
            pass

        receipts_dir = project_path / ".vectimus" / "receipts"
        _write_receipt_sync(receipt, receipts_dir)

    def _get_engine(self, project_path: Path) -> _CachedEngine:
        """Get or create a cached PolicyEngine for the given project."""
        loader = PolicyLoader(project_path=project_path)
        observe = os.environ.get("VECTIMUS_OBSERVE", "").lower() in ("1", "true", "yes")
        if not observe:
            observe = loader.config.is_observe_mode()

        key = (str(project_path), observe)
        cached = self._engines.get(key)

        if cached and (time.monotonic() - cached.created_at) < ENGINE_CACHE_TTL:
            return cached

        engine = PolicyEngine(loader=loader, observe=observe)
        cached = _CachedEngine(engine, loader)
        self._engines[key] = cached
        logger.info("engine_cached", project=str(project_path), observe=observe)
        return cached

    def _schedule_receipt_cleanup(self, project_path: Path) -> None:
        """Schedule receipt cleanup for a project in a background task."""
        asyncio.ensure_future(self._run_receipt_cleanup(project_path))

    async def _run_receipt_cleanup(self, project_path: Path) -> None:
        """Run receipt retention cleanup in a thread to avoid blocking."""
        try:
            from vectimus.engine.config import VectimusConfig
            from vectimus.engine.receipts import cleanup_old_receipts

            config = VectimusConfig()
            receipts_dir = project_path / ".vectimus" / "receipts"
            if receipts_dir.exists():
                retention_days = config.get_receipts_retention_days(project_path)
                removed = await asyncio.to_thread(
                    cleanup_old_receipts, receipts_dir, retention_days
                )
                if removed:
                    logger.info(
                        "daemon_receipt_cleanup",
                        project=str(project_path),
                        removed=removed,
                    )
        except Exception as exc:
            logger.warning("daemon_receipt_cleanup_failed", error=str(exc))

    async def _idle_watchdog(self) -> None:
        """Shut down after idle_timeout seconds of inactivity."""
        while True:
            await asyncio.sleep(60)
            idle = time.monotonic() - self._last_activity
            if idle > self._idle_timeout:
                logger.info("daemon_idle_shutdown", idle_seconds=int(idle))
                self._shutdown_event.set()
                return

    async def shutdown(self) -> None:
        """Clean shutdown: close server, remove socket/info files."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        remove_daemon_info()
        logger.info("daemon_stopped")
