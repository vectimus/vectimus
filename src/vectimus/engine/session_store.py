"""Thread-safe in-memory session store for temporal pattern detection.

Tracks per-session metrics (agent spawns, messages, total actions) so that
Cedar policies can detect flood patterns like an agent spawning 50 sub-agents
one at a time with individually safe parameters.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class SessionMetrics:
    """Accumulated counters for a single session."""

    agent_spawns: int = 0
    agent_messages: int = 0
    total_actions: int = 0
    first_seen: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)


class SessionStore:
    """Thread-safe in-memory session store keyed by ``session_id``.

    Parameters
    ----------
    spawn_limit:
        Number of agent spawns before the session is flagged.
    message_limit:
        Number of agent messages before the session is flagged.
    ttl_seconds:
        Seconds after which idle sessions are evicted.
    """

    def __init__(
        self,
        spawn_limit: int = 10,
        message_limit: int = 50,
        ttl_seconds: int = 3600,
    ) -> None:
        self.spawn_limit = spawn_limit
        self.message_limit = message_limit
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, SessionMetrics] = {}
        self._lock = threading.Lock()

    def record(self, session_id: str, action_type: str) -> SessionMetrics:
        """Record an action for *session_id* and return updated metrics.

        Auto-evicts stale sessions on each call.
        """
        with self._lock:
            self._evict_stale()

            metrics = self._sessions.get(session_id)
            if metrics is None:
                metrics = SessionMetrics()
                self._sessions[session_id] = metrics

            metrics.last_seen = time.monotonic()
            metrics.total_actions += 1

            if action_type == "agent_spawn":
                metrics.agent_spawns += 1
            elif action_type == "agent_message":
                metrics.agent_messages += 1

            return metrics

    def get(self, session_id: str) -> SessionMetrics | None:
        """Return metrics for *session_id*, or ``None`` if not tracked."""
        with self._lock:
            return self._sessions.get(session_id)

    def _evict_stale(self) -> None:
        """Remove sessions older than TTL.  Called under lock."""
        now = time.monotonic()
        stale = [sid for sid, m in self._sessions.items() if (now - m.last_seen) > self.ttl_seconds]
        for sid in stale:
            del self._sessions[sid]
