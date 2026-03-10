"""Tests for the in-memory session store."""

from __future__ import annotations

import time

from vectimus.core.session_store import SessionStore


def test_record_increments_counts() -> None:
    store = SessionStore()
    m = store.record("s1", "agent_spawn")
    assert m.agent_spawns == 1
    assert m.total_actions == 1

    m = store.record("s1", "agent_spawn")
    assert m.agent_spawns == 2
    assert m.total_actions == 2

    m = store.record("s1", "agent_message")
    assert m.agent_messages == 1
    assert m.total_actions == 3

    m = store.record("s1", "shell_command")
    assert m.agent_spawns == 2
    assert m.agent_messages == 1
    assert m.total_actions == 4


def test_separate_sessions_isolated() -> None:
    store = SessionStore()
    store.record("a", "agent_spawn")
    store.record("a", "agent_spawn")
    store.record("b", "agent_spawn")

    ma = store.get("a")
    mb = store.get("b")
    assert ma is not None
    assert mb is not None
    assert ma.agent_spawns == 2
    assert mb.agent_spawns == 1


def test_eviction_removes_stale() -> None:
    store = SessionStore(ttl_seconds=0)
    store.record("old", "agent_spawn")

    # Force a tiny delay so the session is older than TTL=0.
    time.sleep(0.01)

    # Recording a new session should evict the stale one.
    store.record("new", "agent_spawn")
    assert store.get("old") is None
    assert store.get("new") is not None


def test_spawn_limit_detection() -> None:
    store = SessionStore(spawn_limit=3)
    for _ in range(3):
        m = store.record("s1", "agent_spawn")
    assert m.agent_spawns == 3
    assert m.agent_spawns <= store.spawn_limit  # at limit, not over

    m = store.record("s1", "agent_spawn")
    assert m.agent_spawns == 4
    assert m.agent_spawns > store.spawn_limit  # now over limit


def test_message_limit_detection() -> None:
    store = SessionStore(message_limit=2)
    for _ in range(2):
        m = store.record("s1", "agent_message")
    assert m.agent_messages == 2
    assert m.agent_messages <= store.message_limit

    m = store.record("s1", "agent_message")
    assert m.agent_messages == 3
    assert m.agent_messages > store.message_limit
