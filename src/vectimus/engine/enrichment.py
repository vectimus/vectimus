"""Enrich VectimusEvent objects with contextual metadata.

Fills in fields that the normaliser cannot determine from the raw payload
alone: package version, hostname, git identity, repository and branch.
"""

from __future__ import annotations

import getpass
import os
import socket
import subprocess
from functools import lru_cache

import vectimus
from vectimus.engine.models import VectimusEvent

_GIT_TIMEOUT = int(os.environ.get("VECTIMUS_GIT_TIMEOUT", "5"))


# ---------------------------------------------------------------------------
# Cached look-ups
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _get_hostname() -> str | None:
    try:
        return socket.gethostname()
    except OSError:
        return None


@lru_cache(maxsize=1)
def _get_identity() -> str | None:
    """Resolve principal: git email -> git name -> OS user."""
    for git_field in ("user.email", "user.name"):
        try:
            result = subprocess.run(
                ["git", "config", git_field],
                capture_output=True,
                text=True,
                timeout=_GIT_TIMEOUT,
            )
            value = result.stdout.strip()
            if value:
                return value
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue

    try:
        return getpass.getuser()
    except OSError:
        return None


@lru_cache(maxsize=4)
def _get_repository(cwd: str | None) -> str | None:
    if cwd is None:
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            cwd=cwd,
        )
        value = result.stdout.strip()
        return value if value and result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


@lru_cache(maxsize=4)
def _get_branch(cwd: str | None) -> str | None:
    if cwd is None:
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            cwd=cwd,
        )
        value = result.stdout.strip()
        return value if value and result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def enrich(event: VectimusEvent) -> VectimusEvent:
    """Fill in missing metadata fields on *event* and return it.

    Never overwrites fields the normaliser already set.
    """
    # source.version
    if event.source.version is None:
        event.source.version = vectimus.__version__

    # context.hostname
    if event.context.hostname is None:
        event.context.hostname = _get_hostname()

    # identity.principal
    if event.identity.principal == "unknown":
        identity = _get_identity()
        if identity:
            event.identity.principal = identity

    # context.repository
    if event.context.repository is None:
        event.context.repository = _get_repository(event.context.cwd)

    # context.branch
    if event.context.branch is None:
        event.context.branch = _get_branch(event.context.cwd)

    return event
