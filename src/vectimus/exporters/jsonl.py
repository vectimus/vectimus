"""Local JSONL file exporter for audit records.

Writes AuditRecord objects as newline-delimited JSON.  Supports daily log
rotation and a 100 MB file-size cap.  Uses file locking to prevent corruption
when multiple hook processes write concurrently.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from vectimus.core.models import AuditRecord
from vectimus.exporters.base import BaseExporter

_DEFAULT_DIR = Path.home() / ".vectimus"
_MAX_FILE_BYTES = 100 * 1024 * 1024  # 100 MB
_MAX_ROTATION_SUFFIX = 1000

# Platform-specific file locking.
if sys.platform == "win32":
    import msvcrt

    def _lock(f) -> None:  # type: ignore[type-arg]
        """Lock file on Windows."""
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)

    def _unlock(f) -> None:  # type: ignore[type-arg]
        """Unlock file on Windows."""
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock(f) -> None:  # type: ignore[type-arg]
        """Lock file on Unix (blocks until lock acquired)."""
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)

    def _unlock(f) -> None:  # type: ignore[type-arg]
        """Unlock file on Unix."""
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)


class JsonlExporter(BaseExporter):
    """Append audit records to a JSONL file with daily rotation."""

    def __init__(
        self,
        log_dir: str | Path | None = None,
        max_file_size_mb: int | None = None,
    ) -> None:
        self._log_dir = Path(log_dir) if log_dir else _DEFAULT_DIR
        self._log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._current_date: str = ""
        self._current_path: Path | None = None

        # Resolve max file size: explicit arg > env var > module default.
        if max_file_size_mb is not None:
            self._max_file_bytes = max(max_file_size_mb, 1) * 1024 * 1024
        else:
            env = os.environ.get("VECTIMUS_AUDIT_MAX_MB")
            if env:
                try:
                    self._max_file_bytes = max(int(env), 1) * 1024 * 1024
                except (TypeError, ValueError):
                    self._max_file_bytes = _MAX_FILE_BYTES
            else:
                self._max_file_bytes = _MAX_FILE_BYTES

    def export(self, record: AuditRecord) -> None:
        """Append a single audit record as a JSON line with file locking."""
        path = self._resolve_path()
        line = json.dumps(record.model_dump(), default=str)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            _lock(f)
            try:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                _unlock(f)

    def close(self) -> None:
        """No persistent resources to release."""

    def _resolve_path(self) -> Path:
        """Return the log file path, rotating by date or size."""
        today = datetime.now(UTC).strftime("%Y-%m-%d")

        if today != self._current_date:
            self._current_date = today
            self._current_path = self._log_dir / f"audit-{today}.jsonl"

        if self._current_path is None:
            self._current_path = self._log_dir / f"audit-{today}.jsonl"

        # Rotate if the file exceeds the size cap.
        if self._current_path.exists() and self._current_path.stat().st_size > self._max_file_bytes:
            rotated_found = False
            suffix = 1
            while suffix <= _MAX_ROTATION_SUFFIX:
                rotated = self._log_dir / f"audit-{today}-{suffix}.jsonl"
                if not rotated.exists():
                    self._current_path = rotated
                    rotated_found = True
                    break
                suffix += 1
            if not rotated_found:
                # All rotation slots exhausted -- use a timestamped fallback
                # to prevent writing to an oversized file indefinitely.
                import time

                ts = int(time.time())
                self._current_path = self._log_dir / f"audit-{today}-overflow-{ts}.jsonl"

        return self._current_path
