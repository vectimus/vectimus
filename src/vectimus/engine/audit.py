"""Audit record writing for hook evaluations.

Wraps the JSONL exporter with error handling so audit failures
never block the hook response.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vectimus.engine.models import Decision, VectimusEvent


def write_audit(
    event: VectimusEvent,
    decision: Decision,
    log_dir: str | None = None,
    max_file_size_mb: int | None = None,
    receipt_id: str | None = None,
) -> None:
    """Write an audit record to the local JSONL log.

    Failures are logged to stderr but never block the hook response.
    """
    try:
        from vectimus.engine.models import AuditRecord as _AuditRecord
        from vectimus.exporters.jsonl import JsonlExporter

        record = _AuditRecord(event=event, decision=decision, receipt_id=receipt_id)
        JsonlExporter(
            log_dir=log_dir,
            max_file_size_mb=max_file_size_mb,
        ).export(record)
    except Exception as exc:
        print(f"vectimus: audit write failed: {exc}", file=sys.stderr)
