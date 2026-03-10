"""Tests for the JSONL audit log exporter."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from vectimus.core.models import (
    ActionInfo,
    AuditRecord,
    ContextInfo,
    Decision,
    DecisionVerdict,
    IdentityInfo,
    SourceInfo,
    VectimusEvent,
)
from vectimus.exporters.jsonl import _MAX_FILE_BYTES, JsonlExporter


def _make_record(command: str = "ls") -> AuditRecord:
    """Create a minimal AuditRecord for testing."""
    event = VectimusEvent(
        source=SourceInfo(tool="test"),
        identity=IdentityInfo(principal="tester"),
        action=ActionInfo(
            action_type="shell_command",
            raw_tool_name="Bash",
            command=command,
        ),
        context=ContextInfo(),
    )
    decision = Decision(decision=DecisionVerdict.ALLOW)
    return AuditRecord(event=event, decision=decision)


class TestBasicExport:
    """Records are written to the correct path."""

    def test_creates_log_file(self, tmp_path: Path) -> None:
        exporter = JsonlExporter(log_dir=tmp_path)
        exporter.export(_make_record())

        files = list(tmp_path.glob("audit-*.jsonl"))
        assert len(files) == 1

    def test_writes_valid_json_line(self, tmp_path: Path) -> None:
        exporter = JsonlExporter(log_dir=tmp_path)
        exporter.export(_make_record("echo hello"))

        files = list(tmp_path.glob("audit-*.jsonl"))
        line = files[0].read_text().strip()
        data = json.loads(line)
        assert data["event"]["action"]["command"] == "echo hello"
        assert data["decision"]["decision"] == "allow"

    def test_appends_multiple_records(self, tmp_path: Path) -> None:
        exporter = JsonlExporter(log_dir=tmp_path)
        exporter.export(_make_record("cmd1"))
        exporter.export(_make_record("cmd2"))

        files = list(tmp_path.glob("audit-*.jsonl"))
        lines = files[0].read_text().strip().split("\n")
        assert len(lines) == 2

    def test_log_dir_created_if_missing(self, tmp_path: Path) -> None:
        log_dir = tmp_path / "sub" / "logs"
        exporter = JsonlExporter(log_dir=log_dir)
        exporter.export(_make_record())

        assert log_dir.exists()
        assert len(list(log_dir.glob("audit-*.jsonl"))) == 1


class TestDailyRotation:
    """Log files rotate by date."""

    def test_new_day_creates_new_file(self, tmp_path: Path) -> None:
        exporter = JsonlExporter(log_dir=tmp_path)

        with patch("vectimus.exporters.jsonl.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 3, 1, tzinfo=UTC)
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            exporter._current_date = ""
            exporter._current_path = None
            # Manually call _resolve_path with mocked date.
            with patch.object(
                type(exporter),
                "_resolve_path",
                wraps=exporter._resolve_path,
            ):
                exporter.export(_make_record("day1"))

        # Simulate next day by resetting state.
        exporter._current_date = "2026-03-02"
        exporter._current_path = tmp_path / "audit-2026-03-02.jsonl"
        exporter.export(_make_record("day2"))

        files = sorted(tmp_path.glob("audit-*.jsonl"))
        assert len(files) == 2


class TestSizeBasedRotation:
    """Log files rotate when exceeding size cap."""

    def test_rotates_when_over_size(self, tmp_path: Path) -> None:
        exporter = JsonlExporter(log_dir=tmp_path)

        today = datetime.now(UTC).strftime("%Y-%m-%d")
        base_file = tmp_path / f"audit-{today}.jsonl"

        # Create an oversized file.
        base_file.write_text("x" * (_MAX_FILE_BYTES + 1))

        exporter.export(_make_record("after-rotation"))

        rotated = tmp_path / f"audit-{today}-1.jsonl"
        assert rotated.exists()

    def test_max_rotation_suffix_cap(self, tmp_path: Path) -> None:
        exporter = JsonlExporter(log_dir=tmp_path)

        today = datetime.now(UTC).strftime("%Y-%m-%d")
        base_file = tmp_path / f"audit-{today}.jsonl"
        base_file.write_text("x" * (_MAX_FILE_BYTES + 1))

        # Create files up to the suffix cap.
        for i in range(1, 1001):
            (tmp_path / f"audit-{today}-{i}.jsonl").write_text("x")

        # Should still write (to the last file), not crash.
        exporter.export(_make_record("overflow"))

        # The base file should still be used since all rotated names are taken.
        # This verifies we don't enter an infinite loop.


class TestCloseIsNoop:
    """Exporter.close() does not raise."""

    def test_close(self, tmp_path: Path) -> None:
        exporter = JsonlExporter(log_dir=tmp_path)
        exporter.close()  # Should not raise.
