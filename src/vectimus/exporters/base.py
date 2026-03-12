"""Abstract exporter interface for audit records."""

from __future__ import annotations

from abc import ABC, abstractmethod

from vectimus.engine.models import AuditRecord


class BaseExporter(ABC):
    """Base class for audit record exporters.

    Subclasses must implement the ``export`` method to persist a single
    AuditRecord to their backing store.
    """

    @abstractmethod
    def export(self, record: AuditRecord) -> None:
        """Write a single audit record."""

    @abstractmethod
    def close(self) -> None:
        """Release any resources held by the exporter."""
