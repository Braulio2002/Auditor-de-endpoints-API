from abc import ABC, abstractmethod
from pathlib import Path

from app.domain.entities.endpoint_audit_report import EndpointAuditReport


class ReportExporterInterface(ABC):
    """
    Interface for exporting completed audit reports to various formats.
    """

    @abstractmethod
    def export(self, reports: list[EndpointAuditReport], file_path: Path) -> None:
        """
        Exports a list of endpoint audit reports to a specific file.
        """
        pass
