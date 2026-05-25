from abc import ABC, abstractmethod
from pathlib import Path

from app.domain.entities.api_endpoint import ApiEndpoint


class EndpointReaderInterface(ABC):
    """
    Interface for reading API endpoints from a storage file.
    """

    @abstractmethod
    def read_endpoints(self, file_path: Path) -> list[ApiEndpoint]:
        """
        Reads endpoints from the specified path and returns a list of ApiEndpoint models.
        """
        pass
