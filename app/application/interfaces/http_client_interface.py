from abc import ABC, abstractmethod

from app.domain.entities.http_response_info import HttpResponseInfo


class HttpClientInterface(ABC):
    """
    Interface for safely making HTTP requests to endpoints for scanning purposes.
    """

    @abstractmethod
    def send_request(
        self,
        url: str,
        method: str,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        safe_mode: bool = True,
    ) -> HttpResponseInfo:
        """
        Sends an HTTP request to the given url with safe auditing checks.
        If safe_mode is True, restricts non-safe verbs (like POST, PUT, DELETE)
        from sending harmful state-altering payloads, testing OPTIONS or HEAD instead if possible,
        or just making a safe config check.
        """
        pass
