from urllib.parse import urlparse

from app.domain.entities.api_endpoint import ApiEndpoint


class EndpointValidatorService:
    """
    Validates, normalizes, and filters API endpoints from the input file.
    """

    def validate_and_normalize(self, endpoint: ApiEndpoint) -> tuple[bool, str | None, ApiEndpoint]:
        """
        Validates URL and method, normalizes fields, and returns a tuple:
        (is_valid, error_reason, normalized_endpoint)
        """
        # 1. URL validation
        url = (endpoint.url or "").strip()
        is_valid_url, reason = self._validate_url(url)
        if not is_valid_url:
            return False, reason, endpoint

        # 2. HTTP Method normalization and validation
        metodo = (endpoint.metodo or "").strip().upper()
        if not metodo:
            metodo = "GET"

        # 3. requiere_auth normalization
        req_auth = self._normalize_auth(endpoint.requiere_auth)

        # 4. tipo_endpoint normalization
        tipo = self._normalize_tipo(endpoint.tipo_endpoint)

        # 5. Clean name and description
        nombre = (endpoint.nombre or "Endpoint sin nombre").strip()
        descripcion = (endpoint.descripcion or "").strip()

        normalized = ApiEndpoint(
            nombre=nombre,
            url=url,
            metodo=metodo,
            requiere_auth=req_auth,
            tipo_endpoint=tipo,
            descripcion=descripcion,
        )

        return True, None, normalized

    def _validate_url(self, url: str) -> tuple[bool, str | None]:
        if not url:
            return False, "URL vacía"

        parsed_url = urlparse(url)
        if not parsed_url.scheme or parsed_url.scheme not in ("http", "https"):
            return False, f"Esquema URL inválido ({parsed_url.scheme or 'ninguno'})"
        if not parsed_url.netloc:
            return False, "Host URL inválido"

        return True, None

    def _normalize_auth(self, req_auth: str) -> str:
        clean = (req_auth or "").strip().lower()
        if clean in ("si", "sí", "true", "yes", "1"):
            return "si"
        if clean in ("no", "false", "0"):
            return "no"
        return "desconocido"

    def _normalize_tipo(self, tipo: str) -> str:
        clean = (tipo or "").strip().lower()
        if clean in ("privado", "private"):
            return "privado"
        if clean in ("publico", "público", "public"):
            return "publico"
        return "no clasificado"
