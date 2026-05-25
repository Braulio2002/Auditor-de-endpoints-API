import time

import httpx

from app.application.interfaces.http_client_interface import HttpClientInterface
from app.domain.entities.http_response_info import HttpResponseInfo
from app.shared.logger import logger
from app.shared.masking_utils import mask_sensitive_data


class SafeHttpClient(HttpClientInterface):
    """
    Resilient and defensive HTTP client.
    Performs completely non-intrusive scans, managing connection failures,
    timeouts, SSL/DNS errors, and redirects cleanly.
    """

    def __init__(self, user_agent: str, rate_limit_delay: float = 0.5):
        self.user_agent = user_agent
        self.rate_limit_delay = rate_limit_delay

    def send_request(
        self,
        url: str,
        method: str,
        headers: dict[str, str] | None = None,
        timeout: float = 8.0,
        safe_mode: bool = True,
    ) -> HttpResponseInfo:
        """
        Sends an HTTP request with strict safety checks.
        If safe_mode is True and method is unsafe (POST, PUT, PATCH, DELETE),
        the client automatically conducts a non-destructive audit (e.g. utilizing OPTIONS or GET
        instead of mutating state, or sending completely empty headers/body).
        """
        # Apply rate limiting delay before starting request
        if self.rate_limit_delay > 0:
            time.sleep(self.rate_limit_delay)

        req_method = method.upper()
        req_headers = headers.copy() if headers else {}

        # Ensure User-Agent is set
        if "user-agent" not in {k.lower() for k in req_headers}:
            req_headers["User-Agent"] = self.user_agent

        # Log request parameters safely (mask auth tokens if present)
        masked_headers = {}
        for k, v in req_headers.items():
            if k.lower() in ("authorization", "x-api-key", "cookie", "token"):
                masked_headers[k] = mask_sensitive_data(v, "token")
            else:
                masked_headers[k] = v

        logger.debug(f"Iniciando petición HTTP: {req_method} {url} | Headers: {masked_headers}")

        # Safety intervention for state-altering verbs
        is_unsafe = req_method in ("POST", "PUT", "PATCH", "DELETE")

        if is_unsafe and safe_mode:
            logger.debug(
                f"Método de escritura '{req_method}' detectado en modo SAFE_MODE. "
                "Auditando con OPTIONS y GET de manera no destructiva..."
            )
            req_method = "GET"

        start_time = time.perf_counter()

        try:
            with httpx.Client(verify=True, follow_redirects=True, timeout=timeout) as client:
                resp = self._execute_client_call(client, req_method, url, req_headers)
                return self._build_success_response(url, req_method, resp, start_time)

        except httpx.ConnectTimeout:
            return self._build_error_response(
                url, req_method, "Timeout de conexión al host", start_time
            )
        except httpx.ReadTimeout:
            return self._build_error_response(
                url, req_method, "Timeout al leer la respuesta", start_time
            )
        except httpx.ConnectError as ce:
            return self._build_error_response(
                url,
                req_method,
                f"Fallo de conexión (DNS inválido o host inalcanzable): {ce}",
                start_time,
            )
        except httpx.SSLVerificationError as se:
            return self._build_error_response(
                url, req_method, f"Fallo en verificación SSL: {se}", start_time
            )
        except httpx.RequestError as re:
            return self._build_error_response(
                url, req_method, f"Error general de petición: {re}", start_time
            )
        except Exception as e:
            return self._build_error_response(
                url, req_method, f"Error inesperado de comunicación: {e}", start_time
            )

    def _execute_client_call(
        self, client: httpx.Client, method: str, url: str, headers: dict
    ) -> httpx.Response:
        if method == "GET":
            return client.get(url, headers=headers)
        if method == "HEAD":
            return client.head(url, headers=headers)
        if method == "OPTIONS":
            return client.options(url, headers=headers)
        return client.request(method, url, headers=headers, json={})

    def _build_success_response(
        self, url: str, method: str, resp: httpx.Response, start_time: float
    ) -> HttpResponseInfo:
        response_time = (time.perf_counter() - start_time) * 1000.0
        headers_dict = dict(resp.headers)
        content_type = headers_dict.get("Content-Type", "")

        try:
            body_sample = resp.text[:1000]
        except Exception:
            body_sample = "[Cuerpo binario o no decodificable]"

        return HttpResponseInfo(
            url=url,
            metodo=method,
            status_code=resp.status_code,
            headers=headers_dict,
            body_sample=body_sample,
            content_type=content_type,
            response_time_ms=response_time,
            error=None,
        )

    def _build_error_response(
        self, url: str, method: str, error_msg: str, start_time: float
    ) -> HttpResponseInfo:
        response_time = (time.perf_counter() - start_time) * 1000.0
        logger.debug(f"Petición fallida a {url}: {error_msg}")
        return HttpResponseInfo(
            url=url,
            metodo=method,
            status_code=None,
            headers={},
            body_sample="",
            content_type="",
            response_time_ms=response_time,
            error=error_msg,
        )

    def get_allowed_methods(
        self, url: str, headers: dict[str, str] | None = None, timeout: float = 8.0
    ) -> list[str]:
        """
        Sends an OPTIONS request or parses the 'Allow' header from a GET/HEAD response
        to find supported HTTP verbs for an endpoint without modifying data.
        """
        verbs = []
        req_headers = headers.copy() if headers else {}
        if "user-agent" not in {k.lower() for k in req_headers}:
            req_headers["User-Agent"] = self.user_agent

        try:
            with httpx.Client(verify=True, follow_redirects=True, timeout=timeout) as client:
                # 1. Try OPTIONS request
                logger.debug(f"Enviando OPTIONS para descubrir métodos: {url}")
                resp = client.options(url, headers=req_headers)

                # Check Allow header
                allow = resp.headers.get("Allow", "")
                if allow:
                    verbs = [v.strip().upper() for v in allow.split(",") if v.strip()]
                    return verbs

                # Also inspect Access-Control-Allow-Methods for CORS responses
                cors_methods = resp.headers.get("Access-Control-Allow-Methods", "")
                if cors_methods:
                    verbs = [v.strip().upper() for v in cors_methods.split(",") if v.strip()]
                    return verbs

                # 2. If OPTIONS didn't return headers, try a safe GET request and check Allow
                resp_get = client.get(url, headers=req_headers)
                allow = resp_get.headers.get("Allow", "")
                if allow:
                    verbs = [v.strip().upper() for v in allow.split(",") if v.strip()]
                    return verbs

        except Exception as e:
            logger.debug(
                f"No se pudieron obtener los métodos permitidos mediante OPTIONS/Allow en {url}: {e}"
            )

        return verbs
