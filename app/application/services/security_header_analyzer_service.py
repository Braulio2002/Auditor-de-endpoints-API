from app.domain.entities.api_endpoint import ApiEndpoint
from app.domain.entities.http_response_info import HttpResponseInfo
from app.domain.entities.security_finding import SecurityFinding
from app.domain.value_objects.finding_category import FindingCategory
from app.domain.value_objects.finding_severity import FindingSeverity
from app.shared.constants import INFO_EXPOSING_HEADERS, SECURITY_HEADERS


class SecurityHeaderAnalyzerService:
    """
    Analyzes response headers to detect missing security headers or information exposure.
    """

    def analyze(self, endpoint: ApiEndpoint, response: HttpResponseInfo) -> list[SecurityFinding]:
        findings = []

        if response.error:
            return findings

        # Check response headers (case-insensitive keys)
        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        # 1. Missing recommended headers
        missing = self._check_missing_headers(resp_headers, response.url)
        if missing:
            findings.append(
                SecurityFinding(
                    categoria=FindingCategory.SECURITY_HEADERS,
                    severidad=FindingSeverity.LOW,
                    titulo="Cabeceras de seguridad ausentes en la respuesta",
                    descripcion=(
                        f"El endpoint no retorna las siguientes cabeceras de seguridad: "
                        f"{', '.join(missing)}. Esto disminuye el nivel de protección de "
                        "los clientes que consumen el API contra ataques en el navegador o sniffing."
                    ),
                    evidencia_segura=f"Faltan cabeceras: {', '.join(missing)}",
                    recomendacion=(
                        "Configurar el servidor web o el API Gateway para inyectar cabeceras de seguridad estándar: "
                        "X-Content-Type-Options: nosniff, Strict-Transport-Security (HSTS), "
                        "Cache-Control: no-store para respuestas privadas, y configurar adecuadamente CSP."
                    ),
                )
            )

        # 2. Cache check
        cache_finding = self._check_private_cache(resp_headers, endpoint, response.headers)
        if cache_finding:
            findings.append(cache_finding)

        # 3. Technology disclosure check
        tech_finding = self._check_exposed_technology(resp_headers, response.headers)
        if tech_finding:
            findings.append(tech_finding)

        # 4. Content Type sanity
        content_finding = self._check_content_type_sanity(
            resp_headers, response.body_sample, response.headers
        )
        if content_finding:
            findings.append(content_finding)

        return findings

    def _check_missing_headers(self, resp_headers: dict[str, str], url: str) -> list[str]:
        missing = []
        for header in SECURITY_HEADERS:
            h_lower = header.lower()
            if h_lower not in resp_headers:
                if header == "Strict-Transport-Security" and not url.startswith("https://"):
                    continue
                missing.append(header)
        return missing

    def _check_private_cache(
        self, resp_headers: dict[str, str], endpoint: ApiEndpoint, original_headers: dict[str, str]
    ) -> SecurityFinding | None:
        is_private = endpoint.tipo_endpoint == "privado" or endpoint.requiere_auth == "si"
        if not (is_private and "cache-control" in resp_headers):
            return None

        cache_val = resp_headers["cache-control"].lower()
        if "no-store" in cache_val or "no-cache" in cache_val:
            return None

        return SecurityFinding(
            categoria=FindingCategory.SECURITY_HEADERS,
            severidad=FindingSeverity.LOW,
            titulo="Cache-Control inseguro para endpoint sensible",
            descripcion=(
                f"El endpoint contiene datos privados pero su header Cache-Control "
                f"({original_headers.get('Cache-Control')}) permite almacenamiento. "
                "Esto podría causar que intermediarios o navegadores almacenen datos sensibles."
            ),
            evidencia_segura=f"Cache-Control: {original_headers.get('Cache-Control')}",
            recomendacion=(
                "Configurar cabecera Cache-Control: no-store, no-cache, must-revalidate "
                "para todas las respuestas con datos sensibles."
            ),
        )

    def _check_exposed_technology(
        self, resp_headers: dict[str, str], original_headers: dict[str, str]
    ) -> SecurityFinding | None:
        exposed_tech = []
        for header in INFO_EXPOSING_HEADERS:
            h_lower = header.lower()
            if h_lower in resp_headers:
                val = original_headers.get(header, "")
                if (
                    header == "Server" and any(char.isdigit() for char in val)
                ) or header != "Server":
                    exposed_tech.append(f"{header} ({val})")

        if not exposed_tech:
            return None

        return SecurityFinding(
            categoria=FindingCategory.INFORMATION_DISCLOSURE,
            severidad=FindingSeverity.INFO,
            titulo="Cabeceras que exponen información de tecnologías de backend",
            descripcion=(
                f"Se detectaron cabeceras HTTP que revelan detalles sobre el servidor o frameworks: "
                f"{', '.join(exposed_tech)}. Esto facilita la fase de reconocimiento de un atacante."
            ),
            evidencia_segura=f"Cabeceras expuestas: {', '.join(exposed_tech)}",
            recomendacion=(
                "Ocultar o deshabilitar cabeceras informativas innecesarias como X-Powered-By "
                "o X-AspNet-Version. Ofuscar el header Server en la configuración del servidor web "
                "(ej. Nginx ServerTokens off o similar en Apache o Cloudflare)."
            ),
        )

    def _check_content_type_sanity(
        self, resp_headers: dict[str, str], body_sample: str, original_headers: dict[str, str]
    ) -> SecurityFinding | None:
        if "content-type" not in resp_headers:
            return None

        content_type = resp_headers["content-type"].lower()
        if "application/json" in content_type or "application/xml" in content_type:
            return None

        clean_body = body_sample.strip()
        if not clean_body.startswith(("{", "[")):
            return None

        return SecurityFinding(
            categoria=FindingCategory.SECURITY_HEADERS,
            severidad=FindingSeverity.LOW,
            titulo="Content-Type inadecuado para API JSON",
            descripcion=(
                f"El API responde con un cuerpo de tipo JSON pero el header Content-Type "
                f"es '{original_headers.get('Content-Type')}' en lugar de 'application/json'."
            ),
            evidencia_segura=f"Content-Type: {original_headers.get('Content-Type')}",
            recomendacion=(
                "Configurar el endpoint para enviar la cabecera 'Content-Type: application/json' "
                "cuando retorne estructuras de datos en formato JSON."
            ),
        )
