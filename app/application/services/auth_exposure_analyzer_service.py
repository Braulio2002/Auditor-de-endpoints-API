from app.domain.entities.api_endpoint import ApiEndpoint
from app.domain.entities.http_response_info import HttpResponseInfo
from app.domain.entities.security_finding import SecurityFinding
from app.domain.value_objects.finding_category import FindingCategory
from app.domain.value_objects.finding_severity import FindingSeverity


class AuthExposureAnalyzerService:
    """
    Analyzes whether private/authenticated endpoints are exposed without proper authorization.
    """

    def analyze(
        self, endpoint: ApiEndpoint, response: HttpResponseInfo, has_credentials_sent: bool
    ) -> list[SecurityFinding]:
        findings = []

        # If there's an error in response (e.g. DNS or connection failure), we cannot analyze auth exposure
        if response.error:
            return findings

        # Check if the endpoint is defined as requiring auth or being private,
        # but we accessed it without credentials (anonymous request)
        is_private = endpoint.tipo_endpoint == "privado" or endpoint.requiere_auth == "si"

        if is_private and not has_credentials_sent:
            # Successful response (2xx) without credentials is a high-risk exposure
            if response.status_code in (200, 201, 204):
                findings.append(
                    SecurityFinding(
                        categoria=FindingCategory.AUTHENTICATION,
                        severidad=FindingSeverity.CRITICAL,
                        titulo="Acceso no autenticado a endpoint privado",
                        descripcion=(
                            f"El endpoint está clasificado como '{endpoint.tipo_endpoint}' "
                            f"y 'requiere_auth={endpoint.requiere_auth}', pero respondió con código "
                            f"{response.status_code} ante una petición sin credenciales. "
                            f"Esto indica una total ausencia de control de accesos."
                        ),
                        evidencia_segura=f"Status: {response.status_code}. Response: {response.body_sample[:100]}",
                        recomendacion=(
                            "Proteger el endpoint mediante validación estricta de tokens JWT, "
                            "sesión o API Keys en el servidor. Implementar middleware de autenticación "
                            "y no confiar nunca únicamente en validaciones del lado del cliente."
                        ),
                    )
                )
            # Response that returns details instead of 401/403
            elif response.status_code not in (401, 403) and response.status_code is not None:
                # E.g. returning 500 or 302, which is still technically exposing the endpoint but not directly 200
                findings.append(
                    SecurityFinding(
                        categoria=FindingCategory.AUTHENTICATION,
                        severidad=FindingSeverity.MEDIUM,
                        titulo="Código HTTP inadecuado para acceso no autorizado",
                        descripcion=(
                            f"El endpoint privado respondió con código {response.status_code} "
                            f"en vez de 401 (Unauthorized) o 403 (Forbidden) al no proveer credenciales."
                        ),
                        evidencia_segura=f"Status: {response.status_code}",
                        recomendacion=(
                            "Configurar el endpoint para retornar explícitamente 401 (Unauthorized) "
                            "cuando las credenciales no son válidas o están ausentes."
                        ),
                    )
                )

        return findings
