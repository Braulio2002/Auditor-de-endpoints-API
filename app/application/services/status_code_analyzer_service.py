from app.domain.entities.api_endpoint import ApiEndpoint
from app.domain.entities.http_response_info import HttpResponseInfo
from app.domain.entities.security_finding import SecurityFinding
from app.domain.value_objects.finding_category import FindingCategory
from app.domain.value_objects.finding_severity import FindingSeverity


class StatusCodeAnalyzerService:
    """
    Analyzes whether the HTTP status codes returned by the endpoint are consistent and secure.
    """

    def analyze(
        self, endpoint: ApiEndpoint, response: HttpResponseInfo, has_credentials_sent: bool
    ) -> list[SecurityFinding]:
        findings = []

        if response.error or response.status_code is None:
            return findings

        status = response.status_code

        # 1. Endpoint private without credentials returning 200/201/204 instead of 401/403
        is_private = endpoint.tipo_endpoint == "privado" or endpoint.requiere_auth == "si"
        if is_private and not has_credentials_sent and status in (200, 201, 204):
            findings.append(
                SecurityFinding(
                    categoria=FindingCategory.STATUS_CODES,
                    severidad=FindingSeverity.CRITICAL,
                    titulo="Código de estado inconsistente: Retorno de 2xx OK en ruta privada",
                    descripcion=(
                        f"El endpoint está marcado como privado, pero devolvió un código "
                        f"{status} (Éxito) en lugar de 401 (Unauthorized) o 403 (Forbidden) "
                        "cuando se accedió de manera anónima."
                    ),
                    evidencia_segura=f"Status Code: {status}",
                    recomendacion=(
                        "Modificar el controlador en el servidor para retornar código 401 "
                        "si la autenticación falta, o 403 si la sesión/token carece de permisos."
                    ),
                )
            )

        # 2. Check 500 (Internal Server Error) code consistency
        if status == 500:
            findings.append(
                SecurityFinding(
                    categoria=FindingCategory.STATUS_CODES,
                    severidad=FindingSeverity.MEDIUM,
                    titulo="Código de estado inconsistente: Error de servidor 500",
                    descripcion=(
                        "El endpoint respondió con código 500. Esto indica que un error o excepción "
                        "no controlada ocurrió en el backend. Las peticiones mal formadas deben controlarse "
                        "y retornar 400 (Bad Request) o 422 (Unprocessable Entity) en lugar de fallar en el servidor."
                    ),
                    evidencia_segura=f"Status Code: {status}",
                    recomendacion=(
                        "Implementar validación estricta de parámetros en el backend y capturar excepciones "
                        "de negocio de manera que se responda con códigos de la serie 4xx en lugar de 5xx."
                    ),
                )
            )

        return findings
