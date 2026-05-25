from app.domain.entities.api_endpoint import ApiEndpoint
from app.domain.entities.http_response_info import HttpResponseInfo
from app.domain.entities.security_finding import SecurityFinding
from app.domain.value_objects.finding_category import FindingCategory
from app.domain.value_objects.finding_severity import FindingSeverity
from app.shared.constants import VERBOSE_ERROR_PATTERNS
from app.shared.masking_utils import mask_sensitive_data


class VerboseErrorDetectorService:
    """
    Scans the response for verbose system exceptions, stack traces, paths,
    database errors, or specific technologies.
    """

    def analyze(self, endpoint: ApiEndpoint, response: HttpResponseInfo) -> list[SecurityFinding]:
        findings = []

        if response.error or not response.body_sample:
            return findings

        body = response.body_sample.strip()

        detected_errors = []
        for pattern_name, pattern_regex in VERBOSE_ERROR_PATTERNS.items():
            match = pattern_regex.search(body)
            if match:
                matched_str = match.group(0)
                # Mask the matched string to avoid exposing system details in report
                masked_match = mask_sensitive_data(matched_str, "generic")
                detected_errors.append((pattern_name, masked_match))

        if detected_errors:
            evidence = ", ".join(f"{name}: '{val}'" for name, val in detected_errors)

            # Severity could be HIGH for stack traces or DB errors, and MEDIUM for technology disclosure
            has_critical_error = any(
                name in ("stack_trace", "db_error", "file_path") for name, _ in detected_errors
            )
            severity = FindingSeverity.HIGH if has_critical_error else FindingSeverity.MEDIUM

            findings.append(
                SecurityFinding(
                    categoria=FindingCategory.VERBOSE_ERRORS,
                    severidad=severity,
                    titulo="Exposición de detalles técnicos o mensajes de error detallados",
                    descripcion=(
                        f"La respuesta contiene firmas de error o metadatos de desarrollo: {evidence}. "
                        "Esto revela la tecnología subyacente, librerías, ORM o rutas locales del servidor."
                    ),
                    evidencia_segura=f"Firmas detectadas: {evidence}",
                    recomendacion=(
                        "Desactivar el modo depuración (DEBUG = False) en producción. Configurar un "
                        "manejador de excepciones global que capture errores inesperados y devuelva "
                        "mensajes genéricos del tipo 'Internal Server Error' sin exponer detalles internos, "
                        "registrando los stack traces únicamente en logs del servidor protegidos."
                    ),
                )
            )

        # 3. Check for direct 500 status codes without error strings in body (which might still be verbose or misconfigured)
        if response.status_code == 500 and not detected_errors:
            findings.append(
                SecurityFinding(
                    categoria=FindingCategory.STATUS_CODES,
                    severidad=FindingSeverity.MEDIUM,
                    titulo="Error interno del servidor (500)",
                    descripcion=(
                        "El endpoint devolvió un error interno 500. Aunque no se detectaron "
                        "firmas de stack trace directas, los errores 500 indican excepciones no controladas."
                    ),
                    evidencia_segura="HTTP Status 500",
                    recomendacion=(
                        "Asegurar que todas las excepciones estén correctamente controladas en el código "
                        "y devuelvan códigos de respuesta coherentes (como 400 o 422 para errores de cliente) "
                        "en lugar de fallar catastróficamente con un error 500."
                    ),
                )
            )

        return findings
