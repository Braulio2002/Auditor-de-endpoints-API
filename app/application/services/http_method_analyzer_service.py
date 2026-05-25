from app.domain.entities.api_endpoint import ApiEndpoint
from app.domain.entities.http_response_info import HttpResponseInfo
from app.domain.entities.security_finding import SecurityFinding
from app.domain.value_objects.finding_category import FindingCategory
from app.domain.value_objects.finding_severity import FindingSeverity


class HttpMethodAnalyzerService:
    """
    Analyzes allowed and exposed HTTP verbs on the endpoint.
    Detects unsafe methods like TRACE, PUT, PATCH, DELETE, or loose OPTIONS.
    """

    def analyze(
        self,
        endpoint: ApiEndpoint,
        response: HttpResponseInfo,
        # HTTP methods detected via OPTIONS request or Allow header
        options_response: list[str],
    ) -> list[SecurityFinding]:
        findings = []

        # 1. Analyze if TRACE is enabled
        has_trace = any(m.upper() == "TRACE" for m in options_response)

        # Also check if response method was TRACE and was successful (which indicates it's allowed)
        if response.metodo == "TRACE" and response.status_code == 200:
            has_trace = True

        if has_trace:
            findings.append(
                SecurityFinding(
                    categoria=FindingCategory.HTTP_METHODS,
                    severidad=FindingSeverity.HIGH,
                    titulo="Método HTTP TRACE habilitado",
                    descripcion=(
                        f"El método TRACE está activo en {endpoint.url}. "
                        "TRACE permite eco del request completo, lo cual puede ser utilizado "
                        "en ataques de Cross-Site Tracking (XST) para robar cookies de sesión HTTPOnly."
                    ),
                    evidencia_segura="Metodo TRACE expuesto en headers/OPTIONS",
                    recomendacion=(
                        "Deshabilitar el soporte para el método TRACE en la configuración "
                        "del servidor web o del API Gateway."
                    ),
                )
            )

        # 2. Check if dangerous/modifying verbs are exposed when not declared in the Excel
        declared_method = endpoint.metodo.upper()
        allowed_methods = [m.upper() for m in options_response]

        unwanted_verbs = []
        for verb in ["PUT", "PATCH", "DELETE"]:
            if verb in allowed_methods and verb != declared_method:
                unwanted_verbs.append(verb)

        if unwanted_verbs:
            findings.append(
                SecurityFinding(
                    categoria=FindingCategory.HTTP_METHODS,
                    severidad=FindingSeverity.MEDIUM,
                    titulo="Métodos HTTP modificadores expuestos innecesariamente",
                    descripcion=(
                        f"El endpoint declaró únicamente el método '{declared_method}', "
                        f"pero la auditoría detectó que permite los métodos modificadores: "
                        f"{', '.join(unwanted_verbs)}. Esto incrementa la superficie de ataque."
                    ),
                    evidencia_segura=f"Declarado: {declared_method}. Detectados adicionales: {', '.join(unwanted_verbs)}",
                    recomendacion=(
                        "Aplicar el principio de mínimo privilegio. Restringir y desactivar todos los "
                        "verbos HTTP modificadores que no formen parte del diseño funcional de este endpoint."
                    ),
                )
            )

        # 3. Check if OPTIONS is excessively permissive (Allowing everything wildcard, or allowing unsafe verbs in a public endpoint)
        if endpoint.tipo_endpoint == "publico" and (
            "PUT" in allowed_methods or "DELETE" in allowed_methods
        ):
            findings.append(
                SecurityFinding(
                    categoria=FindingCategory.HTTP_METHODS,
                    severidad=FindingSeverity.LOW,
                    titulo="Endpoint público con verbos de escritura expuestos",
                    descripcion=(
                        "El endpoint es público, pero permite métodos de escritura como PUT/DELETE. "
                        "Esto expone a riesgos de modificación o borrado no autorizado."
                    ),
                    evidencia_segura=f"Métodos: {', '.join(allowed_methods)}",
                    recomendacion=(
                        "Asegurar que los métodos de escritura en endpoints públicos estén fuertemente "
                        "autenticados o deshabilitados si no son requeridos."
                    ),
                )
            )

        return findings
