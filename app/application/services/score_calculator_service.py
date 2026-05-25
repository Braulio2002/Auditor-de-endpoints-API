from app.domain.entities.security_finding import SecurityFinding
from app.domain.value_objects.risk_level import RiskLevel


class ScoreCalculatorService:
    """
    Calculates overall risk score (0 to 100) for audited endpoints based on security findings.
    """

    def __init__(self, weights: dict[str, int] = None):
        # Default weights configuration as requested
        self.weights = weights or {
            "auth_bypass": 35,  # Endpoint privado accesible sin auth
            "sensitive_data": 30,  # Datos sensibles expuestos
            "verbose_error": 25,  # Stack trace o error técnico expuesto
            "trace_enabled": 20,  # TRACE habilitado
            "unsafe_verbs": 15,  # Métodos peligrosos expuestos innecesariamente
            "missing_headers": 10,  # Headers de seguridad faltantes
            "inconsistent_code": 10,  # Código HTTP inconsistente
            "expose_tech": 5,  # X-Powered-By o Server detallado
        }

    def calculate(self, findings: list[SecurityFinding]) -> tuple[int, RiskLevel]:
        """
        Calculates the risk score (max 100) and maps it to a RiskLevel.
        """
        score = sum(self._get_finding_score(f) for f in findings)
        score = min(score, 100)
        level = self._map_risk_level(score)
        return score, level

    def _get_finding_score(self, finding: SecurityFinding) -> int:
        title = finding.titulo.lower()

        if "acceso no autenticado" in title or "acceso no autorizado" in title:
            return self.weights.get("auth_bypass", 35)
        if "datos sensibles" in title or "credencial expuesta" in title:
            return self.weights.get("sensitive_data", 30)
        if "detalles técnicos" in title or "stack trace" in title or "error técnico" in title:
            return self.weights.get("verbose_error", 25)
        if "trace" in title:
            return self.weights.get("trace_enabled", 20)
        if "modificadores expuestos" in title or "verbos de escritura" in title:
            return self.weights.get("unsafe_verbs", 15)
        if (
            "cabeceras de seguridad ausentes" in title
            or "cache-control inseguro" in title
            or "content-type inadecuado" in title
        ):
            return self.weights.get("missing_headers", 10)
        if "código de estado inconsistente" in title or "error de servidor" in title:
            return self.weights.get("inconsistent_code", 10)
        if "exponen información de tecnologías" in title:
            return self.weights.get("expose_tech", 5)

        # General fallback based on severity if no string match is found
        return self._get_severity_score(finding.severidad)

    def _get_severity_score(self, severidad) -> int:
        from app.domain.value_objects.finding_severity import FindingSeverity

        if severidad == FindingSeverity.CRITICAL:
            return 35
        if severidad == FindingSeverity.HIGH:
            return 25
        if severidad == FindingSeverity.MEDIUM:
            return 15
        if severidad == FindingSeverity.LOW:
            return 5
        return 0

    def _map_risk_level(self, score: int) -> RiskLevel:
        if score <= 20:
            return RiskLevel.LOW
        if score <= 50:
            return RiskLevel.MEDIUM
        if score <= 75:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL
