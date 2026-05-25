from dataclasses import dataclass, field

from app.domain.entities.api_endpoint import ApiEndpoint
from app.domain.entities.security_finding import SecurityFinding
from app.domain.value_objects.risk_level import RiskLevel


@dataclass
class EndpointAuditReport:
    endpoint: ApiEndpoint
    status_code: int | None = None
    findings: list[SecurityFinding] = field(default_factory=list)
    score_riesgo: int = 0
    nivel_riesgo: RiskLevel = RiskLevel.LOW
    recomendaciones: list[str] = field(default_factory=list)
    fecha_analisis: str = ""
    error: str | None = None
