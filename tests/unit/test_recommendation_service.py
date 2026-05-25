from app.application.services.recommendation_service import RecommendationService
from app.domain.entities.security_finding import SecurityFinding
from app.domain.value_objects.finding_category import FindingCategory
from app.domain.value_objects.finding_severity import FindingSeverity


def test_generates_unique_prioritized_recommendations():
    service = RecommendationService()

    findings = [
        SecurityFinding(
            categoria=FindingCategory.SECURITY_HEADERS,
            severidad=FindingSeverity.LOW,
            titulo="Cabeceras de seguridad ausentes en la respuesta",
            descripcion="Missing security headers",
            evidencia_segura="Faltan cabeceras",
            recomendacion="Recomendación cabeceras",
        ),
        SecurityFinding(
            categoria=FindingCategory.AUTHENTICATION,
            severidad=FindingSeverity.CRITICAL,
            titulo="Acceso no autenticado a endpoint privado",
            descripcion="Bypass",
            evidencia_segura="Status: 200",
            recomendacion="Recomendación autenticación",
        ),
        # Duplicate recommendation
        SecurityFinding(
            categoria=FindingCategory.STATUS_CODES,
            severidad=FindingSeverity.HIGH,
            titulo="Código de estado inconsistente",
            descripcion="Inconsistent code",
            evidencia_segura="Status: 200",
            recomendacion="Recomendación autenticación",
        ),
    ]

    recs = service.generate_recommendations(findings)

    # 1. Check uniqueness (should have only 2 elements, not 3)
    assert len(recs) == 2

    # 2. Check prioritization: CRITICAL should be first, then LOW
    assert recs[0] == "Recomendación autenticación"
    assert recs[1] == "Recomendación cabeceras"
