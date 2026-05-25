from app.application.services.score_calculator_service import ScoreCalculatorService
from app.domain.entities.security_finding import SecurityFinding
from app.domain.value_objects.finding_category import FindingCategory
from app.domain.value_objects.finding_severity import FindingSeverity
from app.domain.value_objects.risk_level import RiskLevel


def test_score_accumulation_and_cap():
    calculator = ScoreCalculatorService()

    # 1. Test low risk finding
    findings_low = [
        SecurityFinding(
            categoria=FindingCategory.SECURITY_HEADERS,
            severidad=FindingSeverity.LOW,
            titulo="Cabeceras de seguridad ausentes en la respuesta",
            descripcion="Missing security headers",
            evidencia_segura="Faltan cabeceras",
            recomendacion="Add headers",
        )
    ]

    score, level = calculator.calculate(findings_low)
    assert score == 10
    assert level == RiskLevel.LOW

    # 2. Test high risk finding (auth bypass + sensitive data)
    findings_high = [
        SecurityFinding(
            categoria=FindingCategory.AUTHENTICATION,
            severidad=FindingSeverity.CRITICAL,
            titulo="Acceso no autenticado a endpoint privado",
            descripcion="Bypass",
            evidencia_segura="Status: 200",
            recomendacion="Fix auth",
        ),
        SecurityFinding(
            categoria=FindingCategory.SENSITIVE_DATA,
            severidad=FindingSeverity.HIGH,
            titulo="Datos sensibles expuestos en la respuesta",
            descripcion="Leaked password",
            evidencia_segura="Fields: password",
            recomendacion="Filter body",
        ),
    ]

    score, level = calculator.calculate(findings_high)
    assert score == 35 + 30  # 65
    assert level == RiskLevel.HIGH

    # 3. Test capped at 100
    findings_critical = findings_high + [
        SecurityFinding(
            categoria=FindingCategory.VERBOSE_ERRORS,
            severidad=FindingSeverity.HIGH,
            titulo="Exposición de detalles técnicos o mensajes de error detallados",
            descripcion="Stacktrace",
            evidencia_segura="Firma: Stacktrace",
            recomendacion="Disable debug",
        ),
        SecurityFinding(
            categoria=FindingCategory.HTTP_METHODS,
            severidad=FindingSeverity.HIGH,
            titulo="Método HTTP TRACE habilitado",
            descripcion="Trace",
            evidencia_segura="Trace",
            recomendacion="Disable TRACE",
        ),
    ]

    score, level = calculator.calculate(findings_critical)
    assert score == 100
    assert level == RiskLevel.CRITICAL
