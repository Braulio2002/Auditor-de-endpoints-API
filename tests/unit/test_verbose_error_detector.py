from app.application.services.verbose_error_detector_service import VerboseErrorDetectorService
from app.domain.entities.api_endpoint import ApiEndpoint
from app.domain.entities.http_response_info import HttpResponseInfo
from app.domain.value_objects.finding_category import FindingCategory
from app.domain.value_objects.finding_severity import FindingSeverity


def test_detects_verbose_sql_errors():
    service = VerboseErrorDetectorService()
    ep = ApiEndpoint(
        nombre="Query",
        url="https://api.example.com/query",
        metodo="GET",
        requiere_auth="no",
        tipo_endpoint="publico",
        descripcion="",
    )

    response = HttpResponseInfo(
        url="https://api.example.com/query",
        metodo="GET",
        status_code=500,
        body_sample="Exception in thread main: org.postgresql.util.PSQLException: FATAL: SQL syntax error near SELECT * FROM node_modules",
    )

    findings = service.analyze(ep, response)

    # We expect one verbose error finding
    # and since it contains "SQL syntax" and "node_modules", it should be HIGH severity.
    assert len(findings) >= 1
    # Check that finding category is VERBOSE_ERRORS
    verbose_findings = [f for f in findings if f.categoria == FindingCategory.VERBOSE_ERRORS]
    assert len(verbose_findings) == 1
    assert verbose_findings[0].severidad == FindingSeverity.HIGH
    assert "db_error" in verbose_findings[0].evidencia_segura.lower()
