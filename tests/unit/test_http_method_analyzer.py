from app.application.services.http_method_analyzer_service import HttpMethodAnalyzerService
from app.domain.entities.api_endpoint import ApiEndpoint
from app.domain.entities.http_response_info import HttpResponseInfo
from app.domain.value_objects.finding_severity import FindingSeverity


def test_detects_trace_enabled():
    service = HttpMethodAnalyzerService()
    ep = ApiEndpoint(
        nombre="Home",
        url="https://api.example.com",
        metodo="GET",
        requiere_auth="no",
        tipo_endpoint="publico",
        descripcion="",
    )

    response = HttpResponseInfo(url="https://api.example.com", metodo="GET", status_code=200)

    findings = service.analyze(ep, response, options_response=["GET", "POST", "TRACE"])

    trace_findings = [f for f in findings if "TRACE" in f.titulo]
    assert len(trace_findings) == 1
    assert trace_findings[0].severidad == FindingSeverity.HIGH


def test_detects_unwanted_verbs():
    service = HttpMethodAnalyzerService()
    ep = ApiEndpoint(
        nombre="Home",
        url="https://api.example.com",
        metodo="GET",
        requiere_auth="no",
        tipo_endpoint="publico",
        descripcion="",
    )

    response = HttpResponseInfo(url="https://api.example.com", metodo="GET", status_code=200)

    findings = service.analyze(ep, response, options_response=["GET", "PUT", "DELETE"])

    unwanted_findings = [f for f in findings if "modificadores" in f.titulo]
    assert len(unwanted_findings) == 1
    assert unwanted_findings[0].severidad == FindingSeverity.MEDIUM
    assert "PUT" in unwanted_findings[0].evidencia_segura
    assert "DELETE" in unwanted_findings[0].evidencia_segura
