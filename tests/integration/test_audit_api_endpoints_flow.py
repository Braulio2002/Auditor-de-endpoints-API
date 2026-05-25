import pandas as pd

from app.application.interfaces.http_client_interface import HttpClientInterface
from app.application.services.auth_exposure_analyzer_service import AuthExposureAnalyzerService

# Services
from app.application.services.endpoint_validator_service import EndpointValidatorService
from app.application.services.http_method_analyzer_service import HttpMethodAnalyzerService
from app.application.services.recommendation_service import RecommendationService
from app.application.services.score_calculator_service import ScoreCalculatorService
from app.application.services.security_header_analyzer_service import SecurityHeaderAnalyzerService
from app.application.services.sensitive_data_detector_service import SensitiveDataDetectorService
from app.application.services.status_code_analyzer_service import StatusCodeAnalyzerService
from app.application.services.verbose_error_detector_service import VerboseErrorDetectorService
from app.application.use_cases.audit_api_endpoints_use_case import AuditApiEndpointsUseCase

# Entities & Interfaces
from app.domain.entities.http_response_info import HttpResponseInfo
from app.infrastructure.exporters.excel_report_exporter import ExcelReportExporter
from app.infrastructure.exporters.json_report_exporter import JsonReportExporter

# Readers & Exporters
from app.infrastructure.readers.excel_endpoint_reader import ExcelEndpointReader


class MockHttpClient(HttpClientInterface):
    """
    Mock HTTP client simulating API server responses for integration testing.
    """

    def send_request(
        self,
        url: str,
        method: str,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        safe_mode: bool = True,
    ) -> HttpResponseInfo:
        # Simulate auth bypass on this URL
        if "users" in url:
            return HttpResponseInfo(
                url=url,
                metodo=method,
                status_code=200,
                headers={"Content-Type": "application/json", "X-Powered-By": "Express"},
                body_sample='[{"id": 1, "username": "braulio", "password": "cleartextpassword"}]',
                content_type="application/json",
                response_time_ms=120.0,
            )
        # Simulate detailed errors
        elif "error" in url or "status/500" in url:
            return HttpResponseInfo(
                url=url,
                metodo=method,
                status_code=500,
                headers={"Content-Type": "text/html"},
                body_sample="Traceback (most recent call last):\n  File 'app.py', line 12, in index\n    db.connect()",
                content_type="text/html",
                response_time_ms=50.0,
            )
        # General response
        return HttpResponseInfo(
            url=url,
            metodo=method,
            status_code=200,
            headers={"Content-Type": "application/json", "X-Content-Type-Options": "nosniff"},
            body_sample='{"status": "ok"}',
            content_type="application/json",
            response_time_ms=80.0,
        )

    def get_allowed_methods(
        self, url: str, headers: dict[str, str] | None = None, timeout: float = 10.0
    ) -> list[str]:
        if "users" in url:
            return ["GET", "OPTIONS", "TRACE"]
        return ["GET", "POST", "OPTIONS"]


def test_integration_audit_flow(tmp_path):
    """
    Integration test validating the full flow from reading Excel,
    auditing with mock, and checking exported reports.
    """
    # 1. Setup temporary folders
    entrada_dir = tmp_path / "datos_entrada"
    salida_dir = tmp_path / "datos_salida"
    entrada_dir.mkdir()
    salida_dir.mkdir()

    excel_file = entrada_dir / "endpoints.xlsx"
    output_excel = salida_dir / "report.xlsx"
    output_json = salida_dir / "report.json"

    # 2. Seed mock Excel file using pandas
    sample_data = [
        {
            "nombre": "Listar usuarios",
            "url": "https://api.empresa.com/users",
            "metodo": "GET",
            "requiere_auth": "si",
            "tipo_endpoint": "privado",
            "descripcion": "Lista usuarios internos",
        },
        {
            "nombre": "Prueba de error",
            "url": "https://api.empresa.com/error",
            "metodo": "GET",
            "requiere_auth": "no",
            "tipo_endpoint": "publico",
            "descripcion": "Simula un error",
        },
    ]
    pd.DataFrame(sample_data).to_excel(excel_file, index=False)

    # 3. Instantiate Dependency Injection components
    reader = ExcelEndpointReader()
    http_client = MockHttpClient()
    excel_exporter = ExcelReportExporter()
    json_exporter = JsonReportExporter()

    validator = EndpointValidatorService()
    auth_analyzer = AuthExposureAnalyzerService()
    method_analyzer = HttpMethodAnalyzerService()
    sensitive_detector = SensitiveDataDetectorService()
    verbose_detector = VerboseErrorDetectorService()
    header_analyzer = SecurityHeaderAnalyzerService()
    status_analyzer = StatusCodeAnalyzerService()

    score_calculator = ScoreCalculatorService()
    recommendation_service = RecommendationService()

    # Orchestrator Use Case
    use_case = AuditApiEndpointsUseCase(
        reader=reader,
        http_client=http_client,
        excel_exporter=excel_exporter,
        json_exporter=json_exporter,
        validator_service=validator,
        auth_analyzer=auth_analyzer,
        method_analyzer=method_analyzer,
        sensitive_detector=sensitive_detector,
        verbose_detector=verbose_detector,
        header_analyzer=header_analyzer,
        status_analyzer=status_analyzer,
        score_calculator=score_calculator,
        recommendation_service=recommendation_service,
    )

    # 4. Run the Use Case
    reports = use_case.execute(
        input_file_path=excel_file,
        output_excel_path=output_excel,
        output_json_path=output_json,
        auth_headers=None,
        safe_mode=True,
        timeout=5.0,
    )

    # 5. Assertions
    assert len(reports) == 2

    # Assert output files exist
    assert output_excel.exists()
    assert output_json.exists()

    # Load outputs to verify correctness
    df_res = pd.read_excel(output_excel, sheet_name="Resumen")
    assert len(df_res) == 2
    assert "score_riesgo" in df_res.columns

    # Assert findings were detected and classified
    df_findings = pd.read_excel(output_excel, sheet_name="Hallazgos")
    assert len(df_findings) > 0
