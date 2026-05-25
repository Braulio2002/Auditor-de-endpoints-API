import datetime
from pathlib import Path

# Domain & interfaces
from app.application.interfaces.endpoint_reader_interface import EndpointReaderInterface
from app.application.interfaces.http_client_interface import HttpClientInterface
from app.application.interfaces.report_exporter_interface import ReportExporterInterface
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
from app.domain.entities.api_endpoint import ApiEndpoint
from app.domain.entities.endpoint_audit_report import EndpointAuditReport
from app.domain.entities.security_finding import SecurityFinding
from app.domain.exceptions.domain_exceptions import DomainException
from app.shared.logger import logger


class AuditApiEndpointsUseCase:
    """
    Main orchestrator for scanning, analyzing, scoring, and reporting security audits on API endpoints.
    """

    def __init__(
        self,
        reader: EndpointReaderInterface,
        http_client: HttpClientInterface,
        excel_exporter: ReportExporterInterface,
        json_exporter: ReportExporterInterface,
        validator_service: EndpointValidatorService,
        auth_analyzer: AuthExposureAnalyzerService,
        method_analyzer: HttpMethodAnalyzerService,
        sensitive_detector: SensitiveDataDetectorService,
        verbose_detector: VerboseErrorDetectorService,
        header_analyzer: SecurityHeaderAnalyzerService,
        status_analyzer: StatusCodeAnalyzerService,
        score_calculator: ScoreCalculatorService,
        recommendation_service: RecommendationService,
    ):
        self.reader = reader
        self.http_client = http_client
        self.excel_exporter = excel_exporter
        self.json_exporter = json_exporter

        self.validator_service = validator_service
        self.auth_analyzer = auth_analyzer
        self.method_analyzer = method_analyzer
        self.sensitive_detector = sensitive_detector
        self.verbose_detector = verbose_detector
        self.header_analyzer = header_analyzer
        self.status_analyzer = status_analyzer
        self.score_calculator = score_calculator
        self.rec_service = recommendation_service

    def execute(
        self,
        input_file_path: Path,
        output_excel_path: Path,
        output_json_path: Path,
        auth_headers: dict[str, str] | None = None,
        safe_mode: bool = True,
        timeout: float = 8.0,
    ) -> list[EndpointAuditReport]:

        # 1. Read endpoints
        logger.info(f"Leyendo endpoints desde {input_file_path.name}...")
        raw_endpoints = self.reader.read_endpoints(input_file_path)
        logger.info(f"Endpoints encontrados: {len(raw_endpoints)}")

        if not raw_endpoints:
            logger.info("No se encontraron endpoints para auditar.")
            return []

        # 2. Validate and normalize endpoints
        logger.info("Validando endpoints...")
        valid_endpoints: list[ApiEndpoint] = []
        for raw in raw_endpoints:
            is_valid, reason, normalized = self.validator_service.validate_and_normalize(raw)
            if is_valid:
                valid_endpoints.append(normalized)
            else:
                logger.warning(f"Endpoint omitado ({reason}): {raw.url}")

        if not valid_endpoints:
            logger.error("No hay endpoints válidos tras la validación.")
            return []

        reports: list[EndpointAuditReport] = []
        has_credentials = auth_headers is not None and len(auth_headers) > 0

        # 3. Perform audit sequentially to respect rate limits
        for i, ep in enumerate(valid_endpoints):
            fecha = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            logger.info(
                f"Auditando endpoint [{i + 1}/{len(valid_endpoints)}]: {ep.metodo} {ep.url}"
            )

            # Safe auditing check
            try:
                # Discover allowed HTTP methods via OPTIONS method or headers
                # We do this asynchronously/safely without modifying data
                options_verbs = self.http_client.get_allowed_methods(
                    url=ep.url, headers=auth_headers, timeout=timeout
                )

                # Send main probe request (which is GET/OPTIONS in safe mode, or harmless empty request)
                logger.info("Analizando cabeceras, respuestas y vulnerabilidades...")
                response_info = self.http_client.send_request(
                    url=ep.url,
                    method=ep.metodo,
                    headers=auth_headers,
                    timeout=timeout,
                    safe_mode=safe_mode,
                )

                findings: list[SecurityFinding] = []

                if response_info.error:
                    logger.warning(f"Error al conectar con endpoint: {response_info.error}")
                    # Compile reports with failed connection details
                    report = EndpointAuditReport(
                        endpoint=ep,
                        status_code=None,
                        findings=[],
                        score_riesgo=0,
                        nivel_riesgo=self.score_calculator.calculate([])[1],
                        recomendaciones=[],
                        fecha_analisis=fecha,
                        error=response_info.error,
                    )
                    reports.append(report)
                    continue

                # Run Security Analysis Services
                logger.debug("Analizando autenticación...")
                findings.extend(
                    self.auth_analyzer.analyze(
                        endpoint=ep, response=response_info, has_credentials_sent=has_credentials
                    )
                )

                logger.debug("Analizando métodos HTTP...")
                findings.extend(
                    self.method_analyzer.analyze(
                        endpoint=ep, response=response_info, options_response=options_verbs
                    )
                )

                findings.extend(self.sensitive_detector.analyze(response=response_info))

                logger.debug("Analizando errores detallados...")
                findings.extend(self.verbose_detector.analyze(endpoint=ep, response=response_info))

                logger.debug("Analizando headers de seguridad...")
                findings.extend(self.header_analyzer.analyze(endpoint=ep, response=response_info))

                logger.debug("Analizando consistencia de códigos de estado...")
                findings.extend(
                    self.status_analyzer.analyze(
                        endpoint=ep, response=response_info, has_credentials_sent=has_credentials
                    )
                )

                # 4. Calculate Risk Scoring & Levels
                logger.debug("Calculando score de riesgo...")
                score, risk_level = self.score_calculator.calculate(findings)

                # 5. Extract actionable hardening recommendations
                recommendations = self.rec_service.generate_recommendations(findings)

                report = EndpointAuditReport(
                    endpoint=ep,
                    status_code=response_info.status_code,
                    findings=findings,
                    score_riesgo=score,
                    nivel_riesgo=risk_level,
                    recomendaciones=recommendations,
                    fecha_analisis=fecha,
                    error=None,
                )
                reports.append(report)

            except Exception as e:
                logger.error(f"Fallo crítico auditando {ep.url}: {e}")
                report = EndpointAuditReport(
                    endpoint=ep,
                    status_code=None,
                    findings=[],
                    score_riesgo=0,
                    nivel_riesgo=self.score_calculator.calculate([])[1],
                    recomendaciones=[],
                    fecha_analisis=fecha,
                    error=str(e),
                )
                reports.append(report)

        # 6. Export audit reports
        if reports:
            try:
                logger.info("Generando reporte Excel...")
                self.excel_exporter.export(reports, output_excel_path)

                logger.info("Generando reporte JSON...")
                self.json_exporter.export(reports, output_json_path)

                logger.info("Reportes generados correctamente en datos_salida/")
            except Exception as ex:
                logger.error(f"Error al guardar reportes: {ex}")
                raise DomainException(f"Error de persistencia de reportes: {ex}")

        logger.info("Proceso finalizado")
        return reports
