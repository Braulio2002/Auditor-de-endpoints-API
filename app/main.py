import sys

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

# Use case & CLI
from app.application.use_cases.audit_api_endpoints_use_case import AuditApiEndpointsUseCase

# Config
from app.config.settings import Settings

# Exporters
from app.infrastructure.exporters.excel_report_exporter import ExcelReportExporter
from app.infrastructure.exporters.json_report_exporter import JsonReportExporter

# Filesystem
from app.infrastructure.filesystem.directory_manager import DirectoryManager

# HTTP client
from app.infrastructure.http.safe_http_client import SafeHttpClient
from app.infrastructure.readers.csv_endpoint_reader import CsvEndpointReader

# Readers
from app.infrastructure.readers.excel_endpoint_reader import ExcelEndpointReader
from app.infrastructure.readers.txt_endpoint_reader import TxtEndpointReader
from app.presentation.cli import ConsoleCLI

# Utilities
from app.shared.filename_utils import get_unique_filename
from app.shared.logger import logger


def main() -> None:
    try:
        # Load application configurations
        settings = Settings()

        # 1. Ensure input and output folders exist, seed sample endpoints.xlsx if missing
        dir_manager = DirectoryManager(
            entrada_dir=settings.DATOS_ENTRADA_DIR, salida_dir=settings.DATOS_SALIDA_DIR
        )
        dir_manager.ensure_directories(settings.INPUT_EXCEL_NAME)

        # 2. Dynamic reader resolution based on available input files
        excel_file = settings.DATOS_ENTRADA_DIR / settings.INPUT_EXCEL_NAME
        csv_file = settings.DATOS_ENTRADA_DIR / "endpoints.csv"
        txt_file = settings.DATOS_ENTRADA_DIR / "endpoints.txt"

        # Default fallback is Excel
        input_file = excel_file
        reader = ExcelEndpointReader()

        # Dynamic reader resolution based on available input files
        if not excel_file.exists():
            if csv_file.exists():
                input_file = csv_file
                reader = CsvEndpointReader()
            elif txt_file.exists():
                input_file = txt_file
                reader = TxtEndpointReader()

        # 3. Initialize secure HTTP client
        http_client = SafeHttpClient(
            user_agent=settings.USER_AGENT, rate_limit_delay=settings.RATE_LIMIT_DELAY
        )

        # 4. Initialize report exporters
        excel_exporter = ExcelReportExporter()
        json_exporter = JsonReportExporter()

        # 5. Initialize security analyzers and scorers
        validator_service = EndpointValidatorService()
        auth_analyzer = AuthExposureAnalyzerService()
        method_analyzer = HttpMethodAnalyzerService()
        sensitive_detector = SensitiveDataDetectorService()
        verbose_detector = VerboseErrorDetectorService()
        header_analyzer = SecurityHeaderAnalyzerService()
        status_analyzer = StatusCodeAnalyzerService()

        # Configure risk weights from settings
        score_calculator = ScoreCalculatorService(weights=settings.SCORING_WEIGHTS)
        recommendation_service = RecommendationService()

        # 6. Build the dependency orchestration container
        use_case = AuditApiEndpointsUseCase(
            reader=reader,
            http_client=http_client,
            excel_exporter=excel_exporter,
            json_exporter=json_exporter,
            validator_service=validator_service,
            auth_analyzer=auth_analyzer,
            method_analyzer=method_analyzer,
            sensitive_detector=sensitive_detector,
            verbose_detector=verbose_detector,
            header_analyzer=header_analyzer,
            status_analyzer=status_analyzer,
            score_calculator=score_calculator,
            recommendation_service=recommendation_service,
        )

        # 7. Generate non-overlapping unique filenames for output reports
        output_excel = get_unique_filename(
            directory=settings.DATOS_SALIDA_DIR,
            base_name=settings.OUTPUT_EXCEL_NAME,
            extension=".xlsx",
        )

        output_json = get_unique_filename(
            directory=settings.DATOS_SALIDA_DIR,
            base_name=settings.OUTPUT_JSON_NAME,
            extension=".json",
        )

        # 8. Start Presentation Console CLI
        cli = ConsoleCLI(use_case)
        cli.run(
            input_file=input_file,
            output_excel=output_excel,
            output_json=output_json,
            auth_headers=settings.AUTH_HEADERS,
            safe_mode=settings.SAFE_MODE,
            timeout=settings.TIMEOUT_SECONDS,
        )

    except Exception as e:
        logger.critical(f"Excepción fatal no controlada durante el arranque: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
