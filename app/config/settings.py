from pathlib import Path


class Settings:
    """
    Configuration settings for the API Endpoint Auditor.
    """

    # Directory Paths (Relative to workspace root or absolute)
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATOS_ENTRADA_DIR: Path = BASE_DIR / "datos_entrada"
    DATOS_SALIDA_DIR: Path = BASE_DIR / "datos_salida"

    # Default file names
    INPUT_EXCEL_NAME: str = "endpoints.xlsx"
    # suffix will be added if exists
    OUTPUT_EXCEL_NAME: str = "api_endpoint_audit_report"
    OUTPUT_JSON_NAME: str = "api_endpoint_audit_report"

    # Scanning Parameters
    TIMEOUT_SECONDS: float = 8.0
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) APIEndpointAuditor/1.0.0 (Defensive Security Audit)"

    # Safe check options
    SAFE_MODE: bool = True  # If True, avoids making harmful POST/PUT/DELETE payload requests
    # Pause between requests in seconds to avoid saturating server
    RATE_LIMIT_DELAY: float = 0.5

    # Optional credentials for authenticated tests (set by user)
    # E.g. Bearer token, api key, cookie session, custom headers
    # NEVER printed in logs/reports, masked before usage
    # Example: {"Authorization": "Bearer token_here"}
    AUTH_HEADERS: dict[str, str] | None = None

    # Scoring Weights for Risk Level evaluation
    SCORING_WEIGHTS: dict[str, int] = {
        "auth_bypass": 35,  # Private endpoint accessible without credentials
        "sensitive_data": 30,  # Sensitive details leaked in response payload
        "verbose_error": 25,  # Stack traces or technical errors exposed
        "trace_enabled": 20,  # HTTP TRACE method enabled
        "unsafe_verbs": 15,  # Unexpected PUT/PATCH/DELETE verbs allowed
        "missing_headers": 10,  # Missing CSP, nosniff, HSTS or cache headers
        # Inconsistent HTTP status codes (200 on private, etc)
        "inconsistent_code": 10,
        # Technology exposure headers (X-Powered-By, detailed Server)
        "expose_tech": 5,
    }
