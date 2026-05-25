from app.application.services.sensitive_data_detector_service import SensitiveDataDetectorService
from app.domain.entities.http_response_info import HttpResponseInfo
from app.domain.value_objects.finding_category import FindingCategory


def test_detects_sensitive_data_in_json():
    service = SensitiveDataDetectorService()

    # Body containing sensitive key-values
    response = HttpResponseInfo(
        url="https://api.example.com/profile",
        metodo="GET",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_sample='{"user": "braulio", "password": "supersecretpassword123", "email": "braulio@empresa.com"}',
    )

    findings = service.analyze(response)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.categoria == FindingCategory.SENSITIVE_DATA
    # Ensure evidence is masked and does not leak the clear password or email
    assert "supersecretpassword123" not in finding.evidencia_segura
    assert "braulio@empresa.com" not in finding.evidencia_segura
    assert (
        "b***o@empresa.com" in finding.evidencia_segura
        or "b***o@e***a.com" in finding.evidencia_segura
        or "password" in finding.evidencia_segura
    )


def test_detects_sensitive_headers():
    service = SensitiveDataDetectorService()

    response = HttpResponseInfo(
        url="https://api.example.com/profile",
        metodo="GET",
        status_code=200,
        headers={"Content-Type": "application/json", "Authorization": "Bearer yoursecrettokenhere"},
        body_sample='{"status": "ok"}',
    )

    findings = service.analyze(response)

    # One sensitive header finding
    assert len(findings) == 1
    assert "Bearer yoursecrettokenhere" not in findings[0].evidencia_segura
    assert "header de respuesta" in findings[0].titulo
