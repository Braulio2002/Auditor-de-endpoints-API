from app.application.services.endpoint_validator_service import EndpointValidatorService
from app.domain.entities.api_endpoint import ApiEndpoint


def test_validate_and_normalize_valid_endpoint():
    service = EndpointValidatorService()
    ep = ApiEndpoint(
        nombre=" Test ",
        url="https://api.example.com/users",
        metodo=" get ",
        requiere_auth=" si ",
        tipo_endpoint=" privado ",
        descripcion="Description here",
    )

    is_valid, reason, normalized = service.validate_and_normalize(ep)

    assert is_valid is True
    assert reason is None
    assert normalized.nombre == "Test"
    assert normalized.url == "https://api.example.com/users"
    assert normalized.metodo == "GET"
    assert normalized.requiere_auth == "si"
    assert normalized.tipo_endpoint == "privado"


def test_validate_and_normalize_invalid_url():
    service = EndpointValidatorService()
    ep = ApiEndpoint(
        nombre="Test",
        url="ftp://invalid-scheme.com",
        metodo="GET",
        requiere_auth="no",
        tipo_endpoint="publico",
        descripcion="",
    )

    is_valid, reason, _ = service.validate_and_normalize(ep)

    assert is_valid is False
    assert "Esquema URL inválido" in reason


def test_validate_and_normalize_empty_url():
    service = EndpointValidatorService()
    ep = ApiEndpoint(
        nombre="Test",
        url="",
        metodo="GET",
        requiere_auth="no",
        tipo_endpoint="publico",
        descripcion="",
    )

    is_valid, reason, _ = service.validate_and_normalize(ep)

    assert is_valid is False
    assert "vacía" in reason.lower()


def test_validate_and_normalize_defaults():
    service = EndpointValidatorService()
    ep = ApiEndpoint(
        nombre="",
        url="http://localhost:8000/api",
        metodo="",
        requiere_auth="",
        tipo_endpoint="",
        descripcion="",
    )

    is_valid, reason, normalized = service.validate_and_normalize(ep)

    assert is_valid is True
    assert normalized.nombre == "Endpoint sin nombre"
    assert normalized.metodo == "GET"
    assert normalized.requiere_auth == "desconocido"
    assert normalized.tipo_endpoint == "no clasificado"
