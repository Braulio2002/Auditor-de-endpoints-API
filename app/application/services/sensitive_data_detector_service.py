import json
from typing import Any

from app.domain.entities.http_response_info import HttpResponseInfo
from app.domain.entities.security_finding import SecurityFinding
from app.domain.value_objects.finding_category import FindingCategory
from app.domain.value_objects.finding_severity import FindingSeverity
from app.shared.constants import SENSITIVE_PATTERNS
from app.shared.masking_utils import mask_sensitive_data


class SensitiveDataDetectorService:
    """
    Detects sensitive information leakage in response headers or body.
    Masks all sensitive values securely.
    """

    def analyze(self, response: HttpResponseInfo) -> list[SecurityFinding]:
        findings = []

        if response.error or not response.body_sample:
            return findings

        body = response.body_sample.strip()

        # 1. Parse JSON if applicable to inspect keys and values recursively
        detected_fields: dict[str, str] = {}

        # We also do a raw regex search in case it is plain text, XML or unparseable JSON
        # Let's inspect JSON specifically if Content-Type is json
        is_json = "application/json" in response.content_type.lower() or body.startswith(("{", "["))

        if is_json:
            try:
                data = json.loads(body)
                self._inspect_json_recursively(data, detected_fields)
            except Exception:
                # Fallback to plain text search if JSON parsing fails
                self._inspect_text(body, detected_fields)
        else:
            self._inspect_text(body, detected_fields)

        # Generate findings for each unique category detected
        if detected_fields:
            # We group them or list them safely
            fields_summary = ", ".join(f"{k} (evidencia: {v})" for k, v in detected_fields.items())

            findings.append(
                SecurityFinding(
                    categoria=FindingCategory.SENSITIVE_DATA,
                    severidad=FindingSeverity.HIGH,
                    titulo="Exposición de datos sensibles en la respuesta",
                    descripcion=(
                        f"Se detectó información sensible o credenciales expuestas en el cuerpo de "
                        f"la respuesta del endpoint: {', '.join(detected_fields.keys())}. "
                        "El API no debe retornar datos personales sin enmascarar ni credenciales/tokens."
                    ),
                    evidencia_segura=f"Campos expuestos: {fields_summary}",
                    recomendacion=(
                        "Aplicar DTOs de salida (Data Transfer Objects) para restringir y filtrar "
                        "los campos devueltos en las respuestas. Enmascarar información personal (PII) "
                        "en el backend y evitar devolver tokens, contraseñas o hashes de claves."
                    ),
                )
            )

        # 2. Inspect headers for sensitive tokens (like Authorization leaking in response headers, which is extremely rare but high risk)
        for h_key, h_val in response.headers.items():
            if h_key.lower() in ("authorization", "x-api-key", "set-cookie"):
                # If set-cookie exposes cookie without HttpOnly or Secure, that is a finding, but we can flag response token leakage
                if h_key.lower() in ("authorization", "x-api-key"):
                    findings.append(
                        SecurityFinding(
                            categoria=FindingCategory.SENSITIVE_DATA,
                            severidad=FindingSeverity.CRITICAL,
                            titulo="Credencial expuesta en header de respuesta",
                            descripcion=(
                                f"El header '{h_key}' se encuentra presente en la respuesta HTTP. "
                                "Los tokens y API Keys de autorización pertenecen únicamente a las peticiones, "
                                "nunca deben ser expuestos en las cabeceras de respuesta del servidor."
                            ),
                            evidencia_segura=f"Header '{h_key}' expuesto: {mask_sensitive_data(h_val, 'token')}",
                            recomendacion=(
                                "Remover cualquier lógica del servidor que refleje credenciales o tokens "
                                "de autorización en los headers de respuesta HTTP."
                            ),
                        )
                    )

        return findings

    def _inspect_json_recursively(
        self, obj: Any, detected: dict[str, str], prefix: str = ""
    ) -> None:
        """
        Recursively walks through a parsed JSON object looking for keys that match sensitive patterns.
        """
        if isinstance(obj, dict):
            self._inspect_dict(obj, detected, prefix)
        elif isinstance(obj, list):
            self._inspect_list(obj, detected, prefix)

    def _inspect_dict(self, obj: dict, detected: dict[str, str], prefix: str) -> None:
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k

            # Check key first
            match_found, masked_val = self._check_key_sensitive(k, v)
            if match_found:
                detected[full_key] = masked_val
            else:
                # Check value next
                match_found_v, masked_val_v = self._check_val_sensitive(v)
                if match_found_v:
                    detected[full_key] = masked_val_v

            # Recurse
            self._inspect_json_recursively(v, detected, prefix=full_key)

    def _inspect_list(self, obj: list, detected: dict[str, str], prefix: str) -> None:
        for i, item in enumerate(obj):
            self._inspect_json_recursively(item, detected, prefix=f"{prefix}[{i}]")

    def _check_key_sensitive(self, key: str, val: Any) -> tuple[bool, str | None]:
        for pattern_name, pattern_regex in SENSITIVE_PATTERNS.items():
            if pattern_regex.search(key):
                masked = mask_sensitive_data(str(val), pattern_name)
                return True, masked
        return False, None

    def _check_val_sensitive(self, val: Any) -> tuple[bool, str | None]:
        if not isinstance(val, str):
            return False, None

        for pattern_name, pattern_regex in SENSITIVE_PATTERNS.items():
            # For value match, check emails or credit cards which have high-fidelity regexes
            if pattern_name in ("email", "credit_card") and pattern_regex.search(val):
                masked = mask_sensitive_data(val, pattern_name)
                return True, masked
        return False, None

    def _inspect_text(self, text: str, detected: dict[str, str]) -> None:
        """
        Fallback scanner for unstructured plain text responses using regex searches.
        """
        for pattern_name, pattern_regex in SENSITIVE_PATTERNS.items():
            matches = pattern_regex.finditer(text)
            for i, match in enumerate(matches):
                matched_str = match.group(0)
                # Keep it safe: report first 2 matches max per pattern to avoid bloating
                if i >= 2:
                    break
                masked_val = mask_sensitive_data(matched_str, pattern_name)
                # Avoid storing complete value, just record the matched segment
                detected[f"texto_coincidencia_{pattern_name}_{i}"] = masked_val
