def mask_sensitive_data(val: str, data_type: str = "generic") -> str:
    """
    Masks sensitive values (tokens, credentials, personal data) to keep evidence safe in reports.
    Does not print or store complete sensitive values.
    """
    if not val:
        return ""

    val = str(val).strip()

    if data_type == "email":
        return _mask_email(val)
    if data_type == "phone":
        return _mask_phone(val)
    if data_type == "credit_card":
        return _mask_credit_card(val)
    if data_type in ("token", "secret", "password", "api_key", "bearer"):
        return _mask_secret(val)

    # Default generic masking
    return _mask_generic(val)


def _mask_email(val: str) -> str:
    if "@" not in val:
        return "***@***.***"
    parts = val.split("@")
    username = parts[0]
    domain = parts[1]
    if len(username) <= 2:
        masked_user = username[0] + "*" * len(username)
    else:
        masked_user = username[0] + "*" * (len(username) - 2) + username[-1]
    return f"{masked_user}@{domain}"


def _mask_phone(val: str) -> str:
    clean_val = "".join(c for c in val if c.isdigit() or c == "+")
    if len(clean_val) > 4:
        return clean_val[:3] + "*" * (len(clean_val) - 5) + clean_val[-2:]
    return "****"


def _mask_credit_card(val: str) -> str:
    clean_val = "".join(c for c in val if c.isdigit())
    if len(clean_val) >= 12:
        return "*" * (len(clean_val) - 4) + clean_val[-4:]
    return "************"


def _mask_secret(val: str) -> str:
    if len(val) <= 6:
        return "*" * len(val)
    return val[:3] + "..." + val[-3:]


def _mask_generic(val: str) -> str:
    if len(val) <= 4:
        return "*" * len(val)
    return val[:2] + "*" * (len(val) - 4) + val[-2:]
