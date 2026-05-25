import re

# Sensitive keywords/patterns for detection in payloads or text response bodies
SENSITIVE_PATTERNS = {
    "password": re.compile(r"(?i)\b(password|passwd|contraseña|contrasena)\b"),
    "secret": re.compile(r"(?i)\b(secret|secreto|private_key|privatekey)\b"),
    "token": re.compile(r"(?i)\b(token|access_token|refreshtoken|refresh_token)\b"),
    "api_key": re.compile(r"(?i)\b(api_key|apikey|client_secret|clientsecret)\b"),
    "authorization": re.compile(r"(?i)\b(authorization|auth|bearer)\b"),
    "cookie": re.compile(r"(?i)\b(cookie|session_id|sessionid|session)\b"),
    "dni": re.compile(r"(?i)\b(dni|documento_identidad|document|cedula)\b"),
    "credit_card": re.compile(r"(?i)\b(credit_card|creditcard|tarjeta_credito|tarjeta)\b"),
    "cvv": re.compile(r"(?i)\b(cvv|cvv2|security_code)\b"),
    "email": re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"),
    "phone": re.compile(r"(?i)\b(phone|telefono|movil|celular)\b"),
    "address": re.compile(r"(?i)\b(address|direccion)\b"),
    "internal_id": re.compile(r"(?i)\b(internal_id|internalid|uuid|guid)\b"),
    "debug_flag": re.compile(r"(?i)\b(debug|stack|exception)\b"),
}

# Verbose technical errors / stack traces patterns
VERBOSE_ERROR_PATTERNS = {
    "stack_trace": re.compile(r"(?i)(stacktrace|stack trace|traceback|at [a-z0-9_.\/]+:\d+)"),
    "db_error": re.compile(
        r"(?i)(sql syntax|database error|postgresql error|mysql error|sqlite3\.|mongodb error|oracle error|deadlock|foreign key constraint)"
    ),
    "file_path": re.compile(
        r"(?i)([a-z]:\\|[a-z0-9_\-\.]+\/node_modules\/|[a-z0-9_\-\.]+\/vendor\/)"
    ),
    "framework_django": re.compile(
        r"(?i)(django\.core|django\.db|django\.http|django\.middleware)"
    ),
    "framework_laravel": re.compile(
        r"(?i)(laravel|illuminate\\support|illuminate\\routing|symfony\\component\\httpkernel)"
    ),
    "framework_express": re.compile(r"(?i)(express/lib/router|node_modules/express)"),
    "framework_nestjs": re.compile(r"(?i)(@nestjs/core|@nestjs/common|nestjs)"),
    "orm_prisma_seq": re.compile(
        r"(?i)(@prisma/client|sequelize\.|sqlalchemy\.orm|hibernate\.internal)"
    ),
    "exception_disclosure": re.compile(
        r"(?i)(exception occurred|nullpointerexception|valueerror|indexerror|keyerror|runtimeerror|typeerror)"
    ),
}

# Recommended security headers for APIs
SECURITY_HEADERS = {
    "Content-Type": "Should be present and set to application/json (or specific API format).",
    "Cache-Control": "Should be no-store, no-cache, must-revalidate for sensitive APIs.",
    "X-Content-Type-Options": "Should be set to nosniff.",
    "X-Frame-Options": "Should be DENY or SAMEORIGIN to prevent clickjacking.",
    "Content-Security-Policy": "Defines valid sources of content.",
    "Strict-Transport-Security": "Should be set (e.g., max-age=31536000; includeSubDomains) to enforce HTTPS.",
    "Referrer-Policy": "Controls how much referrer info is sent.",
    "Permissions-Policy": "Configures browser features (camera, geoloc, etc.).",
}

# Technology-revealing headers that should not be exposed
INFO_EXPOSING_HEADERS = ["X-Powered-By", "Server", "X-AspNet-Version", "X-Runtime"]

# HTTP methods that require auditing / options checks
SAFE_METHODS = ["GET", "HEAD", "OPTIONS"]
UNSAFE_METHODS = ["POST", "PUT", "PATCH", "DELETE", "TRACE"]
