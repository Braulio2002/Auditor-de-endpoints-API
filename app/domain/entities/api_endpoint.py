from dataclasses import dataclass


@dataclass
class ApiEndpoint:
    nombre: str
    url: str
    metodo: str  # GET, POST, etc.
    requiere_auth: str  # si, no, desconocido
    tipo_endpoint: str  # publico, privado, no clasificado
    descripcion: str
