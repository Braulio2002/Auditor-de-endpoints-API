from pathlib import Path

from app.application.interfaces.endpoint_reader_interface import EndpointReaderInterface
from app.domain.entities.api_endpoint import ApiEndpoint
from app.domain.exceptions.domain_exceptions import ReaderException


class TxtEndpointReader(EndpointReaderInterface):
    """
    Reads API endpoints from a TXT file (one URL per line).
    """

    def read_endpoints(self, file_path: Path) -> list[ApiEndpoint]:
        if not file_path.exists():
            raise ReaderException(f"El archivo {file_path} no existe.")

        try:
            endpoints = []
            seen_urls = set()

            with open(file_path, encoding="utf-8") as f:
                for i, line in enumerate(f):
                    url = line.strip()
                    if not url or url.startswith("#"):
                        continue  # Skip empty lines and comments

                    if url in seen_urls:
                        continue
                    seen_urls.add(url)

                    endpoints.append(
                        ApiEndpoint(
                            nombre=f"Endpoint importado {i + 1}",
                            url=url,
                            metodo="GET",
                            requiere_auth="desconocido",
                            tipo_endpoint="no clasificado",
                            descripcion="Importado desde archivo de texto plano",
                        )
                    )

            return endpoints

        except Exception as e:
            raise ReaderException(f"Fallo al leer TXT: {e}")
