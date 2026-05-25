from pathlib import Path

import pandas as pd

from app.application.interfaces.endpoint_reader_interface import EndpointReaderInterface
from app.domain.entities.api_endpoint import ApiEndpoint
from app.domain.exceptions.domain_exceptions import ReaderException


class ExcelEndpointReader(EndpointReaderInterface):
    """
    Reads API endpoints from an Excel file using pandas.
    """

    def read_endpoints(self, file_path: Path) -> list[ApiEndpoint]:
        if not file_path.exists():
            raise ReaderException(f"El archivo {file_path} no existe.")

        try:
            # Load with pandas
            df = pd.read_excel(file_path)

            # Map columns to lowercase to prevent casing mismatches
            df.columns = [col.lower().strip() for col in df.columns]

            # Verify that URL column is present
            if "url" not in df.columns:
                raise ReaderException(
                    "La columna requerida 'url' no está presente en el archivo Excel."
                )

            # Ensure all expected columns exist in dataframe, add them as empty if missing
            expected_cols = ["nombre", "metodo", "requiere_auth", "tipo_endpoint", "descripcion"]
            for col in expected_cols:
                if col not in df.columns:
                    df[col] = ""

            # 1. Ignore rows where URL is empty
            df = df.dropna(subset=["url"])
            df = df[df["url"].astype(str).str.strip() != ""]

            # 2. Normalize and strip values
            for col in df.columns:
                df[col] = df[col].fillna("").astype(str).str.strip()

            # 3. Deduplicate based on URL and Metodo (since duplicate endpoints are redundant)
            df = df.drop_duplicates(subset=["url", "metodo"])

            endpoints = []
            for _, row in df.iterrows():
                # Apply defaults as requested
                metodo = row["metodo"] if row["metodo"] else "GET"
                requiere_auth = row["requiere_auth"] if row["requiere_auth"] else "desconocido"
                tipo_endpoint = row["tipo_endpoint"] if row["tipo_endpoint"] else "no clasificado"

                endpoints.append(
                    ApiEndpoint(
                        nombre=row["nombre"] if row["nombre"] else "Endpoint sin nombre",
                        url=row["url"],
                        metodo=metodo,
                        requiere_auth=requiere_auth,
                        tipo_endpoint=tipo_endpoint,
                        descripcion=row["descripcion"],
                    )
                )

            return endpoints

        except Exception as e:
            if isinstance(e, ReaderException):
                raise
            raise ReaderException(f"Fallo al leer Excel: {e}")
