from pathlib import Path

import pandas as pd

from app.application.interfaces.endpoint_reader_interface import EndpointReaderInterface
from app.domain.entities.api_endpoint import ApiEndpoint
from app.domain.exceptions.domain_exceptions import ReaderException


class CsvEndpointReader(EndpointReaderInterface):
    """
    Reads API endpoints from a CSV file using pandas.
    Handles commas, semicolons, and other common CSV formats.
    """

    def read_endpoints(self, file_path: Path) -> list[ApiEndpoint]:
        if not file_path.exists():
            raise ReaderException(f"El archivo {file_path} no existe.")

        try:
            df = self._load_df(file_path)
            df = self._clean_df(df)
            return self._parse_endpoints(df)
        except Exception as e:
            if isinstance(e, ReaderException):
                raise
            raise ReaderException(f"Fallo al leer CSV: {e}")

    def _load_df(self, file_path: Path) -> pd.DataFrame:
        try:
            df = pd.read_csv(file_path, sep=",")
            # Map columns to lowercase to prevent casing mismatches
            df.columns = [col.lower().strip() for col in df.columns]
            if "url" not in df.columns:
                df = pd.read_csv(file_path, sep=";")
                df.columns = [col.lower().strip() for col in df.columns]
        except Exception:
            df = pd.read_csv(file_path, sep=";")
            df.columns = [col.lower().strip() for col in df.columns]

        if "url" not in df.columns:
            raise ReaderException("La columna requerida 'url' no está presente en el archivo CSV.")
        return df

    def _clean_df(self, df: pd.DataFrame) -> pd.DataFrame:
        expected_cols = ["nombre", "metodo", "requiere_auth", "tipo_endpoint", "descripcion"]
        for col in expected_cols:
            if col not in df.columns:
                df[col] = ""

        # Ignore rows where URL is empty
        df = df.dropna(subset=["url"])
        df = df[df["url"].astype(str).str.strip() != ""]

        # Normalize and strip values
        for col in df.columns:
            df[col] = df[col].fillna("").astype(str).str.strip()

        # Deduplicate based on URL and Metodo
        return df.drop_duplicates(subset=["url", "metodo"])

    def _parse_endpoints(self, df: pd.DataFrame) -> list[ApiEndpoint]:
        endpoints = []
        for _, row in df.iterrows():
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
