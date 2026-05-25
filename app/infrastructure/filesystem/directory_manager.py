from pathlib import Path

import pandas as pd

from app.shared.logger import logger


class DirectoryManager:
    """
    Manages directories, ensuring input and output folders exist,
    and populates a sample Excel file if missing.
    """

    def __init__(self, entrada_dir: Path, salida_dir: Path):
        self.entrada_dir = entrada_dir
        self.salida_dir = salida_dir

    def ensure_directories(self, default_excel_name: str) -> None:
        """
        Ensures input and output directories exist, and creates the sample Excel sheet.
        """
        # Create input directory
        if not self.entrada_dir.exists():
            logger.info(f"Creando carpeta {self.entrada_dir.name} si no existe...")
            self.entrada_dir.mkdir(parents=True, exist_ok=True)

        # Create output directory
        if not self.salida_dir.exists():
            logger.info(f"Creando carpeta {self.salida_dir.name} si no existe...")
            self.salida_dir.mkdir(parents=True, exist_ok=True)

        # Create default endpoints.xlsx if it does not exist
        excel_path = self.entrada_dir / default_excel_name
        if not excel_path.exists():
            logger.info(
                f"Creando archivo de ejemplo {excel_path.name} en {self.entrada_dir.name}..."
            )

            # Sample data matching requirements exactly
            sample_data = [
                {
                    "nombre": "Listar usuarios",
                    # Using a valid public sandbox URL for testing
                    "url": "https://api.github.com/users",
                    "metodo": "GET",
                    "requiere_auth": "si",
                    "tipo_endpoint": "privado",
                    "descripcion": "Lista usuarios de ejemplo",
                },
                {
                    "nombre": "Login de prueba",
                    "url": "https://httpbin.org/post",
                    "metodo": "POST",
                    "requiere_auth": "no",
                    "tipo_endpoint": "publico",
                    "descripcion": "Endpoint público de prueba",
                },
                {
                    "nombre": "Prueba de error",
                    "url": "https://httpbin.org/status/500",
                    "metodo": "GET",
                    "requiere_auth": "no",
                    "tipo_endpoint": "publico",
                    "descripcion": "Simulador de error 500",
                },
                {
                    "nombre": "Prueba de Auth Bypass",
                    "url": "https://httpbin.org/bearer",
                    "metodo": "GET",
                    "requiere_auth": "si",
                    "tipo_endpoint": "privado",
                    "descripcion": "Endpoint privado que debería responder 401 si no hay token",
                },
            ]

            df = pd.DataFrame(sample_data)
            try:
                df.to_excel(excel_path, index=False)
                logger.info(f"Archivo de ejemplo creado con éxito: {excel_path.name}")
            except Exception as e:
                logger.error(f"Error creando archivo de ejemplo {excel_path.name}: {e}")
