import json
from pathlib import Path

from app.application.interfaces.report_exporter_interface import ReportExporterInterface
from app.domain.entities.endpoint_audit_report import EndpointAuditReport
from app.domain.exceptions.domain_exceptions import ExporterException
from app.shared.logger import logger


class JsonReportExporter(ReportExporterInterface):
    """
    Exports audit results to a comprehensive, well-formatted JSON file.
    """

    def export(self, reports: list[EndpointAuditReport], file_path: Path) -> None:
        try:
            logger.info(f"Generando reporte JSON: {file_path.name}...")

            serializable_reports = []
            for r in reports:
                # Compile findings into dict list
                findings_list = []
                for f in r.findings:
                    findings_list.append(
                        {
                            "categoria": f.categoria.value,
                            "severidad": f.severidad.value,
                            "titulo": f.titulo,
                            "descripcion": f.descripcion,
                            "evidencia_segura": f.evidencia_segura,
                            "recomendacion": f.recomendacion,
                        }
                    )

                serializable_reports.append(
                    {
                        "endpoint": {
                            "nombre": r.endpoint.nombre,
                            "url": r.endpoint.url,
                            "metodo": r.endpoint.metodo,
                            "requiere_auth": r.endpoint.requiere_auth,
                            "tipo_endpoint": r.endpoint.tipo_endpoint,
                            "descripcion": r.endpoint.descripcion,
                        },
                        "status_code": r.status_code,
                        "score_riesgo": r.score_riesgo,
                        "nivel_riesgo": r.nivel_riesgo.value,
                        "findings": findings_list,
                        "recomendaciones": r.recomendaciones,
                        "fecha_analisis": r.fecha_analisis,
                        "error": r.error,
                    }
                )

            # Save file
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(serializable_reports, f, indent=4, ensure_ascii=False)

            logger.info(f"Reporte JSON generado correctamente en: {file_path}")

        except Exception as e:
            raise ExporterException(f"Error exportando reporte JSON: {e}")
