import re
from pathlib import Path

import pandas as pd

from app.application.interfaces.report_exporter_interface import ReportExporterInterface
from app.domain.entities.endpoint_audit_report import EndpointAuditReport
from app.domain.exceptions.domain_exceptions import ExporterException
from app.domain.value_objects.finding_category import FindingCategory
from app.shared.logger import logger


class ExcelReportExporter(ReportExporterInterface):
    """
    Exports audit results to a professional, multi-sheet Excel file.
    """

    def export(self, reports: list[EndpointAuditReport], file_path: Path) -> None:
        try:
            logger.info(f"Generando reporte Excel: {file_path.name}...")

            df_resumen = self._build_resumen_df(reports)
            df_hallazgos = self._build_hallazgos_df(reports)
            df_metodos = self._build_metodos_df(reports)
            df_sensibles = self._build_sensibles_df(reports)
            df_errores_det = self._build_errores_det_df(reports)
            df_recom = self._build_recom_df(reports)
            df_errores = self._build_errores_df(reports)

            # Write sheets using pandas ExcelWriter and openpyxl
            with pd.ExcelWriter(file_path, engine="openpyxl") as writer:
                df_resumen.to_excel(writer, sheet_name="Resumen", index=False)
                df_hallazgos.to_excel(writer, sheet_name="Hallazgos", index=False)
                df_metodos.to_excel(writer, sheet_name="Métodos HTTP", index=False)
                df_sensibles.to_excel(writer, sheet_name="Datos Sensibles", index=False)
                df_errores_det.to_excel(writer, sheet_name="Errores Detallados", index=False)
                df_recom.to_excel(writer, sheet_name="Recomendaciones", index=False)
                df_errores.to_excel(writer, sheet_name="Errores", index=False)

            logger.info(f"Reporte Excel generado correctamente en: {file_path}")

        except Exception as e:
            raise ExporterException(f"Error exportando reporte Excel: {e}")

    def _build_resumen_df(self, reports: list[EndpointAuditReport]) -> pd.DataFrame:
        resumen_data = []
        for r in reports:
            # Count findings by severity
            criticos = sum(1 for f in r.findings if f.severidad == "CRITICAL")
            altos = sum(1 for f in r.findings if f.severidad == "HIGH")
            medios = sum(1 for f in r.findings if f.severidad == "MEDIUM")
            bajos = sum(1 for f in r.findings if f.severidad == "LOW")

            resumen_data.append(
                {
                    "nombre": r.endpoint.nombre,
                    "url": r.endpoint.url,
                    "metodo": r.endpoint.metodo,
                    "requiere_auth": r.endpoint.requiere_auth,
                    "status_code": r.status_code if r.status_code is not None else "ERROR",
                    "score_riesgo": r.score_riesgo,
                    "nivel_riesgo": r.nivel_riesgo.value,
                    "total_hallazgos": len(r.findings),
                    "hallazgos_criticos": criticos,
                    "hallazgos_altos": altos,
                    "hallazgos_medios": medios,
                    "hallazgos_bajos": bajos,
                    "error": r.error if r.error else "Ninguno",
                    "fecha_analisis": r.fecha_analisis,
                }
            )
        return pd.DataFrame(resumen_data)

    def _build_hallazgos_df(self, reports: list[EndpointAuditReport]) -> pd.DataFrame:
        hallazgos_data = []
        for r in reports:
            for f in r.findings:
                hallazgos_data.append(
                    {
                        "url": r.endpoint.url,
                        "metodo": r.endpoint.metodo,
                        "categoria": f.categoria.value,
                        "severidad": f.severidad.value,
                        "titulo": f.titulo,
                        "descripcion": f.descripcion,
                        "evidencia_segura": f.evidencia_segura,
                        "recomendacion": f.recomendacion,
                    }
                )
        df = pd.DataFrame(hallazgos_data)
        if df.empty:
            df = pd.DataFrame(
                columns=[
                    "url",
                    "metodo",
                    "categoria",
                    "severidad",
                    "titulo",
                    "descripcion",
                    "evidencia_segura",
                    "recomendacion",
                ]
            )
        return df

    def _build_metodos_df(self, reports: list[EndpointAuditReport]) -> pd.DataFrame:
        metodos_data = []
        for r in reports:
            # Find HTTP_METHODS finding if any
            method_findings = [f for f in r.findings if f.categoria == FindingCategory.HTTP_METHODS]
            detected = self._get_detected_methods(r, method_findings)
            is_risky = "no"
            obs = "Configuración correcta"
            rec = "Mantener privilegios mínimos"

            if method_findings:
                is_risky = "si"
                obs = "; ".join(mf.descripcion for mf in method_findings)
                rec = "; ".join(mf.recomendacion for mf in method_findings)

            metodos_data.append(
                {
                    "url": r.endpoint.url,
                    "metodo_declarado": r.endpoint.metodo,
                    "metodos_detectados": detected,
                    "metodo_riesgoso": is_risky,
                    "observacion": obs,
                    "recomendacion": rec,
                }
            )
        return pd.DataFrame(metodos_data)

    def _get_detected_methods(self, r: EndpointAuditReport, method_findings) -> str:
        if r.status_code is None:
            return "No detectado (error)"

        detected = r.endpoint.metodo
        for mf in method_findings:
            match = re.search(r"Detectados adicionales: ([\w, ]+)", mf.evidencia_segura)
            if match:
                return f"{r.endpoint.metodo}, {match.group(1)}"
            if "Métodos:" in mf.evidencia_segura:
                return mf.evidencia_segura.replace("Métodos:", "").strip()
        return detected

    def _build_sensibles_df(self, reports: list[EndpointAuditReport]) -> pd.DataFrame:
        sensibles_data = []
        for r in reports:
            sensitive_findings = [
                f for f in r.findings if f.categoria == FindingCategory.SENSITIVE_DATA
            ]
            for sf in sensitive_findings:
                self._parse_sensitive_evidence(r.endpoint.url, sf, sensibles_data)

        df = pd.DataFrame(sensibles_data)
        if df.empty:
            df = pd.DataFrame(
                columns=[
                    "url",
                    "campo_sospechoso",
                    "tipo_dato",
                    "evidencia_enmascarada",
                    "severidad",
                    "recomendacion",
                ]
            )
        return df

    def _parse_sensitive_evidence(self, url: str, sf, target_list: list) -> None:
        evidence = sf.evidencia_segura
        if "Campos expuestos:" in evidence:
            parts = evidence.replace("Campos expuestos:", "").strip().split(", ")
            for part in parts:
                match = re.match(r"([a-zA-Z0-9_\-\.\[\]]+)\s*\(evidencia:\s*([^\)]+)\)", part)
                if match:
                    field_name = match.group(1)
                    masked_val = match.group(2)
                    data_type = self._deduce_sensitive_type(field_name)
                    target_list.append(
                        {
                            "url": url,
                            "campo_sospechoso": field_name,
                            "tipo_dato": data_type,
                            "evidencia_enmascarada": masked_val,
                            "severidad": sf.severidad.value,
                            "recomendacion": sf.recomendacion,
                        }
                    )
                else:
                    target_list.append(
                        {
                            "url": url,
                            "campo_sospechoso": "Cuerpo de respuesta",
                            "tipo_dato": "Texto / JSON",
                            "evidencia_enmascarada": part,
                            "severidad": sf.severidad.value,
                            "recomendacion": sf.recomendacion,
                        }
                    )
        elif "Header" in evidence:
            match = re.match(r"Header\s+'([^']+)'\s+expuesto:\s+(.*)", evidence)
            if match:
                target_list.append(
                    {
                        "url": url,
                        "campo_sospechoso": f"Header: {match.group(1)}",
                        "tipo_dato": "Header de Respuesta",
                        "evidencia_enmascarada": match.group(2),
                        "severidad": sf.severidad.value,
                        "recomendacion": sf.recomendacion,
                    }
                )
            else:
                target_list.append(
                    {
                        "url": url,
                        "campo_sospechoso": "Cabecera",
                        "tipo_dato": "Header",
                        "evidencia_enmascarada": evidence,
                        "severidad": sf.severidad.value,
                        "recomendacion": sf.recomendacion,
                    }
                )

    def _deduce_sensitive_type(self, field_name: str) -> str:
        name_lower = field_name.lower()
        if "email" in name_lower:
            return "Email"
        if "phone" in name_lower or "tel" in name_lower:
            return "Teléfono"
        if "card" in name_lower or "tarjeta" in name_lower:
            return "Tarjeta de crédito"
        if "token" in name_lower or "key" in name_lower or "secret" in name_lower:
            return "Token / Credencial"
        return "PII / Sensible"

    def _build_errores_det_df(self, reports: list[EndpointAuditReport]) -> pd.DataFrame:
        errores_det_data = []
        for r in reports:
            verbose_findings = [
                f for f in r.findings if f.categoria == FindingCategory.VERBOSE_ERRORS
            ]
            for vf in verbose_findings:
                self._parse_verbose_evidence(r.endpoint.url, vf, errores_det_data)

        df = pd.DataFrame(errores_det_data)
        if df.empty:
            df = pd.DataFrame(
                columns=[
                    "url",
                    "patron_detectado",
                    "evidencia_enmascarada",
                    "severidad",
                    "recomendacion",
                ]
            )
        return df

    def _parse_verbose_evidence(self, url: str, vf, target_list: list) -> None:
        evidence = vf.evidencia_segura
        if "Firmas detectadas:" in evidence:
            parts = evidence.replace("Firmas detectadas:", "").strip().split(", ")
            for part in parts:
                match = re.match(r"([a-zA-Z0-9_\-\.]+):\s*'([^']*)'", part)
                if match:
                    target_list.append(
                        {
                            "url": url,
                            "patron_detectado": match.group(1),
                            "evidencia_enmascarada": match.group(2),
                            "severidad": vf.severidad.value,
                            "recomendacion": vf.recomendacion,
                        }
                    )
                else:
                    target_list.append(
                        {
                            "url": url,
                            "patron_detectado": "Detalle técnico",
                            "evidencia_enmascarada": part,
                            "severidad": vf.severidad.value,
                            "recomendacion": vf.recomendacion,
                        }
                    )
        else:
            target_list.append(
                {
                    "url": url,
                    "patron_detectado": "Excepción / Stacktrace",
                    "evidencia_enmascarada": evidence,
                    "severidad": vf.severidad.value,
                    "recomendacion": vf.recomendacion,
                }
            )

    def _build_recom_df(self, reports: list[EndpointAuditReport]) -> pd.DataFrame:
        recom_data = []
        for r in reports:
            for f in r.findings:
                recom_data.append(
                    {
                        "url": r.endpoint.url,
                        "prioridad": f.severidad.value,
                        "categoria": f.categoria.value,
                        "problema": f.titulo,
                        "recomendacion": f.recomendacion,
                    }
                )
        df_recom = pd.DataFrame(recom_data)
        if not df_recom.empty:
            df_recom = df_recom.drop_duplicates(subset=["url", "recomendacion"])
        else:
            df_recom = pd.DataFrame(
                columns=["url", "prioridad", "categoria", "problema", "recomendacion"]
            )
        return df_recom

    def _build_errores_df(self, reports: list[EndpointAuditReport]) -> pd.DataFrame:
        errores_data = []
        for r in reports:
            if r.error:
                errores_data.append(
                    {
                        "url": r.endpoint.url,
                        "metodo": r.endpoint.metodo,
                        "tipo_error": "Fallo de Comunicación"
                        if r.status_code is None
                        else "Error HTTP",
                        "mensaje_error": r.error,
                        "fecha_analisis": r.fecha_analisis,
                    }
                )
        df_errores = pd.DataFrame(errores_data)
        if df_errores.empty:
            df_errores = pd.DataFrame(
                columns=["url", "metodo", "tipo_error", "mensaje_error", "fecha_analisis"]
            )
        return df_errores
