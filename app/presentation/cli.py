import sys
from pathlib import Path

from app.application.use_cases.audit_api_endpoints_use_case import AuditApiEndpointsUseCase
from app.domain.entities.endpoint_audit_report import EndpointAuditReport
from app.domain.value_objects.risk_level import RiskLevel
from app.shared.logger import logger


class ConsoleCLI:
    """
    Console CLI Presentation layer.
    Manages terminal outputs, starts execution, and displays scanning metric summaries.
    """

    def __init__(self, use_case: AuditApiEndpointsUseCase):
        self.use_case = use_case

    def run(
        self,
        input_file: Path,
        output_excel: Path,
        output_json: Path,
        auth_headers=None,
        safe_mode: bool = True,
        timeout: float = 8.0,
    ) -> None:
        """
        Runs the audit and prints a professional summary in the terminal.
        """
        print("=" * 70)
        print("                 AUDITOR DE ENDPOINTS API - SEGURIDAD DEFENSIVA       ")
        print("=" * 70)
        print(f"[*] Archivo de entrada: {input_file}")
        print(f"[*] Modo seguro (SAFE_MODE): {'ACTIVO' if safe_mode else 'INACTIVO'}")
        print(f"[*] Timeout por request: {timeout} segundos")
        print("[*] Iniciando auditoría segura...")
        print("-" * 70)

        try:
            reports = self.use_case.execute(
                input_file_path=input_file,
                output_excel_path=output_excel,
                output_json_path=output_json,
                auth_headers=auth_headers,
                safe_mode=safe_mode,
                timeout=timeout,
            )

            if not reports:
                print("\n[!] No se encontraron endpoints válidos o procesables.")
                return

            self._display_summary(reports, output_excel, output_json)

        except Exception as e:
            logger.error(f"Error fatal durante la ejecución de la auditoría: {e}")
            sys.exit(1)

    def _display_summary(
        self, reports: list[EndpointAuditReport], excel_path: Path, json_path: Path
    ) -> None:
        """
        Renders a stunning summary report dashboard in the terminal.
        """
        total = len(reports)
        con_error = sum(1 for r in reports if r.error is not None)
        auditados = total - con_error

        # Severity counts
        criticos = 0
        altos = 0
        medios = 0
        bajos = 0
        info = 0

        # Risk distribution
        risk_dist = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 0,
            RiskLevel.MEDIUM: 0,
            RiskLevel.LOW: 0,
        }

        for r in reports:
            risk_dist[r.nivel_riesgo] += 1
            for f in r.findings:
                sev = f.severidad
                if sev == "CRITICAL":
                    criticos += 1
                elif sev == "HIGH":
                    altos += 1
                elif sev == "MEDIUM":
                    medios += 1
                elif sev == "LOW":
                    bajos += 1
                else:
                    info += 1

        print("\n" + "=" * 70)
        print("                       RESUMEN DE MÉTRICAS DE AUDITORÍA              ")
        print("=" * 70)
        print(f" Total de endpoints encontrados:  {total}")
        print(f" Total de endpoints analizados:    {auditados}")
        print(f" Total con fallos de conexión:     {con_error}")
        print("-" * 70)
        print(" DISTRIBUCIÓN DE RIESGO POR ENDPOINT:")
        print(f"   [!] CRÍTICO: {risk_dist[RiskLevel.CRITICAL]:>3} endpoints")
        print(f"   [!] ALTO:    {risk_dist[RiskLevel.HIGH]:>3} endpoints")
        print(f"   [!] MEDIO:   {risk_dist[RiskLevel.MEDIUM]:>3} endpoints")
        print(f"   [+] BAJO:    {risk_dist[RiskLevel.LOW]:>3} endpoints")
        print("-" * 70)
        print(" TOTAL DE HALLAZGOS POR SEVERIDAD:")
        print(f"   [-] CRITICAL: {criticos:>3}")
        print(f"   [-] HIGH:     {altos:>3}")
        print(f"   [-] MEDIUM:   {medios:>3}")
        print(f"   [-] LOW:      {bajos:>3}")
        print(f"   [-] INFO:     {info:>3}")
        print("-" * 70)
        print(" ARCHIVOS DE REPORTE GENERADOS:")
        print(f"   [+] Excel: {excel_path}")
        print(f"   [+] JSON:  {json_path}")
        print("=" * 70)
        print(" [+] Auditoría finalizada de forma segura. Hardening recomendado aplicado. ")
        print("=" * 70 + "\n")
