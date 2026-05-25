from dataclasses import dataclass

from app.domain.value_objects.finding_category import FindingCategory
from app.domain.value_objects.finding_severity import FindingSeverity


@dataclass
class SecurityFinding:
    categoria: FindingCategory
    severidad: FindingSeverity
    titulo: str
    descripcion: str
    evidencia_segura: str
    recomendacion: str
