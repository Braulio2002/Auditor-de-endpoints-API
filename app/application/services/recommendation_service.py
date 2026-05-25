from app.domain.entities.security_finding import SecurityFinding


class RecommendationService:
    """
    Generates actionable, prioritized recommendations based on security findings.
    """

    def generate_recommendations(self, findings: list[SecurityFinding]) -> list[str]:
        """
        Extracts and prioritizes unique recommendations from a list of findings.
        """
        recommendations = []
        seen = set()

        # Prioritize based on severity: CRITICAL first, then HIGH, MEDIUM, LOW, INFO
        from app.domain.value_objects.finding_severity import FindingSeverity

        severity_order = [
            FindingSeverity.CRITICAL,
            FindingSeverity.HIGH,
            FindingSeverity.MEDIUM,
            FindingSeverity.LOW,
            FindingSeverity.INFO,
        ]

        sorted_findings = sorted(
            findings,
            key=lambda f: (
                severity_order.index(f.severidad) if f.severidad in severity_order else 99
            ),
        )

        for finding in sorted_findings:
            rec = finding.recomendacion.strip()
            if rec and rec not in seen:
                seen.add(rec)
                recommendations.append(rec)

        return recommendations
