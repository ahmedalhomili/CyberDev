"""
Security Scoring and Executive Summary Module.
Provides weighted security scoring and automated summary generation.
"""
from typing import List, Dict, Any, Optional
from models import ScanResult, Finding


class SecurityScorer:
    """
    Calculates a weighted security score based on findings.

    Scoring Model:
        - Start at 100 points
        - Deduct per finding based on severity (with per-tier caps)
        - Floor at 0
        - Grade: A(90-100), B(75-89), C(60-74), D(40-59), F(0-39)
    """

    SEVERITY_PENALTIES = {
        "CRITICAL": 30,
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 3,
        "INFO": 1,
    }

    # Cap total penalty contribution per severity tier
    SEVERITY_CAPS = {
        "CRITICAL": 90,   # No effective cap
        "HIGH": 40,
        "MEDIUM": 30,
        "LOW": 12,
        "INFO": 5,
    }

    # Map findings to scoring sections by category or CWE
    SECTION_CWE_MAP = {
        "Transport Security": [
            "CWE-295", "CWE-319", "CWE-614", "CWE-311",
            "CWE-326", "CWE-327",
        ],
        "Header Security": [
            "CWE-693", "CWE-1021", "CWE-942", "CWE-1004",
            "CWE-524",
        ],
        "Email Security": [],  # Handled by category name
        "Information Disclosure": [
            "CWE-200", "CWE-209", "CWE-497", "CWE-615",
            "CWE-538", "CWE-548",
        ],
        "Vulnerability Assessment": [
            "CWE-79", "CWE-89", "CWE-78", "CWE-98",
            "CWE-918", "CWE-601", "CWE-502", "CWE-611",
            "CWE-917", "CWE-352", "CWE-287", "CWE-798",
        ],
    }

    # Map category strings used in Finding.category to scoring sections
    CATEGORY_TO_SECTION = {
        "Transport Security": "Transport Security",
        "Header Security": "Header Security",
        "Email Security": "Email Security",
        "Cookie Security": "Transport Security",
        "Information Disclosure": "Information Disclosure",
        "Data Leakage": "Information Disclosure",
        "Configuration Exposure": "Information Disclosure",
        "Source Code Leak": "Information Disclosure",
        "Credential Leak": "Information Disclosure",
        "Vulnerability": "Vulnerability Assessment",
        "Injection": "Vulnerability Assessment",
        "CORS": "Header Security",
        "Network Security": "Vulnerability Assessment",
    }

    def calculate(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Calculate security scores from scan results.

        Returns:
            Dict with overall_score, grade, and section breakdown
        """
        findings = scan_result.findings

        # Overall score with per-tier caps
        tier_totals = {}
        for f in findings:
            sev = f.severity.upper()
            penalty = self.SEVERITY_PENALTIES.get(sev, 0)
            tier_totals[sev] = tier_totals.get(sev, 0) + penalty

        total_penalty = sum(
            min(tier_totals.get(sev, 0), cap)
            for sev, cap in self.SEVERITY_CAPS.items()
        )
        overall_score = max(0, 100 - total_penalty)
        overall_grade = self._score_to_grade(overall_score)

        # Section scores
        sections = {}
        for section_name in self.SECTION_CWE_MAP:
            section_findings = self._get_section_findings(findings, section_name)
            section_penalty = sum(
                self.SEVERITY_PENALTIES.get(f.severity.upper(), 0)
                for f in section_findings
            )
            section_score = max(0, 100 - section_penalty)
            sections[section_name] = {
                "score": section_score,
                "grade": self._score_to_grade(section_score),
                "findings_count": len(section_findings),
            }

        return {
            "overall_score": overall_score,
            "grade": overall_grade,
            "total_findings": len(findings),
            "sections": sections,
        }

    def _get_section_findings(self, findings: List[Finding], section_name: str) -> List[Finding]:
        """Get findings belonging to a specific scoring section."""
        section_cwes = set(self.SECTION_CWE_MAP.get(section_name, []))
        result = []

        for f in findings:
            # Match by CWE
            if f.cwe_reference and f.cwe_reference in section_cwes:
                result.append(f)
                continue

            # Match by category mapping
            mapped_section = self.CATEGORY_TO_SECTION.get(f.category)
            if mapped_section == section_name:
                result.append(f)
                continue

            # Special handling for Email Security (match by title/description)
            if section_name == "Email Security":
                if "spf" in f.title.lower() or "dmarc" in f.title.lower() or "email" in f.category.lower():
                    result.append(f)

        return result

    @staticmethod
    def _score_to_grade(score: int) -> str:
        """Convert numeric score to letter grade."""
        if score >= 90:
            return "A"
        elif score >= 75:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 40:
            return "D"
        else:
            return "F"


class ExecutiveSummaryGenerator:
    """
    Generates a human-readable executive summary from scan results.
    Uses dynamic posture text that adapts to the actual highest severity found.
    """

    POSTURE_TEMPLATES = {
        "A": "The target demonstrates a STRONG security posture. Only minor informational findings were identified. The application follows security best practices across most areas.",
        "B": "The target exhibits a GOOD security posture with some areas for improvement. A few low-to-medium severity findings were identified that should be addressed to strengthen the overall defense.",
        "C": "The target shows a MODERATE security posture. Several medium-severity findings were identified that represent tangible security risks requiring attention.",
        "D": "The target has a WEAK security posture. Multiple high-severity findings were identified that pose significant security risks and should be remediated promptly.",
        "F": "The target has a CRITICAL security posture. Severe vulnerabilities were detected that could lead to data breaches, system compromise, or service disruption. Immediate remediation is strongly recommended.",
    }

    # Dynamic F-grade posture when highest severity doesn't warrant "CRITICAL" language
    F_GRADE_BY_SEVERITY = {
        "LOW": "The target has a BELOW AVERAGE security posture. Numerous low-severity findings were detected across multiple areas. While no single issue is critical, the volume of findings indicates systemic configuration weaknesses that should be addressed.",
        "MEDIUM": "The target has a POOR security posture. Multiple medium-severity findings were identified that collectively represent significant security risks. Remediation of these issues is recommended.",
        "INFO": "The target has a BELOW AVERAGE security posture. Many informational findings were identified, suggesting areas where security hardening would be beneficial.",
    }

    # Maximum posture severity based on the highest-severity finding present.
    # Prevents claiming "CRITICAL posture" when only LOW/INFO findings exist.
    HIGHEST_SEVERITY_POSTURE_CAP = {
        "INFO": "A",     # Info only -> never worse than A posture
        "LOW": "B",      # LOW only -> never worse than B posture
        "MEDIUM": "D",   # MEDIUM -> never worse than D
        "HIGH": "F",     # HIGH -> no cap
        "CRITICAL": "F", # CRITICAL -> no cap
    }

    def _get_posture_text(self, effective_grade: str, highest_severity: str) -> str:
        """Get context-appropriate posture text based on grade and actual severity."""
        if effective_grade == "F" and highest_severity in self.F_GRADE_BY_SEVERITY:
            return self.F_GRADE_BY_SEVERITY[highest_severity]
        return self.POSTURE_TEMPLATES.get(effective_grade, self.POSTURE_TEMPLATES["C"])

    def generate(self, scan_result: ScanResult, score_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate executive summary.

        Returns:
            Dict with posture, risk_summary, top_risks, and recommendations
        """
        summary_stats = scan_result.summary()
        grade = score_data.get("grade", "C")

        # Determine the highest severity finding present
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        highest_severity = "INFO"
        for f in scan_result.findings:
            if severity_order.get(f.severity.upper(), 99) < severity_order.get(highest_severity, 99):
                highest_severity = f.severity.upper()

        # Cap posture grade based on the actual highest severity found
        grade_order = {'A': 0, 'B': 1, 'C': 2, 'D': 3, 'F': 4}
        cap_grade = self.HIGHEST_SEVERITY_POSTURE_CAP.get(highest_severity, "F")
        if grade_order.get(grade, 4) > grade_order.get(cap_grade, 4):
            effective_grade = cap_grade
        else:
            effective_grade = grade

        # 1. Posture statement (severity-aware)
        posture = self._get_posture_text(effective_grade, highest_severity)

        # 2. Risk summary
        risk_parts = []
        if summary_stats['critical'] > 0:
            risk_parts.append(f"{summary_stats['critical']} critical")
        if summary_stats['high'] > 0:
            risk_parts.append(f"{summary_stats['high']} high")
        if summary_stats['medium'] > 0:
            risk_parts.append(f"{summary_stats['medium']} medium")
        if summary_stats['low'] > 0:
            risk_parts.append(f"{summary_stats['low']} low")
        if summary_stats['info'] > 0:
            risk_parts.append(f"{summary_stats['info']} informational")

        risk_summary = (
            f"A total of {summary_stats['total']} findings were identified: "
            + ", ".join(risk_parts) + "."
            if risk_parts else
            "No security findings were identified during the assessment."
        )

        # 3. Top risks (highest severity findings, up to 3)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(
            scan_result.findings,
            key=lambda f: severity_order.get(f.severity, 99)
        )
        top_risks = []
        for f in sorted_findings[:3]:
            top_risks.append(f"[{f.severity}] {f.title} - {f.location}")

        # 4. Recommendations (unique, from highest severity findings, up to 5)
        seen_recs = set()
        recommendations = []
        for f in sorted_findings:
            if f.recommendation not in seen_recs and len(recommendations) < 5:
                recommendations.append(f.recommendation)
                seen_recs.add(f.recommendation)

        return {
            "posture": posture,
            "risk_summary": risk_summary,
            "top_risks": top_risks,
            "recommendations": recommendations,
            "grade": grade,
            "score": score_data.get("overall_score", 0),
        }
