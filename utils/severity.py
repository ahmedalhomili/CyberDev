"""
severity.py
------------
Centralized severity handling for scan results.
"""

SEVERITY_LEVELS = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def normalize_severity(severity: str) -> str:
    """
    Ensure severity value is valid.

    Returns:
        str: INFO | LOW | MEDIUM | HIGH | CRITICAL
    """
    s = severity.upper()
    if s in SEVERITY_LEVELS:
        return s
    
    # Simple mapping for mixed case inputs
    mapping = {
        "INFO": "INFO", "INFORMATION": "INFO",
        "LOW": "LOW",
        "MEDIUM": "MEDIUM", "MED": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL", "CRIT": "CRITICAL"
    }
    
    return mapping.get(s, "LOW")


def compare_severity(current: str, new: str) -> str:
    """
    Compare two severity levels and return the higher one.
    """
    current = normalize_severity(current)
    new = normalize_severity(new)

    if SEVERITY_LEVELS[new] > SEVERITY_LEVELS[current]:
        return new
    return current


def calculate_overall_severity(results: dict) -> str:
    """
    Calculate overall severity from multiple scan results.

    Example input:
        {
            "https": {"severity": "Low"},
            "headers": {"severity": "High"},
            "cors": {"severity": "Medium"}
        }
    """
    overall = "Low"

    for result in results.values():
        severity = result.get("severity", "Low")
        overall = compare_severity(overall, severity)

    return overall
