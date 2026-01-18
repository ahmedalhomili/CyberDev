"""
severity.py
------------
Centralized severity handling for scan results.
"""

SEVERITY_LEVELS = {
    "Low": 1,
    "Medium": 2,
    "High": 3
}


def normalize_severity(severity: str) -> str:
    """
    Ensure severity value is valid.

    Returns:
        str: Low | Medium | High
    """
    if severity not in SEVERITY_LEVELS:
        return "Low"
    return severity


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
