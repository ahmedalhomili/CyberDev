"""
headers_check.py
-----------------
Checks for missing or insecure HTTP security headers.

This module performs passive analysis only.
"""

import requests


REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "High",
        "description": "Enforces HTTPS connections.",
        "remediation": "Add Strict-Transport-Security header."
    },
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Prevents XSS and data injection attacks.",
        "remediation": "Define a strict Content-Security-Policy."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Protects against clickjacking.",
        "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "Prevents MIME sniffing.",
        "remediation": "Add X-Content-Type-Options: nosniff."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Controls referrer information.",
        "remediation": "Define a Referrer-Policy."
    }
}


def check_security_headers(url: str) -> dict:
    """
    Check missing or misconfigured security headers.

    Returns:
        dict: {
            "missing": list,
            "present": dict,
            "severity": str
        }
    """

    result = {
        "missing": [],
        "present": {},
        "severity": "Low"
    }

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

    except requests.RequestException:
        result["severity"] = "High"
        result["missing"] = list(REQUIRED_HEADERS.keys())
        return result

    highest_severity = "Low"

    for header, info in REQUIRED_HEADERS.items():
        if header in headers:
            result["present"][header] = headers.get(header)
        else:
            result["missing"].append({
                "header": header,
                "severity": info["severity"],
                "description": info["description"],
                "remediation": info["remediation"]
            })

            if info["severity"] == "High":
                highest_severity = "High"
            elif info["severity"] == "Medium" and highest_severity != "High":
                highest_severity = "Medium"

    result["severity"] = highest_severity
    return result
