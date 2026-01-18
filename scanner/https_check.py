"""
https_check.py
---------------
Checks whether a website enforces HTTPS by redirecting
HTTP traffic to HTTPS.

This is a SAFE and PASSIVE check.
"""

import requests


def check_https_redirect(url: str) -> dict:
    """
    Check if HTTP requests are redirected to HTTPS.

    Returns:
        dict: {
            "https_enforced": bool,
            "initial_url": str,
            "final_url": str,
            "severity": str,
            "message": str,
            "remediation": str
        }
    """

    result = {
        "https_enforced": False,
        "initial_url": url,
        "final_url": "",
        "severity": "Medium",
        "message": "",
        "remediation": ""
    }

    # If URL already uses HTTPS
    if url.startswith("https://"):
        result["https_enforced"] = True
        result["final_url"] = url
        result["severity"] = "Low"
        result["message"] = "URL already uses HTTPS."
        result["remediation"] = "No action required."
        return result

    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=10
        )

        result["final_url"] = response.url

        if response.url.startswith("https://"):
            result["https_enforced"] = True
            result["severity"] = "Low"
            result["message"] = "HTTP traffic is redirected to HTTPS."
            result["remediation"] = "HTTPS redirection is properly configured."
        else:
            result["https_enforced"] = False
            result["severity"] = "High"
            result["message"] = "Website does NOT redirect HTTP to HTTPS."
            result["remediation"] = (
                "Configure the web server to redirect all HTTP traffic to HTTPS."
            )

    except requests.RequestException:
        result["severity"] = "High"
        result["message"] = "Failed to check HTTPS redirection."
        result["remediation"] = "Ensure the website is reachable."

    return result
