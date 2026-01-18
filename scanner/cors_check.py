"""
cors_check.py
--------------
Checks for common CORS misconfigurations in a SAFE and PASSIVE way.

This module only inspects HTTP response headers and does NOT
perform any exploitation.
"""

import requests


def check_cors(url: str) -> dict:
    """
    Check for common CORS misconfigurations.

    Returns:
        dict: {
            "cors_enabled": bool,
            "allow_origin": str,
            "allow_credentials": str,
            "severity": str,
            "message": str
        }
    """

    result = {
        "cors_enabled": False,
        "allow_origin": None,
        "allow_credentials": None,
        "severity": "Low",
        "message": ""
    }

    headers = {}

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

    except requests.RequestException:
        result["severity"] = "Medium"
        result["message"] = "Failed to retrieve CORS headers."
        return result

    allow_origin = headers.get("Access-Control-Allow-Origin")
    allow_credentials = headers.get("Access-Control-Allow-Credentials")

    result["allow_origin"] = allow_origin
    result["allow_credentials"] = allow_credentials

    # No CORS headers at all
    if not allow_origin:
        result["cors_enabled"] = False
        result["severity"] = "Low"
        result["message"] = "CORS is not enabled."
        return result

    result["cors_enabled"] = True

    # Dangerous configuration
    if allow_origin == "*" and allow_credentials == "true":
        result["severity"] = "High"
        result["message"] = (
            "Insecure CORS configuration: wildcard origin with credentials enabled."
        )

    # Wildcard origin
    elif allow_origin == "*":
        result["severity"] = "Medium"
        result["message"] = "CORS allows any origin (*)."

    # Reflected origin (basic check)
    elif allow_origin in url:
        result["severity"] = "Medium"
        result["message"] = "CORS origin appears to be reflected."

    else:
        result["severity"] = "Low"
        result["message"] = "CORS configuration appears restrictive."

    return result
