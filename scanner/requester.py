"""
requester.py
--------------
Responsible for fetching HTTP headers and page content
in a safe and passive manner.

No exploitation or intrusive behavior is performed.
"""

import requests


def fetch_response(url: str) -> dict:
    """
    Fetch headers and body from a given URL.

    Returns:
        dict: {
            "status": bool,
            "status_code": int,
            "headers": dict,
            "body": str,
            "final_url": str,
            "error": str | None
        }
    """

    result = {
        "status": False,
        "status_code": None,
        "headers": {},
        "body": "",
        "final_url": "",
        "error": None
    }

    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=10,
            headers={
                "User-Agent": "Safe-Web-Vulnerability-Checker/1.0"
            }
        )

        result["status"] = True
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)
        result["body"] = response.text[:5000]  # limit size (safe)
        result["final_url"] = response.url

    except requests.RequestException as e:
        result["error"] = str(e)

    return result
