"""
Cross-Site Scripting (XSS) Vulnerability Scanner.
Checks for Reflected XSS vulnerabilities in query parameters.
"""
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from models import Finding
from scanner.requester import Requester

logger = logging.getLogger(__name__)

class XSSScanner:
    """Scanner for Reflected XSS vulnerabilities."""

    def __init__(self):
        self.requester = Requester()
        # Using a canary string to confirm reflection
        self.canary = "XSSCHECK"
        self.payloads = [
            f"<script>alert('{self.canary}')</script>",
            f"\"><script>alert('{self.canary}')</script>",
            f"<img src=x onerror=alert('{self.canary}')>",
            f"'{self.canary}",
            f"\"{self.canary}"
        ]

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for Reflected XSS vulnerabilities.
        """
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        for param in params.keys():
            for payload in self.payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                target_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))

                try:
                    response = self.requester.get(target_url, timeout=5)
                    
                    # Check if payload is reflected in the response body
                    if payload in response.text:
                         findings.append(Finding(
                            title="Reflected XSS Vulnerability",
                            severity="HIGH",
                            description=f"The application reflects user input without sanitization in parameter '{param}'. Payload used: {payload}",
                            location=f"URL: {url} | Param: {param}",
                            recommendation="Encode all user-controlled data before rendering it in the browser. Use Content Security Policy (CSP).",
                            cwe_reference="CWE-79"
                        ))
                         # If one payload works, that's enough to prove vulnerability for this param
                         break
                
                except Exception as e:
                    logger.debug(f"Error scanning XSS for {target_url}: {e}")

        return findings
