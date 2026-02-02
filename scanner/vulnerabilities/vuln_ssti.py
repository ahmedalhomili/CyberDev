"""
Server-Side Template Injection (SSTI) Scanner.
Checks if user input is evaluated by a template engine.
"""
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from models import Finding
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class SSTIScanner:
    """Scanner for SSTI vulnerabilities."""

    def __init__(self):
        self.requester = Requester()
        # Use large unique numbers to avoid False Positives (finding "49" in price, id, etc.)
        self.payloads = [
            ("{{9218*81}}", "746658"),
            ("${9218*81}", "746658"),
            ("<%= 9218*81 %>", "746658"),
            ("{{7*'7'}}", "7777777"),
            ("${{9218*81}}", "746658"),
            ("#{9218*81}", "746658")
        ]

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for SSTI vulnerabilities.
        """
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        for param in params.keys():
            for payload, expected_result in self.payloads:
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
                    
                    # FP Check: Ensure the expected result is present AND the payload (as a string) is NOT just reflected
                    # If payload is "{{...}}" and response contains "{{...}}", it's likely just XSS/Reflection, not SSTI execution.
                    if expected_result in response.text and payload not in response.text:
                         findings.append(Finding(
                            title="Server-Side Template Injection (SSTI)",
                            severity="CRITICAL",
                            description=f"The application evaluated a template expression in parameter '{param}'. Payload: {payload}, Result found: {expected_result}. This often leads to RCE.",
                            location=f"URL: {url} | Param: {param}",
                            recommendation="Sanitize input before passing it to template engines. Use 'logic-less' templates or configured sandboxes.",
                            cwe_reference="CWE-1336"
                        ))
                         return findings # Critical finding, stop scanning for this param
                
                except Exception as e:
                    logger.debug(f"Error scanning SSTI for {target_url}: {e}")

        return findings
