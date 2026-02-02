"""
Remote Code Execution (RCE) Vulnerability Scanner.
Checks for Command Injection vulnerabilities in query parameters.
"""
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from models import Finding
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class RCEScanner:
    """Scanner for Command Injection / RCE vulnerabilities."""

    def __init__(self):
        self.requester = Requester()
        self.check_token = "RCE_CONFIRMED_123"
        # Payloads designed to echo a string back
        self.payloads = [
            f"; echo {self.check_token}",
            f"| echo {self.check_token}",
            f"&& echo {self.check_token}",
            f"`echo {self.check_token}`",
            f"$(echo {self.check_token})",
            f"; echo {self.check_token} #",  # With comment to neutralize rest
        ]
        # Windows specific
        self.win_payloads = [
            f"& echo {self.check_token}",
            f"| echo {self.check_token}"
        ]

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for RCE vulnerabilities.
        """
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        full_payload_list = self.payloads + self.win_payloads

        for param in params.keys():
            for payload in full_payload_list:
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
                    
                    # Verify execution: Token must be present, BUT the full payload shouldn't be exactly reflected 
                    # (which would indicate simple input mirroring).
                    # This is a heuristic. A better way uses arithmetic, but sticking into existing logic:
                    if self.check_token in response.text:
                         # False Positive Check: Is the entire payload string in the response?
                         # If so, it's likely just echoing back the input parameter.
                         if payload in response.text:
                             continue # Skip, likely reflection

                         findings.append(Finding(
                            title="Remote Code Execution (RCE) Vulnerability",
                            severity="CRITICAL",
                            description=f"The application appears to execute system commands injected into parameter '{param}'. Payload: {payload}. Response contained the echo token but not the full payload (indicating execution).",
                            location=f"URL: {url} | Param: {param}",
                            recommendation="Avoid calling system commands with user input. Use language-specific APIs instead of shell execution.",
                            cwe_reference="CWE-78",
                            confidence="High"
                        ))
                         return findings # Return immediately on critical finding
                
                except Exception as e:
                    logger.debug(f"Error scanning RCE for {target_url}: {e}")

        return findings
