"""
Local File Inclusion (LFI) Vulnerability Scanner.
Checks for Path Traversal vulnerabilities in query parameters.
"""
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from models import Finding
from scanner.requester import Requester

logger = logging.getLogger(__name__)

class LFIScanner:
    """Scanner for LFI vulnerabilities."""

    def __init__(self):
        self.requester = Requester()
        self.payloads = [
            "../../../../../../../../etc/passwd",
            "../../../../../../../../windows/win.ini",
            "/etc/passwd",
            "c:/windows/win.ini",
            "....//....//....//etc/passwd" # WAF bypass attempt
        ]
        self.signatures = [
            "root:x:0:0:",
            "[extensions]",
            "[fonts]",
            "bin:x:1:1:"
        ]

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for LFI vulnerabilities.
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
                    
                    for sig in self.signatures:
                        if sig in response.text:
                             findings.append(Finding(
                                title="Local File Inclusion (LFI)",
                                severity="HIGH",
                                description=f"The application allows reading local system files via parameter '{param}'. Payload: {payload}. Signature '{sig}' found in response.",
                                location=f"URL: {url} | Param: {param}",
                                recommendation="Validate user input against a whitelist of allowed files. Disable file inclusion functions if possible.",
                                cwe_reference="CWE-22"
                            ))
                             return findings 
                
                except Exception as e:
                    logger.debug(f"Error scanning LFI for {target_url}: {e}")

        return findings
