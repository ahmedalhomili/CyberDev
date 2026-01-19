"""
Server-Side Request Forgery (SSRF) Scanner.
Checks if the application fetches data from arbitrary or internal URLs.
"""
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from models import Finding
from scanner.requester import Requester

logger = logging.getLogger(__name__)

class SSRFScanner:
    """Scanner for SSRF vulnerabilities."""

    def __init__(self):
        self.requester = Requester(timeout=3) # Short timeout to avoid hanging on firewall drops
        self.collaborator_url = "http://127.0.0.1" # In a real scenario, this would be an OOB callback URL (e.g. Interactsh)
        # Using loopback and cloud metadata for basic detection
        self.payloads = [
            ("http://127.0.0.1", "localhost"),
            ("http://localhost", "localhost"),
            ("http://127.0.0.1:80", "localhost"),
            ("http://169.254.169.254/latest/meta-data/", "ami-id"), # AWS
            ("http://169.254.169.254/latest/user-data", "user-data"),
            ("http://instance-data/latest/meta-data/", "compute"), # GCP
            ("http://[0:0:0:0:0:ffff:127.0.0.1]", "localhost"), # IPv6 bypass
        ]

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for SSRF vulnerabilities.
        """
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        for param in params.keys():
            for payload, indicator in self.payloads:
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
                    # SSRF often manifests as the application returning the content of the internal page 
                    # OR a specific error message distinct from "invalid url"
                    response = self.requester.get(target_url, timeout=4)
                    
                    if indicator in response.text:
                         findings.append(Finding(
                            title="Server-Side Request Forgery (SSRF)",
                            severity="CRITICAL",
                            description=f"The application appears to fetch internal resources via parameter '{param}'. Payload: {payload}. Response contained indicator: '{indicator}'.",
                            location=f"URL: {url} | Param: {param}",
                            recommendation="Validate and whitelist user-supplied URLs. Disable HTTP redirections on internal requests. Run in an isolated network environment.",
                            cwe_reference="CWE-918"
                        ))
                         return findings
                
                except Exception as e:
                    # Timeouts are also an indicator of SSRF (trying to connect to filtered internal IP)
                    # But reliable detection requires more logic (comparing timing vs baseline).
                    # We stick to content matching for this version.
                    pass

        return findings
