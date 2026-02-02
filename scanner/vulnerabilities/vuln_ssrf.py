"""
Server-Side Request Forgery (SSRF) Scanner.
Checks if the application fetches data from arbitrary or internal URLs.
"""
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from models import Finding
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class SSRFScanner:
    """Scanner for SSRF vulnerabilities."""

    def __init__(self):
        self.requester = Requester(timeout=5)  # Moderate timeout
        self.payloads = [
            ("http://127.0.0.1", "localhost"),
            ("http://localhost", "localhost"),
            ("http://127.0.0.1:80", "localhost"),
            ("http://169.254.169.254/latest/meta-data/", "ami-id"),  # AWS
            ("http://169.254.169.254/latest/user-data", "user-data"),
            ("http://instance-data/latest/meta-data/", "compute"),  # GCP
            ("http://[0:0:0:0:0:ffff:127.0.0.1]", "localhost"),  # IPv6 bypass
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

        # 1. Baseline Request
        try:
            baseline = self.requester.get(url)
            baseline_len = len(baseline.text)
        except:
            baseline_len = 0

        for param in params.keys():
            # Basic Payload Injection
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
                    # Measure response
                    response = self.requester.get(target_url, timeout=5)
                    
                    # Check for content indicators (non-blind)
                    # We must be careful not to flag reflection (e.g. "You searched for http://127...")
                    # Ideally we check if the response looks weirdly different or contains cloud metadata
                    if indicator in response.text and payload not in response.text:
                         findings.append(Finding(
                            title="Server-Side Request Forgery (SSRF) - Content Match",
                            severity="CRITICAL",
                            description=f"The application appears to fetch internal resources via parameter '{param}'. Payload: {payload}. Response contained indicator: '{indicator}' but not the payload itself.",
                            location=f"URL: {url} | Param: {param}",
                            recommendation="Validate and whitelist user-supplied URLs. Disable HTTP redirections on internal requests. Run in an isolated network environment.",
                            cwe_reference="CWE-918"
                        ))
                    
                    # Heuristic for Localhost/Blind SSRF:
                    # If we ask for 127.0.0.1 and get response different from baseline, it's suspicious.
                    if "127.0.0.1" in payload:
                        # Check reaction: length difference or status code difference
                        # This is noisy, so we set severity to MEDIUM and require significant difference
                        # (ignoring reflection which would increase length slightly)
                        len_diff = abs(len(response.text) - baseline_len)
                        if response.status_code != 200 and response.status_code >= 500:
                             # Internal server error often happens when upstream connection fails
                             findings.append(Finding(
                                title="Potential Blind SSRF (Error Based)",
                                severity="MEDIUM",
                                description=f"Parameter '{param}' caused a server error when supplied with '{payload}'. This might indicate the server tried to connect and failed.",
                                location=f"URL: {url} | Param: {param}",
                                recommendation="Review backend logic for outgoing requests.",
                                cwe_reference="CWE-918"
                            ))

                except Exception as e:
                    # Timeout suggests the server tried to connect and hung
                    # This is a classic Blind SSRF indicator for firewall drops
                    findings.append(Finding(
                        title="Potential Blind SSRF (Timing/Timeout)",
                        severity="MEDIUM",
                        description=f"Request timed out when parameter '{param}' was set to '{payload}'. This may indicate the server is trying to connect to an internal IP.",
                        location=f"URL: {url} | Param: {param}",
                        recommendation="Ensure the application does not make arbitrary network connections.",
                        cwe_reference="CWE-918"
                    ))

        return findings
