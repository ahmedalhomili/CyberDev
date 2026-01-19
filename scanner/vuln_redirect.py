"""
Open Redirect Vulnerability Scanner.
Checks if the application redirects to arbitrary external domains.
"""
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from models import Finding
from scanner.requester import Requester

logger = logging.getLogger(__name__)

class OpenRedirectScanner:
    """Scanner for Open Redirect vulnerabilities."""

    def __init__(self):
        self.requester = Requester()
        self.target_domain = "example.com"
        self.payloads = [
            f"http://{self.target_domain}",
            f"https://{self.target_domain}",
            f"//{self.target_domain}",
            f"/{self.target_domain}", # Sometimes parsed as relative, sometimes generic
            f"http%3A%2F%2F{self.target_domain}"
        ]

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for Open Redirect vulnerabilities.
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
                    # We need to manually handle redirects to check the 'Location' header
                    # Requester by default follows, so we check the history or final URL
                    response = self.requester.get(target_url, timeout=5)
                    
                    is_vulnerable = False
                    
                    # Method 1: Check history (if redirects were followed)
                    if response.history:
                         for resp in response.history:
                             if "Location" in resp.headers and self.target_domain in resp.headers["Location"]:
                                 is_vulnerable = True
                                 break
                    
                    # Method 2: Check final URL (if it landed on example.com)
                    if self.target_domain in response.url:
                        is_vulnerable = True

                    if is_vulnerable:
                         findings.append(Finding(
                            title="Open Redirect Vulnerability",
                            severity="MEDIUM",
                            description=f"The application redirects users to arbitrary domains via parameter '{param}'. Payload: {payload}.",
                            location=f"URL: {url} | Param: {param}",
                            recommendation="Validate redirect targets against a whitelist of allowed domains or relative paths.",
                            cwe_reference="CWE-601"
                        ))
                         return findings
                
                except Exception as e:
                    logger.debug(f"Error scanning Redirect for {target_url}: {e}")

        return findings
