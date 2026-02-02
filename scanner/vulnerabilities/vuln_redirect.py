"""
Open Redirect Vulnerability Scanner.
Checks if the application redirects to arbitrary external domains.
"""
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from models import Finding
from scanner.core.requester import Requester

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
                    # We manually handle redirects to check the 'Location' header immediately
                    # allow_redirects=False prevents the library from following the redirect
                    response = self.requester.get(target_url, timeout=5, allow_redirects=False)
                    
                    is_vulnerable = False
                    
                    # Logic: 
                    # 1. Status code is a redirect (301, 302, 303, 307, 308)
                    # 2. Location header is present
                    # 3. Location header matches our payload domain
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                         location = response.headers.get("Location", "")
                         # Strict check: Location should start with or contain our target domain
                         if self.target_domain in location:
                             is_vulnerable = True
                    
                    # Fallback for meta-refresh (200 OK but redirects via HTML)
                    # This often requires parsing HTML, but basic string check can work for simple cases
                    if "http-equiv=\"refresh\"" in response.text.lower() and self.target_domain in response.text:
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
