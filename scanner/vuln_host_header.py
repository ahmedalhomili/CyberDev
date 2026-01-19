"""
Host Header Injection Scanner.
Checks if the application trusts the Host header for generating links or redirects.
"""
import logging
from typing import List
from models import Finding
from scanner.requester import Requester

logger = logging.getLogger(__name__)

class HostHeaderScanner:
    """Scanner for Host Header Injection vulnerabilities."""

    def __init__(self):
        self.requester = Requester()
        self.evil_host = "evil.com"

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for Host Header vulnerabilities.
        """
        findings = []
        
        try:
            # 1. Basic Host Header Injection
            # We must use a separate session or careful request to not break the library's SSL logic
            # Many libraries force the Host header based on the URL. We explicitly override it.
            headers = {"Host": self.evil_host}
            
            # Using verify=False because changing Host header usually breaks SSL cert validation
            response = self.requester.get(url, headers=headers)
            
            vuln_detected = False
            evidence = ""

            # Check for generic reflection in body (e.g. absolute links)
            if f"http://{self.evil_host}" in response.text or f"https://{self.evil_host}" in response.text:
                vuln_detected = True
                evidence = "The injected Host header was reflected in absolute links/scripts in the response body."

            # Check Location header in redirects
            if response.history:
                for hist in response.history:
                    if "Location" in hist.headers and self.evil_host in hist.headers["Location"]:
                        vuln_detected = True
                        evidence = "The injected Host header was used to construct a Location redirect header."
                        break
            elif "Location" in response.headers and self.evil_host in response.headers["Location"]:
                vuln_detected = True
                evidence = "The injected Host header was used to construct a Location redirect header."

            if vuln_detected:
                findings.append(Finding(
                    title="Host Header Injection",
                    severity="MEDIUM",
                    description=f"The application appears to trust the 'Host' HTTP header to generate links or redirects. {evidence}",
                    location=f"URL: {url} | Header: Host: {self.evil_host}",
                    recommendation="Validate the Host header against a whitelist of allowed domains. Do not trust the Host header for constructing URL links.",
                    cwe_reference="CWE-601"
                ))
            
            # 2. X-Forwarded-Host Injection (often accepted by proxies)
            headers_xfh = {"X-Forwarded-Host": self.evil_host}
            response_xfh = self.requester.get(url, headers=headers_xfh)
            
            if f"http://{self.evil_host}" in response_xfh.text or f"https://{self.evil_host}" in response_xfh.text:
                 findings.append(Finding(
                    title="Host Header Injection (via X-Forwarded-Host)",
                    severity="MEDIUM",
                    description="The application uses the 'X-Forwarded-Host' header to generate links/content without validation.",
                    location=f"URL: {url} | Header: X-Forwarded-Host: {self.evil_host}",
                    recommendation="Configure your web server/proxy to ignore X-Forwarded-Host unless specifically required and validated.",
                    cwe_reference="CWE-601"
                ))

        except Exception as e:
            logger.debug(f"Error scanning Host Header for {url}: {e}")

        return findings
