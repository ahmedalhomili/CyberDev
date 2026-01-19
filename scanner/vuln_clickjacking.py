"""
Clickjacking Vulnerability Scanner.
Checks for missing X-Frame-Options and CSP frame-ancestors.
"""
import logging
from typing import List
from models import Finding
from scanner.requester import Requester

logger = logging.getLogger(__name__)

class ClickjackingScanner:
    """Scanner for Clickjacking vulnerabilities."""

    def __init__(self):
        self.requester = Requester()

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for Clickjacking misconfigurations.
        """
        findings = []
        try:
            response = self.requester.get(url)
            headers = response.headers

            x_frame = headers.get("X-Frame-Options", "").upper()
            csp = headers.get("Content-Security-Policy", "")

            # Check logic
            vulnerable = True
            
            # X-Frame-Options check
            if x_frame in ["DENY", "SAMEORIGIN"]:
                vulnerable = False
                
            # CSP check (stronger than XFO)
            if "frame-ancestors" in csp:
                vulnerable = False

            if vulnerable:
                findings.append(Finding(
                    title="Clickjacking Vulnerability (Missing Anti-Framing)",
                    severity="MEDIUM",
                    description="The application does not enforce X-Frame-Options or CSP frame-ancestors, allowing it to be framed by malicious sites.",
                    location=f"URL: {url}",
                    recommendation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', and implement 'Content-Security-Policy: frame-ancestors 'self''.",
                    cwe_reference="CWE-1021"
                ))

        except Exception as e:
            logger.debug(f"Error scanning Clickjacking for {url}: {e}")

        return findings
