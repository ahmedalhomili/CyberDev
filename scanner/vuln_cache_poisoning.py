"""
Web Cache Poisoning Scanner.
Analyzes response headers for cache configuration weaknesses.
"""
import logging
from typing import List
from models import Finding
from scanner.requester import Requester

logger = logging.getLogger(__name__)

class CachePoisoningScanner:
    """Scanner for Web Cache Poisoning indicators."""

    def __init__(self):
        self.requester = Requester()

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for Cache Poisoning risks.
        """
        findings = []
        try:
            response = self.requester.get(url)
            headers = response.headers
            
            # Indicators that the page is cached
            cache_indicators = ["X-Cache", "CF-Cache-Status", "X-Drupal-Cache", "Via", "Age"]
            is_cached = any(h in headers for h in cache_indicators)
            
            if is_cached:
                # 1. Check if unkeyed inputs might be reflected (Passive heuristic)
                # Hard to fully automate safely without risking poisoning real users, 
                # so we stick to configuration analysis.
                
                # 2. Check Cache-Control
                cc = headers.get("Cache-Control", "").lower()
                
                if not cc:
                     findings.append(Finding(
                        title="Missing Cache-Control Header",
                        severity="LOW",
                        description="The application uses caching (detected via other headers) but does not define a Cache-Control policy.",
                        location=f"URL: {url}",
                        recommendation="Define explicit Cache-Control headers to prevent caching of sensitive data.",
                        cwe_reference="CWE-524"
                    ))
                elif "public" in cc and "no-cache" not in cc:
                    # If it's public, verify if specific security headers are missing (like Vary)
                    if "Vary" not in headers:
                         findings.append(Finding(
                            title="Weak Caching Policy (Missing Vary Header)",
                            severity="MEDIUM",
                            description="The resource is cached publicly but does not specify a 'Vary' header. This might increase the risk of serving content to the wrong user if headers differ.",
                            location=f"URL: {url}",
                            recommendation="Use the 'Vary' header to instruct the cache to distinguish requests based on key headers (e.g., Accept-Encoding, User-Agent).",
                            cwe_reference="CWE-524"
                        ))

        except Exception as e:
            logger.debug(f"Error scanning Cache Poisoning for {url}: {e}")

        return findings
