"""
Web Cache Poisoning Scanner.
Analyzes response headers for cache configuration weaknesses.
"""
import logging
from typing import List
from models import Finding
from scanner.core.requester import Requester

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
            # 1. Passive Check
            response = self.requester.get(url)
            findings.extend(self.check_cache_headers(response.headers, url))
            
            # 2. Active Check (X-Forwarded-Host)
            # We try to reflect a custom host header. If it's reflected AND cached, it's poisoning.
            poison_host = "vulnerable.com"
            headers = {"X-Forwarded-Host": poison_host}
            
            # Use a cachebuster to ensure we are testing a fresh request logic, 
            # though active poisoning relies on getting THIS response cached.
            # We assume if it reflects, it *could* be cached if headers allow.
            poison_response = self.requester.get(url, headers=headers)
            
            if poison_host in poison_response.text:
                # Reflected! Now is it cacheable?
                cache_headers = poison_response.headers
                is_cached_response = any(h in cache_headers for h in ["X-Cache", "CF-Cache-Status", "Age"])
                cc = cache_headers.get("Cache-Control", "").lower()
                
                # If reflected and explicitly cacheable (public) OR indicators show it was cached
                if is_cached_response or ("public" in cc and "no-cache" not in cc):
                     findings.append(Finding(
                        title="Web Cache Poisoning Risk (Reflected Header)",
                        severity="HIGH",
                        description=f"The application reflects the 'X-Forwarded-Host' header value ('{poison_host}') in the response, and the response appears to be cacheable. An attacker could poison the cache to serve malicious content to other users.",
                        location=f"URL: {url} | Header: X-Forwarded-Host",
                        recommendation="Disable support for X-Forwarded-Host or ensure it is not used to generate response content (links, imports) without validation. Ensure 'Vary: X-Forwarded-Host' is set if used.",
                        cwe_reference="CWE-444"
                    ))

            return findings
        except Exception as e:
            logger.error(f"Error checking cache poisoning: {e}")
            return findings

    def check_cache_headers(self, headers: dict, url: str = "Target") -> List[Finding]:
        findings = []
        
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
                        title="Cacheable Response Missing 'Vary' Header",
                        severity="MEDIUM",
                        description="Response is publicly cacheable but does not specify a 'Vary' header. This may increase risks of cache poisoning (e.g. unkeyed headers affecting stored response).",
                        location=f"Headers: {url}",
                        recommendation="Set 'Vary' header to include key inputs like 'User-Agent', 'Accept-Encoding', or custom headers used for content negotiation.",
                        cwe_reference="CWE-444"
                    ))

        return findings
