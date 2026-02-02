"""
Rate Limiting and Brute Force Protection Scanner.
Actively tests for missing rate limiting by sending multiple requests.
"""
import logging
import time
from typing import List
from models import Finding
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class RateLimitScanner:
    """
    Scanner for Rate Limiting and Brute Force Protection.
    """
    def __init__(self):
        self.requester = Requester()
        self.test_count = 15  # Number of rapid requests to send

    def scan(self, url: str) -> List[Finding]:
        findings = []
        
        try:
            # 1. Check for Rate Limit Headers (Passive)
            initial_res = self.requester.get(url, timeout=5)
            headers = initial_res.headers
            
            has_rate_limit_headers = any(
                h for h in headers if 'ratelimit' in h.lower() or 
                'x-rate' in h.lower() or 
                'retry-after' in h.lower()
            )
            
            # 2. Active Test: Send rapid requests
            success_count = 0
            blocked = False
            start_time = time.time()
            
            for i in range(self.test_count):
                try:
                    response = self.requester.get(url, timeout=5)
                    
                    # Check if we got rate limited (429 or 503 often)
                    if response.status_code in [429, 503]:
                        blocked = True
                        break
                    elif response.status_code == 200:
                        success_count += 1
                        
                except Exception:
                    pass
            
            elapsed_time = time.time() - start_time
            
            # Analysis
            if not blocked and success_count >= self.test_count - 2:
                # All or nearly all requests succeeded without rate limiting
                severity = "HIGH" if not has_rate_limit_headers else "MEDIUM"
                
                findings.append(Finding(
                    title="Missing Rate Limiting Protection",
                    severity=severity,
                    description=f"The application accepted {success_count}/{self.test_count} rapid requests without rate limiting. This makes it vulnerable to brute force attacks, credential stuffing, and DoS.",
                    location=f"URL: {url}",
                    recommendation="Implement rate limiting per IP/user. Use 429 status code and Retry-After header. Consider using CAPTCHA for sensitive endpoints.",
                    cwe_reference="CWE-799",
                    confidence="High" if success_count == self.test_count else "Medium"
                ))
            elif blocked:
                # Good! Rate limiting is working
                logger.info(f"Rate limiting detected on {url} - protection is active")
            
            # 3. Check for missing security headers
            if not has_rate_limit_headers and not blocked:
                findings.append(Finding(
                    title="Missing Rate Limit Headers",
                    severity="LOW",
                    description="The application does not expose rate limit information via headers (X-RateLimit-Limit, X-RateLimit-Remaining). This makes it harder for legitimate clients to handle rate limits gracefully.",
                    location=f"URL: {url}",
                    recommendation="Add X-RateLimit-* headers to inform clients about rate limits.",
                    cwe_reference="CWE-799"
                ))
                
        except Exception as e:
            logger.debug(f"Error scanning rate limiting for {url}: {e}")
            
        return findings
