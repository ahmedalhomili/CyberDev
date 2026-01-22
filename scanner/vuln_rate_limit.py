from typing import List
from models import Finding
from scanner.requester import Requester

class RateLimitScanner:
    """
    Scanner for Rate Limiting and Brute Force Protection.
    """
    def __init__(self):
        self.requester = Requester()

    def scan(self, url: str) -> List[Finding]:
        findings = []
        # Active Check: Send slightly rapid requests to see if 429 is triggered or headers change
        # NOTE: Be careful not to DoS. 
        # Check for X-RateLimit headers
        
        try:
             res = self.requester.get(url)
             headers = res.headers
             if any(h for h in headers if 'ratelimit' in h.lower()):
                 # This is actually good!
                 pass
             else:
                 # Passive indicator of missing rate limiting info (not definitive proof of vuln)
                 pass
        except:
            pass
            
        return findings
