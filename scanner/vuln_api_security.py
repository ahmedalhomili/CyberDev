from typing import List
from models import Finding
from scanner.requester import Requester

class APISecurityScanner:
    """
    Scanner for API Security (OWASP API Top 10).
    """
    def __init__(self):
        self.requester = Requester()

    def scan(self, url: str) -> List[Finding]:
        findings = []
        
        # Check for exposing internal info (Mass Assignment / Excessive Data Exposure)
        # e.g. /api/users returning 'is_admin': false, 'password_hash': '...'
        
        # Check for GraphQL
        if 'graphql' in url.lower():
             findings.append(Finding(
                title="GraphQL Endpoint Discovered",
                severity="INFO",
                description="GraphQL endpoint identified. Requires Introspection check.",
                location=url,
                recommendation="Ensure introspection is disabled in production.",
                cwe_reference="OWASP API8:2019"
            ))
            
        return findings
