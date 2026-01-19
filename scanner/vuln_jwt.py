"""
JWT Security Scanner.
Analyzes JSON Web Tokens for configuration weaknesses.
"""
import logging
import base64
import json
import re
from typing import List
from models import Finding
from scanner.requester import Requester

logger = logging.getLogger(__name__)

class JWTScanner:
    """Scanner for JWT vulnerabilities."""

    def __init__(self):
        self.requester = Requester()
        # Basic regex to find potential JWTs: header.payload.signature
        self.jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+')

    def _decode_segment(self, segment):
        try:
            # Pad if necessary
            padding = len(segment) % 4
            if padding:
                segment += '=' * (4 - padding)
            return json.loads(base64.urlsafe_b64decode(segment))
        except Exception:
            return None

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL's cookies and headers for insecure JWTs.
        """
        findings = []
        try:
            response = self.requester.get(url)
            
            # Gather potential tokens from Cookies and Headers
            candidates = []
            
            # Check Cookies
            for cookie in response.cookies:
                if self.jwt_pattern.match(str(cookie.value)):
                    candidates.append((f"Cookie: {cookie.name}", cookie.value))
            
            # Check Authorization Header (if present in specific flows, rare in passive initial scan but good to check)
            auth_header = response.headers.get("Authorization", "")
            if "Bearer " in auth_header:
                token = auth_header.split("Bearer ")[1]
                if self.jwt_pattern.match(token):
                    candidates.append(("Authorization Header", token))

            for location, token in candidates:
                parts = token.split('.')
                if len(parts) != 3:
                    continue
                
                header_json = self._decode_segment(parts[0])
                payload_json = self._decode_segment(parts[1])
                
                if header_json:
                    # Check Algorithm
                    alg = header_json.get('alg', 'none').lower()
                    if alg == 'none':
                        findings.append(Finding(
                            title="Insecure JWT: Algorithm 'None'",
                            severity="CRITICAL",
                            description="The JWT allows the 'none' algorithm, which may allow attackers to forge tokens without a signature.",
                            location=f"{location}",
                            recommendation="Disable the 'none' algorithm in your JWT library configuration.",
                            cwe_reference="CWE-327"
                        ))
                    elif alg == 'hs256':
                        # Weakness warning (brute force potential if secret is weak)
                        pass 

                if payload_json:
                    # Check Expiration
                    if 'exp' not in payload_json:
                        findings.append(Finding(
                            title="Insecure JWT: Missing Expiration",
                            severity="MEDIUM",
                            description="The JWT does not appear to have an expiration time ('exp' claim), meaning it may never expire.",
                            location=f"{location}",
                            recommendation="Always include an 'exp' claim in JWTs to limit the window of opportunity for stolen tokens.",
                            cwe_reference="CWE-613"
                        ))

        except Exception as e:
            logger.debug(f"Error scanning JWT for {url}: {e}")

        return findings
