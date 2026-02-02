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
from scanner.core.requester import Requester

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

    def _encode_segment(self, data):
        """Encodes a dictionary segment to base64url string without padding."""
        try:
            json_str = json.dumps(data, separators=(",", ":"))
            return base64.urlsafe_b64encode(json_str.encode()).decode().rstrip("=")
        except Exception:
            return ""

    def _send_request(self, url, inj_type, inj_key, token):
        """Helper to send request with modified token."""
        try:
            if inj_type == "cookie":
                return self.requester.get(url, cookies={inj_key: token})
            else:
                # inj_key is likely "Authorization"
                return self.requester.get(url, headers={inj_key: f"Bearer {token}"})
        except Exception as e:
            logger.debug(f"Error sending active JWT request: {e}")
            return None

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL's cookies and headers for insecure JWTs.
        Includes passive checks (weak config) and active checks ('None' algorithm).
        """
        findings = []
        try:
            response = self.requester.get(url)
            
            # Gather potential tokens from Cookies and Headers
            # Store tuple: (location_desc, token_value, injection_type, injection_key)
            candidates = []
            
            # Check Cookies
            for cookie in response.cookies:
                if self.jwt_pattern.match(str(cookie.value)):
                    candidates.append((f"Cookie: {cookie.name}", cookie.value, "cookie", cookie.name))
            
            # Check Authorization Header
            auth_header = response.headers.get("Authorization", "")
            if "Bearer " in auth_header:
                token = auth_header.split("Bearer ")[1]
                if self.jwt_pattern.match(token):
                    candidates.append(("Authorization Header", token, "header", "Authorization"))

            seen_tokens = set()

            for location, token, inj_type, inj_key in candidates:
                if token in seen_tokens:
                    continue
                seen_tokens.add(token)

                parts = token.split('.')
                if len(parts) != 3:
                    continue
                
                header_json = self._decode_segment(parts[0])
                payload_json = self._decode_segment(parts[1])
                
                if not header_json or not payload_json:
                    continue

                # --- Passive Checks ---
                
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
                    # Info/Low severity - Weakness warning (brute force potential if secret is weak)
                    pass 

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

                # --- Active Checks ---
                # Attempt 'None' algorithm bypass active verification
                
                try:
                    # 1. Forge token with 'alg': 'none'
                    header_none = header_json.copy()
                    header_none['alg'] = 'none' # Try lowercase 'none'
                    
                    token_none = f"{self._encode_segment(header_none)}.{parts[1]}." # Signature empty
                    
                    # 2. Forge token with bad signature (Baseline for failure)
                    token_bad = f"{parts[0]}.{parts[1]}.invalidSig{parts[2][:5]}"

                    # Send Requests
                    res_bad = self._send_request(url, inj_type, inj_key, token_bad)
                    res_none = self._send_request(url, inj_type, inj_key, token_none)
                    
                    if res_bad and res_none:
                        if res_bad.status_code in [401, 403, 500] and res_none.status_code in [200, 201, 202, 302]:
                             findings.append(Finding(
                                title="JWT None Algorithm Bypass (Active Verification)",
                                severity="CRITICAL",
                                description="Active testing confirmed the server accepts JWTs signed with the 'none' algorithm.",
                                location=f"{location} (Active verification)",
                                recommendation="Immediately update JWT library and configuration to reject 'alg: none'.",
                                cwe_reference="CWE-327"
                            ))
                except Exception as e:
                    logger.debug(f"Active scanning failed for JWT: {e}")

        except Exception as e:
            logger.debug(f"Error scanning JWT for {url}: {e}")

        return findings
