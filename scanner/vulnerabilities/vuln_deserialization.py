"""
Insecure Deserialization Scanner.
Passively detects serialized objects in Cookies and Parameters.
"""
import logging
import re
from urllib.parse import urlparse, parse_qs
from typing import List
from models import Finding
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class DeserializationScanner:
    """Scanner for Insecure Deserialization patterns."""

    def __init__(self):
        self.requester = Requester()
        self.signatures = [
            # Java Serialization: starts with 0xAC ED 00 05 -> Base64: rO0AB
            (re.compile(r'rO0AB'), "Java Serialized Object"),
            # Python Pickle: manual checks often look for specific opcodes but generic base64 often starts with gA
            # or complex heuristics. We look for 'gAS' (protocol 4?) or 'cos' (system) often base64'd
            (re.compile(r'gAS[a-zA-Z0-9]{5,}'), "Python Pickle"),
            # PHP Serialization: O:4:"User":...
            (re.compile(r'O:[0-9]+:'), "PHP Serialized Object"),
            # .NET ViewState (generic check for very long base64 starting with /wEP...)
            (re.compile(r'^/wEP[a-zA-Z0-9+/=]{20,}'), ".NET ViewState (Potential)")
        ]

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for patterns indicating dangerous serialization usage.
        """
        findings = []
        try:
            # We need to look at what the server *sets* (Cookies) and also what might be in the URL.
            # Ideally we'd also check POST bodies, but this is a GET based scan mostly.
            response = self.requester.get(url)
            
            check_targets = []
            
            # 1. Cookies
            for cookie in response.cookies:
                check_targets.append((f"Cookie: {cookie.name}", cookie.value))
                
            # 2. URL Params
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for k, v in params.items():
                for val in v:
                    check_targets.append((f"Param: {k}", val))

            # Analysis
            for location, value in check_targets:
                if not value: continue
                
                value_str = str(value)
                for pattern, label in self.signatures:
                    if pattern.search(value_str):
                        severity = "HIGH" if "Java" in label or "Pickle" in label else "MEDIUM"
                        
                        findings.append(Finding(
                            title=f"Insecure Deserialization Indicator ({label})",
                            severity=severity,
                            description=f"A pattern matching {label} was found in {location}. Deserializing untrusted data can lead to Remote Code Execution.",
                            location=f"URL: {url} | {location}",
                            recommendation="Avoid accepting serialized objects from users. Use safe data formats like JSON. If necessary, sign the data with an integrity check.",
                            cwe_reference="CWE-502"
                        ))

        except Exception as e:
            logger.debug(f"Error scanning Deserialization for {url}: {e}")

        return findings
