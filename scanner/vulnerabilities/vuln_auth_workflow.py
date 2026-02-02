import requests
import re
from typing import List, Dict
from models import Finding
from scanner.core.requester import Requester

class AuthScanner:
    """
    Scanner for Authentication, Session Management, CSRF, and IDOR.
    """
    def __init__(self):
        self.requester = Requester()

    def scan(self, url: str, response: requests.Response) -> List[Finding]:
        findings = []
        findings.extend(self.check_session_cookies(response))
        findings.extend(self.check_csrf(response))
        findings.extend(self.check_idor_indicators(url))
        return findings

    def check_session_cookies(self, response: requests.Response) -> List[Finding]:
        """Check for missing secure flags in cookies."""
        findings = []
        for cookie in response.cookies:
            # Note: requests.cookies.RequestsCookieJar stores cookies. 
            # We need to access the cookie object attributes if possible, or check headers.
            # Simpler to check Set-Cookie headers for flags.
            pass
        
        # improved check via headers
        set_cookie_headers = [v for k, v in response.headers.items() if k.lower() == 'set-cookie']
        for header in set_cookie_headers:
            if 'session' in header.lower() or 'id' in header.lower() or 'token' in header.lower():
                if 'HttpOnly' not in header:
                    findings.append(Finding(
                        title="Cookie Missing HttpOnly Flag",
                        severity="MEDIUM",
                        description=f"Session cookie found without HttpOnly flag: {header[:50]}...",
                        location="Headers (Set-Cookie)",
                        recommendation="Set the HttpOnly flag to prevent access via JavaScript.",
                        cwe_reference="CWE-1004"
                    ))
                if 'Secure' not in header and 'https' in response.url:
                    findings.append(Finding(
                        title="Cookie Missing Secure Flag",
                        severity="MEDIUM",
                        description=f"Session cookie found without Secure flag over HTTPS.",
                        location="Headers (Set-Cookie)",
                        recommendation="Set the Secure flag to ensure cookie is only sent over HTTPS.",
                        cwe_reference="CWE-614"
                    ))
                if 'SameSite' not in header:
                    findings.append(Finding(
                        title="Cookie Missing SameSite Attribute",
                        severity="LOW",
                        description="Cookie is missing SameSite attribute, increasing CSRF risk.",
                        location="Headers (Set-Cookie)",
                        recommendation="Set SameSite to 'Strict' or 'Lax'.",
                        cwe_reference="CWE-1275"
                    ))
        return findings

    def check_csrf(self, response: requests.Response) -> List[Finding]:
        """Analyze forms for CSRF tokens."""
        findings = []
        content = response.text
        # Naive regex for forms
        forms = re.findall(r'<form.*?>.*?</form>', content, re.DOTALL | re.IGNORECASE)
        for form in forms:
            if 'method="post"' in form.lower() or "method='post'" in form.lower():
                # Check for common token names
                if not any(token in form.lower() for token in ['csrf', 'xsrf', 'token', '_token', 'authenticity_token']):
                    findings.append(Finding(
                        title="Potential CSRF Vulnerability",
                        severity="HIGH",
                        description="HTML form detected without anti-CSRF token.",
                        location="HTML Body",
                        recommendation="Implement anti-CSRF tokens for all state-changing operations.",
                        cwe_reference="CWE-352"
                    ))
        return findings

    def check_idor_indicators(self, url: str) -> List[Finding]:
        """Check URL for IDOR patterns."""
        findings = []
        # Pattern for numeric IDs in query params or path
        # e.g. /user/123 or ?id=123
        if re.search(r'[?&](id|user|account|order|profile)=\d+', url, re.IGNORECASE) or \
           re.search(r'/(user|profile|order|invoice)/\d+', url, re.IGNORECASE):
            findings.append(Finding(
                title="Potential IDOR Parameter Detected",
                severity="MEDIUM",
                description=f"URL contains numeric ID pattern which may be vulnerable to Insecure Direct Object Reference: {url}",
                location=url,
                recommendation="Use indirect reference maps or GUIDs instead of sequential numeric IDs. Enforce strict server-side authorization checks.",
                cwe_reference="CWE-639"
            ))
        return findings
