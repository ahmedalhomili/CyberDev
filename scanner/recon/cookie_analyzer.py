"""
Cookie Security Analysis Module.
Passive analysis of HTTP cookies for security flag compliance.
"""
import re
import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs
from models import Finding
from scanner.core.base_check import SecurityCheck

logger = logging.getLogger(__name__)


class CookieAnalyzer(SecurityCheck):
    """Analyzes HTTP response cookies for security best practices."""

    name = "Cookie Security Analysis"
    check_type = "passive"
    category = "Cookie Security"

    # Known session cookie name patterns
    SESSION_PATTERNS = [
        "sessionid", "session_id", "phpsessid", "jsessionid",
        "asp.net_sessionid", "sid", "sess", "token", "auth",
        "csrftoken", "csrf_token",
    ]

    def run(self, target: str, **kwargs) -> List[Finding]:
        """
        Run cookie security analysis.

        Args:
            target: Target URL
            **kwargs: Must include 'headers' dict with response headers

        Returns:
            List of Finding objects
        """
        headers = kwargs.get('headers', {})
        return self.analyze(headers, target)

    def analyze(self, response_headers: Dict[str, str], url: str) -> List[Finding]:
        """
        Analyze Set-Cookie headers from HTTP response.

        Args:
            response_headers: HTTP response headers dict
            url: The target URL (for session-in-URL check)

        Returns:
            List of cookie security findings
        """
        findings = []
        cookies = self._parse_set_cookie_headers(response_headers)

        for cookie in cookies:
            name = cookie.get('name', 'Unknown')
            is_session = self._is_session_cookie(name)

            # Check Secure flag
            if not cookie.get('secure'):
                severity = "MEDIUM" if is_session else "LOW"
                findings.append(Finding(
                    title="Cookie Missing Secure Flag",
                    severity=severity,
                    description=(
                        f"Cookie '{name}' is set without the Secure flag. "
                        "This means the cookie can be transmitted over unencrypted HTTP connections, "
                        "potentially exposing it to interception."
                    ),
                    location=f"Set-Cookie: {name}",
                    recommendation="Add the Secure flag to all cookies: Set-Cookie: name=value; Secure",
                    cwe_reference="CWE-614",
                    confidence="High",
                    category="Cookie Security",
                    evidence=f"Set-Cookie: {cookie.get('raw', name + '=...')}",
                ))

            # Check HttpOnly flag
            if not cookie.get('httponly') and is_session:
                findings.append(Finding(
                    title="Session Cookie Missing HttpOnly Flag",
                    severity="LOW",
                    description=(
                        f"Session cookie '{name}' is set without the HttpOnly flag. "
                        "This allows client-side JavaScript to access the cookie, "
                        "increasing the risk of session hijacking via XSS."
                    ),
                    location=f"Set-Cookie: {name}",
                    recommendation="Add the HttpOnly flag: Set-Cookie: name=value; HttpOnly",
                    cwe_reference="CWE-1004",
                    confidence="High",
                    category="Cookie Security",
                    evidence=f"Set-Cookie: {cookie.get('raw', name + '=...')}",
                ))

            # Check SameSite attribute
            samesite = cookie.get('samesite', '').lower()
            if samesite == 'none' and not cookie.get('secure'):
                findings.append(Finding(
                    title="Cookie SameSite=None Without Secure Flag",
                    severity="MEDIUM",
                    description=(
                        f"Cookie '{name}' has SameSite=None but lacks the Secure flag. "
                        "Modern browsers reject SameSite=None cookies without Secure. "
                        "This may also expose the cookie to cross-site request attacks."
                    ),
                    location=f"Set-Cookie: {name}",
                    recommendation="When using SameSite=None, always include the Secure flag.",
                    cwe_reference="CWE-352",
                    confidence="High",
                    category="Cookie Security",
                    evidence=f"SameSite={samesite}; Secure flag missing",
                ))
            elif not samesite and is_session:
                findings.append(Finding(
                    title="Session Cookie Missing SameSite Attribute",
                    severity="LOW",
                    description=(
                        f"Session cookie '{name}' does not set the SameSite attribute. "
                        "While browsers default to Lax, explicitly setting SameSite is recommended."
                    ),
                    location=f"Set-Cookie: {name}",
                    recommendation="Set SameSite=Lax or SameSite=Strict on session cookies.",
                    cwe_reference="CWE-352",
                    confidence="Medium",
                    category="Cookie Security",
                ))

        # Check for session ID in URL parameters
        findings.extend(self._check_session_in_url(url))

        return findings

    def _parse_set_cookie_headers(self, headers: Dict[str, str]) -> List[Dict]:
        """Parse Set-Cookie headers into structured cookie data."""
        cookies = []

        # Collect all Set-Cookie values
        set_cookie_values = []
        for key, value in headers.items():
            if key.lower() == 'set-cookie':
                set_cookie_values.append(value)

        for raw_cookie in set_cookie_values:
            cookie = {'raw': raw_cookie}
            parts = raw_cookie.split(';')

            # First part is name=value
            if parts:
                name_value = parts[0].strip()
                if '=' in name_value:
                    cookie['name'] = name_value.split('=', 1)[0].strip()
                    cookie['value'] = name_value.split('=', 1)[1].strip()
                else:
                    cookie['name'] = name_value
                    cookie['value'] = ''

            # Parse flags
            flags_str = raw_cookie.lower()
            cookie['secure'] = 'secure' in flags_str
            cookie['httponly'] = 'httponly' in flags_str

            # Parse SameSite
            samesite_match = re.search(r'samesite\s*=\s*(\w+)', flags_str)
            cookie['samesite'] = samesite_match.group(1) if samesite_match else ''

            cookies.append(cookie)

        return cookies

    def _is_session_cookie(self, name: str) -> bool:
        """Check if a cookie name matches known session cookie patterns."""
        name_lower = name.lower()
        return any(pattern in name_lower for pattern in self.SESSION_PATTERNS)

    def _check_session_in_url(self, url: str) -> List[Finding]:
        """Check if session identifiers appear in URL query parameters."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        session_params = [
            p for p in params
            if any(s in p.lower() for s in ['session', 'sid', 'token', 'jsessionid', 'phpsessid'])
        ]

        if session_params:
            findings.append(Finding(
                title="Session Identifier in URL",
                severity="MEDIUM",
                description=(
                    f"Session-related parameter(s) found in URL query string: {', '.join(session_params)}. "
                    "Session identifiers in URLs can be leaked through browser history, "
                    "referrer headers, and server logs."
                ),
                location=f"URL: {url}",
                recommendation="Use cookies instead of URL parameters for session management.",
                cwe_reference="CWE-598",
                confidence="Medium",
                category="Cookie Security",
                evidence=f"URL contains: {', '.join(session_params)}",
            ))

        return findings
