"""
CORS (Cross-Origin Resource Sharing) policy analysis module.
Detects CORS misconfigurations and security risks via passive header
inspection and active origin reflection testing.
"""
import logging
import requests
import urllib3
from typing import List, Optional, Dict
from models import Finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class CORSAnalyzer:
    """Analyzes CORS configuration in HTTP response headers."""

    def __init__(self, headers: Dict[str, str], url: str = None):
        """
        Initialize with HTTP response headers and optional target URL.

        Args:
            headers: Dictionary of HTTP response headers
            url: Target URL for active CORS testing (optional)
        """
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.url = url
        self.findings: List[Finding] = []

    def check_allow_origin(self) -> Optional[Finding]:
        """
        Analyze Access-Control-Allow-Origin header.
        """
        acao = self.headers.get('access-control-allow-origin')
        acac = self.headers.get('access-control-allow-credentials', 'false').lower()

        if not acao:
            # CORS headers not configured - may be intentional
            return None

        if acao == '*':
            # Wildcard origin detected
            if acac == 'true':
                return Finding(
                    title='Misconfigured CORS: Wildcard with Credentials',
                    severity='LOW',
                    description='Access-Control-Allow-Origin is set to * while '
                               'Access-Control-Allow-Credentials is true. '
                               'Browsers will block this request, so it is not directly exploitable, but indicates a configuration error.',
                    location='CORS Headers',
                    recommendation='Remove Access-Control-Allow-Credentials: true OR '
                                  'remove wildcard and specify exact origins',
                    cwe_reference='CWE-942',
                    confidence='High',
                    category='CORS',
                )
            else:
                return Finding(
                    title='Wildcard CORS Origin (Best Practice)',
                    severity='LOW',
                    description='Access-Control-Allow-Origin: * allows any origin to access resources. '
                               'Common for public APIs, but verify this is intended.',
                    location='CORS Configuration',
                    recommendation='Specify allowed origins explicitly if this is not a public API',
                    confidence='High',
                    category='CORS',
                )

        return None

    def check_allow_methods(self) -> Optional[Finding]:
        """
        Analyze Access-Control-Allow-Methods header.
        """
        acam = self.headers.get('access-control-allow-methods', '')

        if not acam:
            return None

        methods = [m.strip().upper() for m in acam.split(',')]

        # Check for dangerous method combinations
        dangerous_methods = {'PUT', 'DELETE', 'PATCH'}
        if any(m in methods for m in dangerous_methods):
            acao = self.headers.get('access-control-allow-origin', '')

            if acao == '*':
                return Finding(
                    title='Potential Risk: Wildcard CORS with Dangerous Methods',
                    severity='MEDIUM',
                    description=f'Wildcard CORS combined with methods: {", ".join(methods)}. '
                               'Any origin can trigger these methods. Verify if additional authentication is enforced.',
                    location='CORS Headers',
                    recommendation='Restrict allowed methods to safe operations (GET, HEAD, OPTIONS)',
                    category='CORS',
                )
            else:
                return Finding(
                    title='Unusual CORS Methods',
                    severity='MEDIUM',
                    description=f'Cross-origin requests allowed for: {", ".join(methods)}. '
                               'Verify this is intentional.',
                    location='CORS Headers',
                    recommendation='Restrict to necessary methods only',
                    category='CORS',
                )

        return None

    def check_allow_headers(self) -> Optional[Finding]:
        """
        Analyze Access-Control-Allow-Headers for security issues.
        """
        acah = self.headers.get('access-control-allow-headers', '')

        if acah == '*':
            return Finding(
                title='Wildcard in Allow-Headers',
                severity='MEDIUM',
                description='Access-Control-Allow-Headers: * allows any header. '
                           'May enable bypassing security mechanisms.',
                location='CORS Configuration',
                recommendation='Specify only necessary headers explicitly',
                category='CORS',
            )

        return None

    def active_check_origin_reflection(self) -> Optional[Finding]:
        """
        Actively test if the server reflects arbitrary Origin headers.
        Sends a request with Origin: https://evil.com and checks if
        the server echoes it back in Access-Control-Allow-Origin.
        """
        if not self.url:
            return None

        try:
            test_origin = "https://evil.com"
            resp = requests.get(
                self.url,
                headers={"Origin": test_origin},
                timeout=10,
                verify=False,
                allow_redirects=True,
            )

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if test_origin in acao:
                evidence = f"ACAO: {acao} | ACAC: {acac} | Origin sent: {test_origin}"

                if acac == "true":
                    return Finding(
                        title="CORS Origin Reflection with Credentials",
                        severity="HIGH",
                        description="The server reflects arbitrary Origin headers in Access-Control-Allow-Origin "
                                   "while Access-Control-Allow-Credentials is true. This allows any malicious "
                                   "website to make authenticated cross-origin requests and steal sensitive data.",
                        location=f"CORS Active Test: {self.url}",
                        recommendation="Implement a strict allowlist of trusted origins instead of reflecting "
                                      "the Origin header. Remove Access-Control-Allow-Credentials if not needed.",
                        cwe_reference="CWE-942",
                        confidence="High",
                        category="CORS",
                        evidence=evidence,
                    )
                else:
                    return Finding(
                        title="CORS Origin Reflection (Without Credentials)",
                        severity="MEDIUM",
                        description="The server reflects arbitrary Origin headers in Access-Control-Allow-Origin. "
                                   "While credentials are not included, this may allow data theft from "
                                   "unauthenticated endpoints.",
                        location=f"CORS Active Test: {self.url}",
                        recommendation="Implement a strict allowlist of trusted origins instead of reflecting "
                                      "the Origin header.",
                        cwe_reference="CWE-942",
                        confidence="High",
                        category="CORS",
                        evidence=evidence,
                    )

        except Exception as e:
            logger.debug(f"Active CORS test failed: {e}")

        return None

    def analyze_all(self) -> List[Finding]:
        """
        Run all CORS analyses (passive + active).

        Returns:
            List of CORS-related Finding objects
        """
        self.findings = []

        analyses = [
            self.check_allow_origin(),
            self.check_allow_methods(),
            self.check_allow_headers(),
            self.active_check_origin_reflection(),
        ]

        self.findings = [f for f in analyses if f is not None]

        return self.findings
