"""
CORS (Cross-Origin Resource Sharing) policy analysis module.
Detects CORS misconfigurations and security risks.
"""
from typing import List, Optional, Dict
from models import Finding

class CORSAnalyzer:
    """Analyzes CORS configuration in HTTP response headers."""
    
    def __init__(self, headers: Dict[str, str]):
        """
        Initialize with HTTP response headers.
        
        Args:
            headers: Dictionary of HTTP response headers
        """
        self.headers = {k.lower(): v for k, v in headers.items()}
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
                    confidence='High'
                )
            else:
                return Finding(
                    title='Wildcard CORS Origin (Best Practice)',
                    severity='LOW',
                    description='Access-Control-Allow-Origin: * allows any origin to access resources. '
                               'Common for public APIs, but verify this is intended.',
                    location='CORS Configuration',
                    recommendation='Specify allowed origins explicitly if this is not a public API',
                    confidence='High'
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
                    recommendation='Restrict allowed methods to safe operations (GET, HEAD, OPTIONS)'
                )
            else:
                return Finding(
                    title='Unusual CORS Methods',
                    severity='MEDIUM',
                    description=f'Cross-origin requests allowed for: {", ".join(methods)}. '
                               'Verify this is intentional.',
                    location='CORS Headers',
                    recommendation='Restrict to necessary methods only'
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
                recommendation='Specify only necessary headers explicitly'
            )
        
        return None
    
    def analyze_all(self) -> List[Finding]:
        """
        Run all CORS analyses.
        
        Returns:
            List of CORS-related Finding objects
        """
        self.findings = []
        
        analyses = [
            self.check_allow_origin(),
            self.check_allow_methods(),
            self.check_allow_headers()
        ]
        
        self.findings = [f for f in analyses if f is not None]
        
        return self.findings
