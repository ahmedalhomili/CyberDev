"""
Security headers analysis module.
Validates and scores security header configurations.
"""
from typing import List, Dict, Optional
from models import Finding
import re

class HeadersAnalyzer:
    """Analyzes security-related HTTP response headers."""
    
    def __init__(self, headers: Dict[str, str]):
        """
        Initialize with raw HTTP headers.
        
        Args:
            headers: Dictionary of HTTP response headers
        """
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.findings: List[Finding] = []
    
    def analyze_hsts(self) -> Optional[Finding]:
        """
        Analyze HTTP Strict-Transport-Security header (RFC 6797).
        """
        hsts_header = self.headers.get('strict-transport-security')
        
        if not hsts_header:
            return Finding(
                title='Missing HSTS Header',
                severity='HIGH',
                description='Strict-Transport-Security header not found. '
                           'This allows MITM attacks by forcing HTTP downgrade.',
                location='HTTP Response Headers',
                recommendation='Add: Strict-Transport-Security: max-age=31536000; '
                              'includeSubDomains; preload',
                cwe_reference='CWE-295'
            )
        
        # Parse HSTS header
        max_age_match = re.search(r'max-age=(\d+)', hsts_header)
        has_subdomains = 'includesubdomains' in hsts_header.lower()
        
        if not max_age_match:
            return Finding(
                title='Malformed HSTS Header',
                severity='MEDIUM',
                description='HSTS header present but max-age not specified.',
                location='Strict-Transport-Security Header',
                recommendation='Ensure max-age is set to a reasonable value (>=31536000)'
            )
        
        max_age = int(max_age_match.group(1))
        if max_age < 31536000:
            return Finding(
                title='Low HSTS max-age',
                severity='MEDIUM',
                description=f'HSTS max-age is {max_age} seconds. '
                           'Recommended minimum is 31536000 (1 year).',
                location='Strict-Transport-Security Header',
                recommendation='Increase max-age to at least 31536000'
            )
        
        if not has_subdomains:
            return Finding(
                title='HSTS Missing includeSubDomains',
                severity='LOW',
                description='HSTS header lacks includeSubDomains directive.',
                location='Strict-Transport-Security Header',
                recommendation='Add includeSubDomains to protect subdomains: '
                              'Strict-Transport-Security: max-age=31536000; includeSubDomains'
            )
        
        return None  # HSTS is properly configured
    
    def analyze_csp(self) -> Optional[Finding]:
        """
        Analyze Content-Security-Policy header structure.
        """
        csp_header = self.headers.get('content-security-policy')
        
        if not csp_header:
            return Finding(
                title='Missing Content-Security-Policy',
                severity='MEDIUM',
                description='CSP header not found. Site vulnerable to XSS attacks.',
                location='HTTP Response Headers',
                recommendation='Implement CSP: Content-Security-Policy: '
                              'default-src \'self\'; script-src \'self\'; style-src \'self\'',
                cwe_reference='CWE-79'
            )
        
        # Check for unsafe directives
        if "'unsafe-inline'" in csp_header.lower():
            return Finding(
                title='CSP Contains unsafe-inline',
                severity='HIGH',
                description='Content-Security-Policy uses \'unsafe-inline\', '
                           'which significantly weakens XSS protection.',
                location='Content-Security-Policy Header',
                recommendation='Remove \'unsafe-inline\' and use nonces or hashes instead'
            )
        
        if "'unsafe-eval'" in csp_header.lower():
            return Finding(
                title='CSP Contains unsafe-eval',
                severity='MEDIUM',
                description='CSP includes \'unsafe-eval\', allowing eval() and similar.',
                location='Content-Security-Policy Header',
                recommendation='Remove \'unsafe-eval\' from script-src directive'
            )
        
        return None
    
    def analyze_x_frame_options(self) -> Optional[Finding]:
        """
        Analyze X-Frame-Options header for clickjacking protection.
        """
        xfo_header = self.headers.get('x-frame-options')
        
        if not xfo_header:
            # Check if CSP frame-ancestors is present as it supersedes X-Frame-Options
            csp = self.headers.get('content-security-policy', '')
            if 'frame-ancestors' in csp:
                return None

            return Finding(
                title='Missing X-Frame-Options Header',
                severity='MEDIUM',
                description='X-Frame-Options not set. Site vulnerable to clickjacking attacks.',
                location='HTTP Response Headers',
                recommendation='Add X-Frame-Options: SAMEORIGIN or DENY',
                cwe_reference='CWE-1021'
            )
        
        valid_values = ['DENY', 'SAMEORIGIN', 'ALLOW-FROM']
        if not any(val in xfo_header.upper() for val in valid_values):
            return Finding(
                title='Invalid X-Frame-Options Value',
                severity='HIGH',
                description=f'X-Frame-Options has invalid value: {xfo_header}',
                location='X-Frame-Options Header',
                recommendation='Use DENY or SAMEORIGIN'
            )
        
        return None
    
    def analyze_x_content_type_options(self) -> Optional[Finding]:
        """
        Analyze X-Content-Type-Options for MIME-sniffing protection.
        """
        xcto_header = self.headers.get('x-content-type-options', '').lower()
        
        if not xcto_header:
            return Finding(
                title='Missing X-Content-Type-Options',
                severity='LOW',
                description='X-Content-Type-Options not set. Browsers may sniff MIME types.',
                location='HTTP Response Headers',
                recommendation='Add: X-Content-Type-Options: nosniff'
            )
        
        if 'nosniff' not in xcto_header:
            return Finding(
                title='X-Content-Type-Options Not Set to nosniff',
                severity='LOW',
                description=f'Header value is: {xcto_header}',
                location='X-Content-Type-Options Header',
                recommendation='Set to: X-Content-Type-Options: nosniff'
            )
        
        return None
    
    def analyze_referrer_policy(self) -> Optional[Finding]:
        """
        Analyze Referrer-Policy header for privacy protection.
        """
        ref_policy = self.headers.get('referrer-policy')
        
        if not ref_policy:
            return Finding(
                title='Missing Referrer-Policy',
                severity='LOW',
                description='Referrer-Policy not set. May leak sensitive information in referrer.',
                location='HTTP Response Headers',
                recommendation='Add: Referrer-Policy: strict-origin-when-cross-origin'
            )
        
        return None
    
    def analyze_all(self) -> List[Finding]:
        """
        Run all header analyses and return complete findings list.
        """
        self.findings = []
        
        # Run all analyses
        analyses = [
            self.analyze_hsts(),
            self.analyze_csp(),
            self.analyze_x_frame_options(),
            self.analyze_x_content_type_options(),
            self.analyze_referrer_policy()
        ]
        
        # Filter out None values and add to findings
        self.findings = [f for f in analyses if f is not None]
        
        return self.findings
