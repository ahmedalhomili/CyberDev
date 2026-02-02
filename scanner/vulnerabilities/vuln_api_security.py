"""
API Security Scanner (OWASP API Security Top 10).
Actively tests API endpoints for common vulnerabilities.
"""
import logging
import json
from typing import List
from models import Finding
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class APISecurityScanner:
    """
    Scanner for API Security (OWASP API Top 10).
    """
    def __init__(self):
        self.requester = Requester()
        self.api_docs_paths = [
            '/swagger.json', '/swagger.yaml', '/swagger-ui.html',
            '/openapi.json', '/openapi.yaml',
            '/api-docs', '/api/docs', '/docs',
            '/redoc', '/api/swagger', '/api/openapi'
        ]

    def scan(self, url: str) -> List[Finding]:
        findings = []
        
        # 1. Check if URL looks like an API endpoint
        api_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql']
        is_api_url = any(pattern in url.lower() for pattern in api_patterns)
        
        if is_api_url:
            findings.append(Finding(
                title="API Endpoint Detected",
                severity="INFO",
                description="URL structure suggests an API endpoint. Further security testing recommended.",
                location=url,
                recommendation="Ensure proper authentication, authorization, input validation, and rate limiting.",
                cwe_reference="OWASP API Security Top 10"
            ))
            
            # Test for BOLA (Broken Object Level Authorization) - CWE-639
            findings.extend(self._test_bola(url))
            
            # Test for Excessive Data Exposure
            findings.extend(self._test_data_exposure(url))
        
        # 2. Actively search for API documentation
        findings.extend(self._scan_for_api_docs(url))
        
        # 3. Test for Mass Assignment
        findings.extend(self._test_mass_assignment(url))
        
        return findings

    def _scan_for_api_docs(self, base_url: str) -> List[Finding]:
        """Scan for exposed API documentation."""
        findings = []
        
        # Extract base URL
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(base_url)
        base = urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))
        
        for doc_path in self.api_docs_paths:
            doc_url = base + doc_path
            try:
                response = self.requester.get(doc_url, timeout=5)
                
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    
                    # Check if it's actual API documentation
                    doc_indicators = ['swagger', 'openapi', 'paths', 'endpoints', 'api', 'definitions']
                    if any(ind in content_lower for ind in doc_indicators):
                        findings.append(Finding(
                            title="Exposed API Documentation",
                            severity="MEDIUM",
                            description=f"API documentation is publicly accessible at {doc_url}. This exposes the API structure, endpoints, and parameters to potential attackers.",
                            location=doc_url,
                            recommendation="Restrict access to API documentation in production environments. Use authentication or IP whitelisting.",
                            cwe_reference="CWE-200"
                        ))
                        break  # Found documentation, no need to check others
                        
            except Exception:
                pass
        
        return findings

    def _test_bola(self, url: str) -> List[Finding]:
        """Test for Broken Object Level Authorization (IDOR)."""
        findings = []
        
        import re
        # Check if URL contains numeric IDs that might be enumerable
        id_match = re.search(r'/(\d+)(?:/|$)', url)
        if id_match:
            original_id = id_match.group(1)
            
            # Try accessing with a different ID
            test_id = str(int(original_id) + 1)
            test_url = url.replace(f'/{original_id}', f'/{test_id}')
            
            try:
                response = self.requester.get(test_url, timeout=5)
                
                # If we get 200 OK without authentication, it's likely vulnerable
                if response.status_code == 200:
                    findings.append(Finding(
                        title="Potential Broken Object Level Authorization (BOLA/IDOR)",
                        severity="HIGH",
                        description=f"API endpoint allows accessing object ID {test_id} when the original request was for {original_id}. This may indicate missing authorization checks.",
                        location=url,
                        recommendation="Implement server-side authorization checks for all object access. Verify the user has permission to access the requested resource.",
                        cwe_reference="CWE-639",
                        confidence="Medium"
                    ))
            except Exception:
                pass
        
        return findings

    def _test_data_exposure(self, url: str) -> List[Finding]:
        """Test for Excessive Data Exposure."""
        findings = []
        
        try:
            response = self.requester.get(url, timeout=5)
            
            # Check if response is JSON
            content_type = response.headers.get('Content-Type', '').lower()
            if 'application/json' in content_type:
                try:
                    data = response.json()
                    
                    # Check for sensitive fields in response
                    sensitive_fields = [
                        'password', 'passwd', 'pwd', 'secret', 'token',
                        'api_key', 'apikey', 'private_key', 'auth',
                        'ssn', 'social_security', 'credit_card', 'cvv'
                    ]
                    
                    def check_dict(obj, path=""):
                        found_fields = []
                        if isinstance(obj, dict):
                            for key, value in obj.items():
                                key_lower = str(key).lower()
                                if any(sens in key_lower for sens in sensitive_fields):
                                    found_fields.append(f"{path}.{key}" if path else key)
                                if isinstance(value, (dict, list)):
                                    found_fields.extend(check_dict(value, f"{path}.{key}" if path else key))
                        elif isinstance(obj, list):
                            for i, item in enumerate(obj):
                                if isinstance(item, (dict, list)):
                                    found_fields.extend(check_dict(item, f"{path}[{i}]"))
                        return found_fields
                    
                    exposed_fields = check_dict(data)
                    
                    if exposed_fields:
                        findings.append(Finding(
                            title="Excessive Data Exposure in API Response",
                            severity="HIGH",
                            description=f"API response contains potentially sensitive fields: {', '.join(exposed_fields[:5])}. APIs should only return data that the user needs.",
                            location=url,
                            recommendation="Filter API responses to include only necessary data. Implement field-level authorization.",
                            cwe_reference="CWE-213"
                        ))
                    
                    # Check for large response size (potential mass data exposure)
                    if len(response.text) > 100000:  # 100KB
                        findings.append(Finding(
                            title="Large API Response Size",
                            severity="MEDIUM",
                            description=f"API returned a very large response ({len(response.text)} bytes). This may indicate lack of pagination or excessive data exposure.",
                            location=url,
                            recommendation="Implement pagination and limit response size. Use filtering to return only requested fields.",
                            cwe_reference="CWE-770"
                        ))
                        
                except json.JSONDecodeError:
                    pass
                    
        except Exception:
            pass
        
        return findings

    def _test_mass_assignment(self, url: str) -> List[Finding]:
        """Test for Mass Assignment vulnerability."""
        findings = []
        
        # This is speculative - we try to POST/PUT with admin fields
        try:
            # Try to send a request with suspicious fields
            test_payload = {
                "isAdmin": True,
                "role": "admin",
                "is_admin": True,
                "admin": True,
                "permissions": ["all"]
            }
            
            # Try POST first
            response = self.requester.post(url, json=test_payload, timeout=5)
            
            # Check if the request was accepted (not rejected)
            if response.status_code in [200, 201, 202]:
                # Try to verify if the field was actually set
                try:
                    resp_data = response.json()
                    if any(key in resp_data for key in test_payload.keys()):
                        findings.append(Finding(
                            title="Potential Mass Assignment Vulnerability",
                            severity="HIGH",
                            description="API accepted and possibly set privileged fields (isAdmin, role, permissions) from user input. This could allow privilege escalation.",
                            location=url,
                            recommendation="Use a whitelist of allowed fields for user input. Implement proper access controls. Use DTOs/schemas to explicitly define allowed fields.",
                            cwe_reference="CWE-915",
                            confidence="Medium"
                        ))
                except:
                    pass
                    
        except Exception:
            pass
        
        return findings
