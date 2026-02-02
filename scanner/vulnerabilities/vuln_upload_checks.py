"""
File Upload Vulnerability Scanner.
Actively tests for unrestricted file upload vulnerabilities.
"""
import logging
import re
import io
from typing import List
from models import Finding
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class FileUploadScanner:
    """
    Scanner for File Upload Vulnerabilities.
    """
    def __init__(self):
        self.requester = Requester()

    def scan(self, url: str, content: str) -> List[Finding]:
        findings = []
        
        # 1. Passive Detection: Check for file input fields
        file_inputs = re.findall(r'<input[^>]*type=["\']file["\'][^>]*>', content, re.IGNORECASE)
        
        if not file_inputs:
            return findings
        
        # File upload detected - add passive finding
        findings.append(Finding(
            title="File Upload Functionality Detected",
            severity="INFO",
            description=f"Web application contains {len(file_inputs)} file upload interface(s). Further testing recommended.",
            location=url,
            recommendation="Ensure strict validation of file types (MIME & extension), names, and content. Store uploaded files outside webroot.",
            cwe_reference="CWE-434"
        ))
        
        # 2. Extract form details for active testing
        for file_input in file_inputs:
            # Try to find the parent form
            form_match = self._find_parent_form(content, file_input)
            if form_match:
                findings.extend(self._test_upload_form(url, form_match))
        
        # 3. Check for dangerous file type acceptance in HTML attributes
        for file_input in file_inputs:
            # Check if 'accept' attribute exists
            accept_match = re.search(r'accept=["\']([^"\']+)["\']', file_input, re.IGNORECASE)
            if not accept_match:
                findings.append(Finding(
                    title="File Upload Without Type Restrictions",
                    severity="MEDIUM",
                    description="File upload field does not specify an 'accept' attribute. This may allow uploading of dangerous file types.",
                    location=url,
                    recommendation="Add 'accept' attribute to restrict file types on client-side, and implement strict server-side validation.",
                    cwe_reference="CWE-434"
                ))
            else:
                # Check if dangerous types are allowed
                accept_value = accept_match.group(1).lower()
                dangerous_patterns = ['.exe', '.php', '.jsp', '.asp', '.sh', '.bat', '.cmd', 'application/x-']
                if any(pattern in accept_value for pattern in dangerous_patterns):
                    findings.append(Finding(
                        title="File Upload Accepts Dangerous File Types",
                        severity="HIGH",
                        description=f"File upload field accepts potentially dangerous file types: {accept_value}",
                        location=url,
                        recommendation="Restrict file uploads to safe types only (images, documents). Validate on server-side.",
                        cwe_reference="CWE-434"
                    ))
        
        return findings

    def _find_parent_form(self, content: str, file_input: str) -> str:
        """Find the parent form element for a given file input."""
        # Find the position of the file input
        input_pos = content.find(file_input)
        if input_pos == -1:
            return ""
        
        # Search backwards for <form tag
        form_start = content.rfind('<form', 0, input_pos)
        if form_start == -1:
            return ""
        
        # Search forward from form_start for </form>
        form_end = content.find('</form>', form_start)
        if form_end == -1:
            return ""
        
        return content[form_start:form_end + 7]

    def _test_upload_form(self, base_url: str, form_html: str) -> List[Finding]:
        """Actively test file upload form with various payloads."""
        findings = []
        
        try:
            # Extract form action and method
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            
            if not action_match:
                return findings
            
            action = action_match.group(1)
            method = method_match.group(1).upper() if method_match else 'POST'
            
            # Build absolute URL
            from urllib.parse import urljoin
            upload_url = urljoin(base_url, action)
            
            # Extract file input name
            name_match = re.search(r'name=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            if not name_match:
                return findings
            
            file_field_name = name_match.group(1)
            
            # Test with a simple text file disguised as PHP
            test_filename = "test_safe_scanner.php.txt"
            test_content = b"<?php echo 'TEST'; ?>"
            
            files = {file_field_name: (test_filename, io.BytesIO(test_content), 'application/x-php')}
            
            if method == 'POST':
                response = self.requester.post(upload_url, files=files, timeout=10)
                
                # Analyze response for success indicators
                success_indicators = ['uploaded', 'success', 'file saved', 'upload complete']
                error_indicators = ['not allowed', 'invalid', 'forbidden', 'denied', 'error']
                
                response_lower = response.text.lower()
                
                has_success = any(ind in response_lower for ind in success_indicators)
                has_error = any(ind in response_lower for ind in error_indicators)
                
                if has_success and not has_error:
                    findings.append(Finding(
                        title="Potential Unrestricted File Upload",
                        severity="CRITICAL",
                        description=f"The application appears to accept file uploads without proper validation. Test file '{test_filename}' with PHP content was seemingly accepted.",
                        location=upload_url,
                        recommendation="Implement strict server-side validation: check MIME type, extension whitelist, file content analysis, and rename uploaded files.",
                        cwe_reference="CWE-434",
                        confidence="Medium"
                    ))
                elif response.status_code == 200 and not has_error:
                    findings.append(Finding(
                        title="File Upload Endpoint Responds Without Clear Rejection",
                        severity="MEDIUM",
                        description="File upload endpoint returned HTTP 200 without clear error message. Manual testing recommended.",
                        location=upload_url,
                        recommendation="Ensure proper validation and clear error messages for rejected uploads.",
                        cwe_reference="CWE-434",
                        confidence="Low"
                    ))
                    
        except Exception as e:
            logger.debug(f"Error testing upload form: {e}")
        
        return findings
