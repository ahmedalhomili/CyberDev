"""
Directory and File Fuzzer.
Checks for sensitive hidden files and directories.
"""
import requests
import logging
from typing import List
from models import Finding
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class DirectoryFuzzer:
    """Fuzzer for discovering hidden paths."""

    def __init__(self):
        self.requester = Requester()
        self.common_paths = [
            ".env",
            "config.php",
            "config.php.bak",
            "wp-config.php",
            "backup.zip",
            "backup.sql",
            ".git/HEAD",
            "robots.txt",
            "sitemap.xml",
            "admin/",
            "phpinfo.php",
            ".htaccess",
            "server-status"
        ]

    def scan(self, base_url: str) -> List[Finding]:
        """
        Scan a URL for hidden files.
        """
        findings = []
        if not base_url.endswith('/'):
            base_url += '/'

        for path in self.common_paths:
            target_url = base_url + path
            try:
                # We use a custom requester that might follow redirects, 
                # but for fuzzing we usually want to know if the resource exists directly (200 OK)
                response = self.requester.get(target_url, timeout=5)
                
                # Verify it's not a soft 404 or just a generic landing page
                if response.status_code == 200:
                    content = response.text.lower()
                    is_valid = False
                    
                    # Content-based verification
                    if ".env" in path and "DB_HOST=" in response.text:
                         is_valid = True
                    elif "config" in path and ("<?php" in response.text or "define(" in response.text):
                         # If php source is exposed (rare, usually executes) - if it executes it might be blank.
                         # But if it executes and returns blank 200, is it a vuln? Maybe not.
                         # We are looking for accidental source code disclosure or sensitive config text.
                         if "password" in content or "secret" in content:
                             is_valid = True
                    elif ".git" in path and "ref: refs/" in response.text:
                         is_valid = True
                    elif "phpinfo" in path and "php version" in content:
                         is_valid = True
                    elif "server-status" in path and "apache status" in content:
                         is_valid = True
                    elif "backup" in path and (len(response.content) > 100): # Backup file likely not empty
                         is_valid = True
                    elif "admin" in path and ("login" in content or "admin" in content or "user" in content):
                         is_valid = True
                         severity = "INFO"
                         description = f"Admin entry point found: {path}"

                    if is_valid:
                        if severity != "INFO": # Default if not set above
                            description = f"Found sensitive file/directory: {path}"
                            severity = "MEDIUM"
                        
                        # Heuristics to upgrade severity
                        if ".env" in path or "config" in path or "backup" in path:
                            severity = "HIGH"
                            description += " (Contains potentially sensitive configuration or backup data)"
                        if ".git" in path:
                            severity = "HIGH"
                            description += " (Source code repository exposed)"

                        findings.append(Finding(
                            title="Sensitive File/Directory Discovered",
                            severity=severity,
                            description=description,
                            location=target_url,
                            recommendation="Restrict access to sensitive administrative or configuration files. Remove backup files from the web root.",
                            cwe_reference="CWE-538",
                            confidence="High"
                        ))
            
            except Exception:
                pass

        return findings
