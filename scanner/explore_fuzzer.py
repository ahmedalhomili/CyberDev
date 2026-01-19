"""
Directory and File Fuzzer.
Checks for sensitive hidden files and directories.
"""
import requests
import logging
from typing import List
from models import Finding
from scanner.requester import Requester

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
                
                if response.status_code == 200:
                    description = f"Found hidden file/directory: {path}"
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
                        cwe_reference="CWE-538"
                    ))
            
            except Exception:
                pass

        return findings
