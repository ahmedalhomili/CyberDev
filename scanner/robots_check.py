"""
Checks for robots.txt and sitemap.xml to discover hidden paths.
"""
from typing import List
from models import Finding
from scanner.http_handler import HTTPAnalyzer

class RobotsAnalyzer:
    """Analyzes robots.txt for sensitive paths."""
    
    def __init__(self, http_handler: HTTPAnalyzer):
        self.http = http_handler

    def analyze(self, base_url: str) -> List[Finding]:
        findings = []
        
        # Construct robots.txt URL
        if not base_url.endswith('/'):
            base_url += '/'
        robots_url = base_url.rstrip('/') + "/robots.txt"
        
        response = self.http.fetch_page_content(robots_url)
        if response['success'] and response['status_code'] == 200:
            content = response['content']
            
            disallowed = []
            for line in content.splitlines():
                if line.strip().lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        disallowed.append(path)
            
            # Check for interesting disallowed paths
            sensitive_paths = [p for p in disallowed if any(x in p.lower() for x in ['admin', 'backend', 'config', 'db', 'private', 'backup', 'test'])]
            
            if sensitive_paths:
                findings.append(Finding(
                    title="Sensitive Paths in robots.txt",
                    severity="LOW", # Informational/Low
                    description=f"robots.txt reveals {len(sensitive_paths)} potentially sensitive paths (e.g., {sensitive_paths[:3]}). Attackers use this to map the site.",
                    location=robots_url,
                    recommendation="Ensure sensitive directories are actually protected by authentication, not just hidden by robots.txt.",
                    cwe_reference="CWE-200"
                ))

        return findings
