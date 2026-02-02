"""
Checks for robots.txt and sitemap.xml to discover hidden paths.
"""
from typing import List
from models import Finding
from scanner.core.http_handler import HTTPAnalyzer

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
            sitemaps = []
            for line in content.splitlines():
                stripped_line = line.strip()
                if stripped_line.lower().startswith('disallow:'):
                    path = stripped_line.split(':', 1)[1].strip()
                    if path and path != '/':
                        disallowed.append(path)
                elif stripped_line.lower().startswith('sitemap:'):
                    sitemap_val = stripped_line.split(':', 1)[1].strip()
                    if sitemap_val:
                        sitemaps.append(sitemap_val)
            
            # Check for interesting disallowed paths
            sensitive_paths = [p for p in disallowed if any(x in p.lower() for x in ['admin', 'backend', 'config', 'db', 'private', 'backup', 'test'])]
            
            if sensitive_paths:
                findings.append(Finding(
                    title="Public Information (robots.txt)",
                    severity="INFO",
                    description=f"robots.txt reveals {len(sensitive_paths)} paths (e.g., {sensitive_paths[:3]}). "
                                "This is public information, not a vulnerability, but helps attackers map the site.",
                    location=robots_url,
                    recommendation="Ensure sensitive directories are actually protected by authentication.",
                    cwe_reference="CWE-200",
                    confidence="High"
                ))

            if sitemaps:
                findings.append(Finding(
                    title="Sitemap Discovered",
                    severity="INFO",
                    description=f"robots.txt specifies {len(sitemaps)} sitemap(s): {', '.join(sitemaps[:3])}. "
                                "This aids in mapping the application's structure.",
                    location=robots_url,
                    recommendation="Ensure the sitemap does not list non-public URLs.",
                    cwe_reference="CWE-200",
                    confidence="High"
                ))

        return findings
