"""
Analyzes HTML content for sensitive information leaks.
Passive analysis of response body for comments, emails, and secrets.
"""
import re
from typing import List, Dict
from bs4 import BeautifulSoup, Comment
from models import Finding
from config import SEVERITY_LEVELS

class ContentAnalyzer:
    """Analyzes HTML body for information leakage."""

    def analyze(self, html_content: str, url: str) -> List[Finding]:
        findings = []
        if not html_content:
            return findings

        soup = BeautifulSoup(html_content, 'html.parser')

        # 1. HTML Comments Analysis (Using BS4)
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        sensitive_comments = []
        
        for comment in comments:
            comment_lower = comment.lower()
            if any(keyword in comment_lower for keyword in ['todo', 'fixme', 'bug', 'password', 'admin', 'key', 'test', 'internal']):
                if len(comment.strip()) < 300: 
                    sensitive_comments.append(comment.strip())
        
        if sensitive_comments:
            findings.append(Finding(
                title="Sensitive HTML Comments (Info Leak)",
                severity="LOW",
                description=f"Found {len(sensitive_comments)} interesting comments in HTML. Examples: {sensitive_comments[:2]}...",
                location="HTML Body",
                recommendation="Remove development comments from production code.",
                cwe_reference="CWE-615"
            ))

        # 2. Email Address Disclosure
        # Parse text content only, not tags
        text_content = soup.get_text()
        emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text_content))
        valid_emails = [e for e in emails if not any(x in e for x in ['example.com', 'yourdomain.com', '.png', '.jpg', '.svg', '.css', '.js'])]
        
        if valid_emails:
            findings.append(Finding(
                title="Email Addresses Exposed",
                severity="LOW", 
                description=f"Found {len(valid_emails)} email addresses in visible text. Examples: {valid_emails[:3]}",
                location="HTML Body",
                recommendation="Obfuscate emails or use contact forms to prevent scraping.",
                cwe_reference="CWE-200"
            ))

        # 3. Insecure Forms (HTTP Action)
        forms = soup.find_all('form')
        insecure_forms = []
        for form in forms:
            action = form.get('action', '').lower()
            if action.startswith('http://'):
                insecure_forms.append(action)
        
        if insecure_forms:
            findings.append(Finding(
                title="Insecure Form Submission (HTTP)",
                severity="HIGH",
                description=f"Found {len(insecure_forms)} forms submitting data over cleartext HTTP.",
                location="HTML Form",
                recommendation="Ensure all forms submit via HTTPS.",
                cwe_reference="CWE-319"
            ))

        # 4. Potential Keys / Tokens (High Entropy - Regex on Scripts)
        scripts = soup.find_all('script')
        potential_keys = []
        for script in scripts:
            if script.string:
                keys = re.findall(r'(?:api[_-]?key|auth[_-]?token|access[_-]?token)[\"\']?\s*[:=]\s*[\"\']([a-zA-Z0-9_\-]{20,})[\"\']', script.string, re.IGNORECASE)
                potential_keys.extend(keys)
        
        if potential_keys:
            findings.append(Finding(
                title="Potential API Key/Token Disclosure",
                severity="HIGH",
                description="Patterns resembling API keys were found in client-side scripts.",
                location="HTML Script",
                recommendation="Revoke keys immediately and move secrets to backend.",
                cwe_reference="CWE-798"
            ))

        return findings
