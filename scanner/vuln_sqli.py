"""
SQL Injection Vulnerability Scanner.
Checks for Error-Based and generic SQL Injection vulnerabilities.
"""
import requests
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict
from models import Finding
from scanner.requester import Requester

logger = logging.getLogger(__name__)

class SQLiScanner:
    """Scanner for SQL Injection vulnerabilities."""

    def __init__(self):
        self.requester = Requester()
        self.payloads = [
            "'", 
            "\"", 
            "' OR '1'='1", 
            "\" OR \"1\"=\"1", 
            "' OR 1=1 --", 
            "admin' --", 
            "' OR 'a'='a",
            "sleep(10)"  # Very basic blind check helper, though full blind needs timing analysis
        ]
        self.error_signatures = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL query",
            "Microsoft OLE DB Provider for SQL Server",
            "Unclosed quotation mark"
        ]

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for SQL Injection vulnerabilities.
        It injects payloads into query parameters.
        """
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        # Test each parameter
        for param in params.keys():
            for payload in self.payloads:
                # Construct malicious URL
                test_params = params.copy()
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                target_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))

                try:
                    # We use a lower timeout because we process many requests
                    response = self.requester.get(target_url, timeout=5)
                    
                    # 1. Error-Based Check
                    for error in self.error_signatures:
                        if error.lower() in response.text.lower():
                            findings.append(Finding(
                                title="Possible SQL Injection (Error-Based)",
                                severity="HIGH",
                                description=f"Database error message detected when injecting payload '{payload}' into parameter '{param}'. This indicates the input is not properly sanitized.",
                                location=f"URL: {url} | Param: {param}",
                                recommendation="Use parameterized queries (Prepared Statements) for all database access. Sanitize all user inputs.",
                                cwe_reference="CWE-89"
                            ))
                            # Break inner loop to avoid duplicate findings for same param if multiple errors match
                            break
                    
                    # 2. Basic Boolean Check (very simple: if OR 1=1 returns significantly different content size/code than default, it's suspicious - omitted for safety/noise ratio in this basic version, keeping to error-based mostly)

                except Exception as e:
                    logger.debug(f"Error scanning SQLi for {target_url}: {e}")

        return findings
