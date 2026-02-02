"""
SQL Injection Vulnerability Scanner.
Checks for Error-Based, Boolean-Based, and Time-Based SQL Injection vulnerabilities.
"""
import requests
import logging
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict
from models import Finding
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class SQLiScanner:
    """Scanner for SQL Injection vulnerabilities."""

    def __init__(self):
        self.requester = Requester()
        # Error-based payloads
        self.error_payloads = [
            "'", 
            "\"", 
            "' OR '1'='1", 
            "\" OR \"1\"=\"1", 
            "' OR 1=1 --", 
            "admin' --", 
            "' OR 'a'='a",
            "1' AND '1'='2",  # False condition for testing
        ]
        # Time-based blind SQLi payloads (database-agnostic attempts)
        self.time_payloads = [
            "' OR SLEEP(5)--",  # MySQL
            "'; WAITFOR DELAY '00:00:05'--",  # MSSQL
            "' OR pg_sleep(5)--",  # PostgreSQL
            "1' AND SLEEP(5)--",
            "1 OR SLEEP(5)#",
        ]
        # Boolean-based blind payloads
        self.boolean_payloads = [
            ("' AND '1'='1", True),   # Should return normal response
            ("' AND '1'='2", False),  # Should return different response
        ]
        
        self.error_signatures = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL query",
            "Microsoft OLE DB Provider for SQL Server",
            "Unclosed quotation mark",
            "SQLite3::",
            "Warning: mysql",
            "pg_query()",
            "SQLException",
            "mysql_num_rows",
            "MariaDB server"
        ]

    def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for SQL Injection vulnerabilities.
        Tests for Error-Based, Boolean-Based, and Time-Based SQL Injection.
        """
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        # Baseline check
        try:
            baseline_response = self.requester.get(url, timeout=5)
            baseline_errors = set()
            for error in self.error_signatures:
                if error.lower() in baseline_response.text.lower():
                    baseline_errors.add(error)
            baseline_length = len(baseline_response.text)
            baseline_time = baseline_response.elapsed.total_seconds()
        except Exception:
            baseline_errors = set()
            baseline_length = 0
            baseline_time = 0

        # Test each parameter
        for param in params.keys():
            # Test 1: Error-Based SQLi
            error_finding = self._test_error_based(url, parsed, params, param, baseline_errors)
            if error_finding:
                findings.append(error_finding)
                continue  # Found SQLi, move to next parameter
            
            # Test 2: Boolean-Based Blind SQLi
            boolean_finding = self._test_boolean_based(url, parsed, params, param, baseline_length)
            if boolean_finding:
                findings.append(boolean_finding)
                continue
            
            # Test 3: Time-Based Blind SQLi
            time_finding = self._test_time_based(url, parsed, params, param)
            if time_finding:
                findings.append(time_finding)

        return findings

    def _test_error_based(self, url: str, parsed, params: dict, param: str, baseline_errors: set) -> Finding:
        """Test for Error-Based SQL Injection."""
        for payload in self.error_payloads:
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
                response = self.requester.get(target_url, timeout=5)
                
                # Check for SQL errors
                for error in self.error_signatures:
                    if error.lower() in response.text.lower() and error not in baseline_errors:
                        return Finding(
                            title="SQL Injection - Error-Based",
                            severity="HIGH",
                            description=f"Database error message detected when injecting payload '{payload}' into parameter '{param}'. This indicates the input is not properly sanitized.\nError signature: '{error}'",
                            location=f"URL: {url} | Param: {param}",
                            recommendation="Use parameterized queries (Prepared Statements) for all database access. Never concatenate user input into SQL queries.",
                            cwe_reference="CWE-89",
                            confidence="High"
                        )

            except Exception as e:
                logger.debug(f"Error testing error-based SQLi for {target_url}: {e}")
        
        return None

    def _test_boolean_based(self, url: str, parsed, params: dict, param: str, baseline_length: int) -> Finding:
        """Test for Boolean-Based Blind SQL Injection."""
        try:
            true_payload, false_payload = "' OR '1'='1", "' AND '1'='2"
            
            # Test with TRUE condition
            test_params_true = params.copy()
            test_params_true[param] = [true_payload]
            true_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params_true, doseq=True),
                parsed.fragment
            ))
            
            response_true = self.requester.get(true_url, timeout=5)
            
            # Test with FALSE condition
            test_params_false = params.copy()
            test_params_false[param] = [false_payload]
            false_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params_false, doseq=True),
                parsed.fragment
            ))
            
            response_false = self.requester.get(false_url, timeout=5)
            
            # Compare responses
            true_len = len(response_true.text)
            false_len = len(response_false.text)
            
            # If TRUE condition gives significantly different response than FALSE
            # AND TRUE is similar to baseline (or larger), it indicates SQLi
            len_diff = abs(true_len - false_len)
            
            # Heuristic: If difference is > 10% and TRUE doesn't shrink response
            if len_diff > max(50, baseline_length * 0.1) and true_len >= baseline_length * 0.8:
                return Finding(
                    title="SQL Injection - Boolean-Based Blind",
                    severity="HIGH",
                    description=f"Application behavior changes based on SQL boolean conditions in parameter '{param}'. TRUE condition returned {true_len} bytes, FALSE returned {false_len} bytes. This indicates blind SQL injection vulnerability.",
                    location=f"URL: {url} | Param: {param}",
                    recommendation="Use parameterized queries (Prepared Statements). Implement proper input validation and output encoding.",
                    cwe_reference="CWE-89",
                    confidence="Medium"
                )
                
        except Exception as e:
            logger.debug(f"Error testing boolean-based SQLi: {e}")
        
        return None

    def _test_time_based(self, url: str, parsed, params: dict, param: str) -> Finding:
        """Test for Time-Based Blind SQL Injection."""
        for payload in self.time_payloads:
            test_params = params.copy()
            test_params[param] = [payload]
            target_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(test_params, doseq=True),
                parsed.fragment
            ))

            try:
                start_time = time.time()
                response = self.requester.get(target_url, timeout=10)
                elapsed = time.time() - start_time
                
                # If response took significantly longer (at least 4 seconds), likely SQLi
                if elapsed >= 4.5:
                    return Finding(
                        title="SQL Injection - Time-Based Blind",
                        severity="CRITICAL",
                        description=f"Application response was delayed by {elapsed:.2f} seconds when injecting time-based SQLi payload '{payload}' into parameter '{param}'. This confirms blind SQL injection vulnerability.",
                        location=f"URL: {url} | Param: {param}",
                        recommendation="Use parameterized queries (Prepared Statements). Never use string concatenation for SQL queries with user input.",
                        cwe_reference="CWE-89",
                        confidence="High"
                    )
                
            except requests.exceptions.Timeout:
                # Timeout could also indicate time-based SQLi
                return Finding(
                    title="SQL Injection - Time-Based Blind (Timeout)",
                    severity="HIGH",
                    description=f"Application timed out when injecting time-based SQLi payload into parameter '{param}'. This strongly suggests blind SQL injection vulnerability.",
                    location=f"URL: {url} | Param: {param}",
                    recommendation="Use parameterized queries (Prepared Statements). Never use string concatenation for SQL queries.",
                    cwe_reference="CWE-89",
                    confidence="High"
                )
            except Exception as e:
                logger.debug(f"Error testing time-based SQLi for {target_url}: {e}")
        
        return None
