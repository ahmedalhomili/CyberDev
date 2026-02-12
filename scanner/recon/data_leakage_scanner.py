"""
Passive Data Leakage Detection Module.
Scans response content for sensitive data patterns using regex.
Detects API keys, credentials, internal IPs, stack traces, and more.
"""
import re
import logging
from typing import List, Dict, Tuple
from models import Finding
from scanner.core.base_check import SecurityCheck

logger = logging.getLogger(__name__)


class DataLeakageScanner(SecurityCheck):
    """Regex-based scanner for detecting sensitive data exposure in responses."""

    name = "Data Leakage Detection"
    check_type = "passive"
    category = "Data Leakage"

    # Pattern definitions: name -> (regex, severity, cwe, description, confidence)
    PATTERNS: Dict[str, Dict] = {
        "AWS Access Key": {
            "regex": r"AKIA[0-9A-Z]{16}",
            "severity": "CRITICAL",
            "cwe": "CWE-798",
            "description": "AWS Access Key ID detected in response content. This could allow unauthorized access to AWS services.",
            "confidence": "High",
        },
        "Google API Key": {
            "regex": r"AIza[0-9A-Za-z_\-]{35}",
            "severity": "HIGH",
            "cwe": "CWE-798",
            "description": "Google API Key detected in response content.",
            "confidence": "High",
        },
        "Generic Secret Assignment": {
            "regex": r"""(?:secret|password|passwd|pwd|token|api_key|apikey|auth_token|access_token|private_key)[\s]*[=:]\s*['"][a-zA-Z0-9_\-/+=]{8,}['"]""",
            "severity": "HIGH",
            "cwe": "CWE-798",
            "description": "Potential secret or credential assignment detected in response.",
            "confidence": "Medium",
        },
        "Private IPv4 Address": {
            "regex": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            "severity": "LOW",
            "cwe": "CWE-200",
            "description": "Private/internal IP address leaked in response content. This reveals internal network topology.",
            "confidence": "Medium",
        },
        "Python Stack Trace": {
            "regex": r"Traceback \(most recent call last\)",
            "severity": "MEDIUM",
            "cwe": "CWE-209",
            "description": "Python stack trace detected in response. Error messages may reveal internal paths, library versions, and application logic.",
            "confidence": "High",
        },
        "Java Stack Trace": {
            "regex": r"(?:java\.\w+\.[\w.]+Exception|at\s+[\w.$]+\([\w.]+:\d+\))",
            "severity": "MEDIUM",
            "cwe": "CWE-209",
            "description": "Java exception/stack trace detected in response.",
            "confidence": "High",
        },
        ".NET Stack Trace": {
            "regex": r"(?:System\.\w+Exception|at \w+\.[\w.<>]+\(|Server Error in)",
            "severity": "MEDIUM",
            "cwe": "CWE-209",
            "description": ".NET exception or server error page detected in response.",
            "confidence": "High",
        },
        "PHP Error": {
            "regex": r"(?:Fatal error|Parse error|Warning):\s+.+\s+in\s+.+\s+on line\s+\d+",
            "severity": "MEDIUM",
            "cwe": "CWE-209",
            "description": "PHP error message detected revealing file paths and line numbers.",
            "confidence": "High",
        },
        "SQL Error Message": {
            "regex": r"(?:mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|Microsoft SQL.*Server|SQLSTATE\[)",
            "severity": "MEDIUM",
            "cwe": "CWE-209",
            "description": "Database error message detected in response, revealing database type and potentially query details.",
            "confidence": "High",
        },
        "Credit Card (Visa)": {
            "regex": r"\b4[0-9]{12}(?:[0-9]{3})?\b",
            "severity": "CRITICAL",
            "cwe": "CWE-312",
            "description": "Potential Visa credit card number detected in response.",
            "confidence": "Low",
            "validator": "luhn",
        },
        "Credit Card (Mastercard)": {
            "regex": r"\b5[1-5][0-9]{14}\b",
            "severity": "CRITICAL",
            "cwe": "CWE-312",
            "description": "Potential Mastercard credit card number detected in response.",
            "confidence": "Low",
            "validator": "luhn",
        },
        "JWT Token": {
            "regex": r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+",
            "severity": "MEDIUM",
            "cwe": "CWE-200",
            "description": "JWT token detected in response content. May contain sensitive claims.",
            "confidence": "High",
        },
        "Sensitive HTML Comment": {
            "regex": r"<!--[\s\S]{0,500}?(?:password|secret|admin|internal|debug|TODO|FIXME|HACK|credentials|private)[\s\S]{0,500}?-->",
            "severity": "LOW",
            "cwe": "CWE-615",
            "description": "HTML comment containing potentially sensitive keywords detected.",
            "confidence": "Medium",
        },
        "Email Address": {
            "regex": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            "severity": "INFO",
            "cwe": "CWE-200",
            "description": "Email address found in response content.",
            "confidence": "High",
            "max_findings": 3,
        },
    }

    # Exclude common false positive patterns
    FALSE_POSITIVE_EXCLUDES = {
        "Private IPv4 Address": [
            r"10\.0\.0\.0",  # Common documentation IP
            r"192\.168\.0\.0",
            r"172\.16\.0\.0",
        ],
        "Email Address": [
            r"example\.com$",
            r"yourdomain\.com$",
            r"\.png$", r"\.jpg$", r"\.svg$", r"\.css$", r"\.js$",
        ],
    }

    def run(self, target: str, **kwargs) -> List[Finding]:
        """
        Run data leakage detection.

        Args:
            target: Target URL
            **kwargs: Must include 'content' with response body text

        Returns:
            List of Finding objects
        """
        content = kwargs.get('content', '')
        return self.scan(content, target)

    def scan(self, content: str, url: str) -> List[Finding]:
        """
        Scan content for data leakage patterns.

        Args:
            content: Response body text to scan
            url: Source URL for finding location

        Returns:
            List of findings for detected patterns
        """
        if not content:
            return []

        findings = []
        seen_patterns = set()

        for pattern_name, config in self.PATTERNS.items():
            if pattern_name in seen_patterns:
                continue

            try:
                matches = re.findall(config["regex"], content, re.IGNORECASE)
            except re.error:
                continue

            if not matches:
                continue

            # Filter false positives
            matches = self._filter_false_positives(pattern_name, matches)
            if not matches:
                continue

            # Apply validator (e.g., Luhn for credit cards)
            if config.get("validator") == "luhn":
                matches = [m for m in matches if self._luhn_check(m)]
                if not matches:
                    continue
                # Upgrade confidence after Luhn validation
                confidence = "High"
            else:
                confidence = config.get("confidence", "Medium")

            # Limit findings per pattern
            max_findings = config.get("max_findings", 1)
            match_count = len(matches)
            display_matches = matches[:max_findings]

            # Build evidence (truncated, safe)
            evidence_parts = [self._safe_evidence(m) for m in display_matches]
            evidence = "; ".join(evidence_parts)
            if match_count > max_findings:
                evidence += f" (and {match_count - max_findings} more)"

            description = config["description"]
            if match_count > 1:
                description += f" ({match_count} instances found)"

            findings.append(Finding(
                title=f"Data Leakage: {pattern_name}",
                severity=config["severity"],
                description=description,
                location=f"Response Body: {url}",
                recommendation="Review and remove sensitive data from public-facing responses. Rotate any exposed credentials immediately.",
                cwe_reference=config["cwe"],
                confidence=confidence,
                category="Data Leakage",
                evidence=evidence,
            ))

            seen_patterns.add(pattern_name)

        return findings

    def _filter_false_positives(self, pattern_name: str, matches: list) -> list:
        """Remove known false positive matches."""
        excludes = self.FALSE_POSITIVE_EXCLUDES.get(pattern_name, [])
        if not excludes:
            return matches

        filtered = []
        for match in matches:
            is_fp = False
            for exclude_pattern in excludes:
                if re.search(exclude_pattern, str(match), re.IGNORECASE):
                    is_fp = True
                    break
            if not is_fp:
                filtered.append(match)
        return filtered

    @staticmethod
    def _luhn_check(number: str) -> bool:
        """
        Validate a number using the Luhn algorithm.
        Used to verify credit card numbers.
        """
        digits = [int(d) for d in str(number) if d.isdigit()]
        if len(digits) < 13:
            return False

        checksum = 0
        reverse_digits = digits[::-1]
        for i, d in enumerate(reverse_digits):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    @staticmethod
    def _safe_evidence(match) -> str:
        """Create a safe evidence snippet, masking sensitive middle portions."""
        s = str(match)
        if len(s) > 12:
            # Mask middle portion for security
            visible = max(4, len(s) // 4)
            return s[:visible] + "*" * (len(s) - visible * 2) + s[-visible:]
        return s
