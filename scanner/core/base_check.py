"""
Base Security Check Module.
Provides abstract base class for modular, plugin-based security checks.
"""
from abc import ABC, abstractmethod
from typing import List, Optional
from models import Finding


class SecurityCheck(ABC):
    """
    Abstract base class for all security checks.

    Every security check module should inherit from this class
    and implement the `run()` method. This enables a plugin-based
    architecture where checks can be discovered, registered, and
    executed uniformly.

    Attributes:
        name: Human-readable check name
        check_type: 'passive' or 'active'
        severity: Default severity level for findings from this check
        cwe: Primary CWE reference
        owasp: Primary OWASP Top 10 2021 category
        category: Finding category for scoring (e.g. 'Header Security')
    """

    name: str = "Base Check"
    check_type: str = "passive"  # 'passive' or 'active'
    severity: str = "INFO"
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    category: str = "General"

    @abstractmethod
    def run(self, target: str, **kwargs) -> List[Finding]:
        """
        Execute the security check against the target.

        Args:
            target: URL, header dict, or other input depending on check type
            **kwargs: Additional context (headers, response, cookies, etc.)

        Returns:
            List of Finding objects
        """
        pass

    @property
    def metadata(self) -> dict:
        """Return check metadata for reporting and registry."""
        return {
            "name": self.name,
            "type": self.check_type,
            "severity": self.severity,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "category": self.category,
        }


class CheckRegistry:
    """
    Registry for managing and executing security checks.

    Provides auto-discovery and execution of registered SecurityCheck instances.
    Supports filtering by check type (passive/active) for profile-based scanning.
    """

    def __init__(self):
        self.checks: List[SecurityCheck] = []

    def register(self, check: SecurityCheck):
        """Register a security check instance."""
        self.checks.append(check)

    def run_all(self, target: str, **kwargs) -> List[Finding]:
        """Run all registered checks and aggregate findings."""
        all_findings = []
        for check in self.checks:
            try:
                findings = check.run(target, **kwargs)
                all_findings.extend(findings)
            except Exception:
                pass
        return all_findings

    def get_by_type(self, check_type: str) -> List[SecurityCheck]:
        """Get checks filtered by type ('passive' or 'active')."""
        return [c for c in self.checks if c.check_type == check_type]

    def get_passive_checks(self) -> List[SecurityCheck]:
        """Get only passive checks."""
        return self.get_by_type("passive")

    def get_active_checks(self) -> List[SecurityCheck]:
        """Get only active checks."""
        return self.get_by_type("active")

    @property
    def check_count(self) -> int:
        """Total number of registered checks."""
        return len(self.checks)
