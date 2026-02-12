"""
OWASP Top 10 (2021) Mapping Module.
Maps CWE references to OWASP Top 10 2021 categories for standardized reporting.
"""
from typing import Optional

# OWASP Top 10 2021 Categories
OWASP_CATEGORIES = {
    "A01": "A01:2021 - Broken Access Control",
    "A02": "A02:2021 - Cryptographic Failures",
    "A03": "A03:2021 - Injection",
    "A04": "A04:2021 - Insecure Design",
    "A05": "A05:2021 - Security Misconfiguration",
    "A06": "A06:2021 - Vulnerable and Outdated Components",
    "A07": "A07:2021 - Identification and Authentication Failures",
    "A08": "A08:2021 - Software and Data Integrity Failures",
    "A09": "A09:2021 - Security Logging and Monitoring Failures",
    "A10": "A10:2021 - Server-Side Request Forgery (SSRF)",
}

# CWE → OWASP 2021 mapping
CWE_TO_OWASP = {
    # A01: Broken Access Control
    "CWE-200": "A01:2021 - Broken Access Control",      # Exposure of Sensitive Information
    "CWE-284": "A01:2021 - Broken Access Control",      # Improper Access Control
    "CWE-285": "A01:2021 - Broken Access Control",      # Improper Authorization
    "CWE-352": "A01:2021 - Broken Access Control",      # CSRF
    "CWE-538": "A01:2021 - Broken Access Control",      # Sensitive File/Dir Exposure
    "CWE-548": "A01:2021 - Broken Access Control",      # Directory Listing
    "CWE-598": "A01:2021 - Broken Access Control",      # Session ID in URL
    "CWE-601": "A01:2021 - Broken Access Control",      # Open Redirect
    "CWE-639": "A01:2021 - Broken Access Control",      # IDOR
    "CWE-862": "A01:2021 - Broken Access Control",      # Missing Authorization
    "CWE-863": "A01:2021 - Broken Access Control",      # Incorrect Authorization

    # A02: Cryptographic Failures
    "CWE-256": "A02:2021 - Cryptographic Failures",     # Plaintext Storage of Password
    "CWE-295": "A02:2021 - Cryptographic Failures",     # Improper Certificate Validation
    "CWE-310": "A02:2021 - Cryptographic Failures",     # Cryptographic Issues
    "CWE-311": "A02:2021 - Cryptographic Failures",     # Missing Encryption
    "CWE-312": "A02:2021 - Cryptographic Failures",     # Cleartext Storage
    "CWE-319": "A02:2021 - Cryptographic Failures",     # Cleartext Transmission
    "CWE-326": "A02:2021 - Cryptographic Failures",     # Inadequate Encryption Strength
    "CWE-327": "A02:2021 - Cryptographic Failures",     # Broken Crypto Algorithm
    "CWE-328": "A02:2021 - Cryptographic Failures",     # Reversible One-Way Hash
    "CWE-614": "A02:2021 - Cryptographic Failures",     # Cookie Without Secure Flag
    "CWE-757": "A02:2021 - Cryptographic Failures",     # Insecure Algorithm Selection

    # A03: Injection
    "CWE-77":  "A03:2021 - Injection",                  # Command Injection
    "CWE-78":  "A03:2021 - Injection",                  # OS Command Injection
    "CWE-79":  "A03:2021 - Injection",                  # Cross-Site Scripting (XSS)
    "CWE-89":  "A03:2021 - Injection",                  # SQL Injection
    "CWE-90":  "A03:2021 - Injection",                  # LDAP Injection
    "CWE-91":  "A03:2021 - Injection",                  # XML Injection
    "CWE-94":  "A03:2021 - Injection",                  # Code Injection
    "CWE-98":  "A03:2021 - Injection",                  # File Inclusion (LFI/RFI)
    "CWE-116": "A03:2021 - Injection",                  # Improper Output Encoding
    "CWE-611": "A03:2021 - Injection",                  # XML External Entity (XXE)
    "CWE-917": "A03:2021 - Injection",                  # SSTI (Expression Language)
    "CWE-1336": "A03:2021 - Injection",                 # Template Injection

    # A04: Insecure Design
    "CWE-209": "A04:2021 - Insecure Design",            # Info Exposure via Error Message
    "CWE-256": "A04:2021 - Insecure Design",            # Unprotected Credentials
    "CWE-501": "A04:2021 - Insecure Design",            # Trust Boundary Violation
    "CWE-522": "A04:2021 - Insecure Design",            # Insufficiently Protected Credentials

    # A05: Security Misconfiguration
    "CWE-16":  "A05:2021 - Security Misconfiguration",  # Configuration
    "CWE-209": "A05:2021 - Security Misconfiguration",  # Error Messages
    "CWE-497": "A05:2021 - Security Misconfiguration",  # Exposure of Sys Info
    "CWE-524": "A05:2021 - Security Misconfiguration",  # Cache Control Issues
    "CWE-615": "A05:2021 - Security Misconfiguration",  # HTML Comment Info Leak
    "CWE-693": "A05:2021 - Security Misconfiguration",  # Protection Mechanism Failure
    "CWE-942": "A05:2021 - Security Misconfiguration",  # Overly Permissive CORS
    "CWE-1004": "A05:2021 - Security Misconfiguration", # Cookie Without HttpOnly
    "CWE-1021": "A05:2021 - Security Misconfiguration", # Improper Restriction of Frame

    # A06: Vulnerable and Outdated Components
    "CWE-1035": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-1104": "A06:2021 - Vulnerable and Outdated Components",

    # A07: Identification and Authentication Failures
    "CWE-287": "A07:2021 - Identification and Authentication Failures",
    "CWE-307": "A07:2021 - Identification and Authentication Failures",
    "CWE-384": "A07:2021 - Identification and Authentication Failures",
    "CWE-613": "A07:2021 - Identification and Authentication Failures",
    "CWE-640": "A07:2021 - Identification and Authentication Failures",
    "CWE-798": "A07:2021 - Identification and Authentication Failures",

    # A08: Software and Data Integrity Failures
    "CWE-345": "A08:2021 - Software and Data Integrity Failures",
    "CWE-347": "A08:2021 - Software and Data Integrity Failures",
    "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-565": "A08:2021 - Software and Data Integrity Failures",

    # A09: Security Logging and Monitoring Failures
    "CWE-117": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-223": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-778": "A09:2021 - Security Logging and Monitoring Failures",

    # A10: Server-Side Request Forgery (SSRF)
    "CWE-918": "A10:2021 - Server-Side Request Forgery (SSRF)",
}


def get_owasp_category(cwe_reference: Optional[str]) -> Optional[str]:
    """
    Look up the OWASP Top 10 2021 category for a given CWE reference.

    Args:
        cwe_reference: CWE string like "CWE-79" or "CWE-89"

    Returns:
        OWASP category string or None if not mapped
    """
    if not cwe_reference:
        return None

    # Normalize: handle "CWE-79", "cwe-79", "79"
    cwe = cwe_reference.strip().upper()
    if not cwe.startswith("CWE-"):
        cwe = f"CWE-{cwe}"

    return CWE_TO_OWASP.get(cwe)
