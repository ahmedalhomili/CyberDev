"""
Configuration module for Safe Web Vulnerability Checker.
Contains constants, defaults, and security reference data.
"""

# Security Headers Reference
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'required': True,
        'severity_if_missing': 'HIGH',
        'min_max_age': 31536000,  # 1 year
        'description': 'Enforces HTTPS connections (RFC 6797)'
    },
    'Content-Security-Policy': {
        'required': True,
        'severity_if_missing': 'MEDIUM',
        'description': 'Prevents XSS and injection attacks'
    },
    'X-Frame-Options': {
        'required': True,
        'severity_if_missing': 'MEDIUM',
        'valid_values': ['DENY', 'SAMEORIGIN', 'ALLOW-FROM'],
        'description': 'Prevents clickjacking attacks'
    },
    'X-Content-Type-Options': {
        'required': True,
        'severity_if_missing': 'LOW',
        'expected_value': 'nosniff',
        'description': 'Prevents MIME-sniffing attacks'
    }
}

# Severity Levels
SEVERITY_LEVELS = {
    'HIGH': {'symbol': '🔴', 'color': 'red', 'priority': 1},
    'MEDIUM': {'symbol': '🟠', 'color': 'yellow', 'priority': 2},
    'LOW': {'symbol': '🟢', 'color': 'green', 'priority': 3}
}

# Logging Configuration
LOG_DIR = './sessions/scan_sessions'
LOG_FORMAT = '%(timestamp)s - %(level)s - %(message)s'
MAX_RETRIES = 3
REQUEST_TIMEOUT = 10  # seconds

# CORS Reference
CORS_UNSAFE_PATTERNS = {
    'wildcard': '*',
    'wildcard_with_credentials': ('*', True)
}
