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
    'CRITICAL': {'symbol': '🔴', 'color': 'red', 'priority': 0},
    'HIGH': {'symbol': '🔴', 'color': 'red', 'priority': 1},
    'MEDIUM': {'symbol': '🟠', 'color': 'yellow', 'priority': 2},
    'LOW': {'symbol': '🟢', 'color': 'green', 'priority': 3},
    'INFO': {'symbol': '🔵', 'color': 'blue', 'priority': 4}
}

# Logging Configuration
LOG_DIR = './sessions/scan_sessions'
LOG_FORMAT = '%(timestamp)s - %(level)s - %(message)s'
MAX_RETRIES = 3
REQUEST_TIMEOUT = 10  # seconds

# Link Crawler Configuration
CRAWLER_MAX_DEPTH = 2
CRAWLER_MAX_URLS = 30
CRAWLER_TIMEOUT = 10

# Port Scanning Configuration
PORT_SCAN_TIMEOUT = 1.5
PORT_SCAN_MAX_PORTS = 10
COMMON_PORTS = [80, 443, 22, 21, 25, 53, 3306, 5432, 8080, 8443]

# CORS Reference
CORS_UNSAFE_PATTERNS = {
    'wildcard': '*',
    'wildcard_with_credentials': ('*', True)
}
