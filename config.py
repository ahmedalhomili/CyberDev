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

# Parameter Discovery Configuration
PARAM_DISCOVERY_MAX_JS_FILES = 10      # Max JS files to download and parse
PARAM_DISCOVERY_MAX_PARAMS = 5         # Max params per endpoint to test
PARAM_DISCOVERY_MAX_BRUTE = 15         # Max common params to bruteforce per path
PARAM_DISCOVERY_TIMEOUT = 5            # Per-request timeout in seconds

# Port Scanning Configuration
PORT_SCAN_TIMEOUT = 0.8                # Socket timeout per port (seconds)
PORT_SCAN_THREADS = 30                 # Concurrent threads for port scanning
COMMON_PORTS = [
    # ═══ Web Services ═══
    80, 443, 8080, 8443, 8000, 8888, 8008, 8181, 8888, 9090, 9443,
    # ═══ Remote Access ═══
    22, 23, 3389, 5900, 5901,
    # ═══ Email ═══
    25, 110, 143, 465, 587, 993, 995,
    # ═══ File Transfer ═══
    20, 21, 69, 115, 989, 990,
    # ═══ Databases ═══
    1433, 1521, 3306, 5432, 6379, 9200, 9300, 27017, 27018,
    # ═══ DNS ═══
    53,
    # ═══ Directory / Auth ═══
    88, 389, 636, 445, 139,
    # ═══ Message Queues ═══
    5672, 15672, 11211, 61616,
    # ═══ Monitoring / Admin ═══
    161, 162, 199, 2049, 5601, 3000, 4443, 7001, 7002, 8090, 10000,
    # ═══ Proxy / VPN ═══
    1080, 3128, 8118, 1194,
    # ═══ Docker / Kubernetes ═══
    2375, 2376, 6443, 10250, 10255,
    # ═══ CI/CD / Dev Tools ═══
    8081, 8082, 9000, 9001, 4200, 5000, 5001,
]

# CORS Reference
CORS_UNSAFE_PATTERNS = {
    'wildcard': '*',
    'wildcard_with_credentials': ('*', True)
}
