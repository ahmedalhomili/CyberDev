"""
Configuration module for Safe Web Vulnerability Checker.
Contains constants, defaults, and security reference data.
"""

# Tool Metadata
TOOL_NAME = "Safe Web Vulnerability Checker"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Academic Security Assessment Framework"

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

# Reports directory (top-level folder where format-specific subfolders will be created)
# Example structure after export: ./reports/json, ./reports/html, ./reports/md, ./reports/csv, ./reports/pdf
REPORTS_DIR = './reports'

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
PORT_SCAN_THREADS = 74                 # Concurrent threads for port scanning
COMMON_PORTS_MAP = {
    # Web Services
    'http': 80,
    'https': 443,
    'http-alt': 8080,
    'https-alt': 8443,
    'http-local': 8000,
    'http-alt2': 8008,
    'tomcat': 8181,
    'dev-web': 8888,
    'jetty': 9090,
    'https-9443': 9443,

    # Remote Access
    'ssh': 22,
    'telnet': 23,
    'rdp': 3389,
    'vnc': 5900,
    'vnc-alt': 5901,

    # Email
    'smtp': 25,
    'pop3': 110,
    'imap': 143,
    'smtps': 465,
    'submission': 587,
    'imaps': 993,
    'pop3s': 995,

    # File Transfer
    'ftp-data': 20,
    'ftp': 21,
    'tftp': 69,
    'nfs': 2049,
    'ftps': 989,
    'ftps-data': 990,

    # Databases
    'mssql': 1433,
    'oracle': 1521,
    'mysql': 3306,
    'postgres': 5432,
    'redis': 6379,
    'elasticsearch': 9200,
    'elasticsearch-transport': 9300,
    'mongodb': 27017,
    'mongodb-alt': 27018,

    # DNS
    'dns': 53,

    # Directory / Auth
    'kerberos': 88,
    'ldap': 389,
    'ldaps': 636,
    'samba': 445,
    'netbios-ssn': 139,

    # Message Queues
    'amqp': 5672,
    'rabbitmq-mgmt': 15672,
    'memcached': 11211,
    'activemq': 61616,

    # Monitoring / Admin
    'snmp': 161,
    'snmp-trap': 162,
    'rsync': 873,
    'nfs-alt': 199,
    'cassandra': 9042,
    'kibana': 5601,
    'grafana': 3000,
    'node-admin': 4443,
    'weblogic': 7001,
    'weblogic-ssl': 7002,
    'tomcat-admin': 8090,
    'webmin': 10000,

    # Proxy / VPN
    'socks': 1080,
    'squid': 3128,
    'privoxy': 8118,
    'openvpn': 1194,

    # Docker / Kubernetes
    'docker': 2375,
    'docker-tls': 2376,
    'k8s-api': 6443,
    'k8s-kube': 10250,
    'k8s-proxy': 10255,

    # CI/CD / Dev Tools
    'sonarqube': 9000,
    'jenkins': 8081,
    'jenkins-alt': 8082,
    'vscode-server': 9001,
    'react-dev': 4200,
    'flask': 5000,
    'flask-alt': 5001,
}

# Backwards-compatible list of common port numbers
COMMON_PORTS = list(COMMON_PORTS_MAP.values())

# Map port number -> canonical name for display in reports
COMMON_PORTS_NUM_TO_NAME = {num: name for name, num in COMMON_PORTS_MAP.items()}

# CORS Reference
CORS_UNSAFE_PATTERNS = {
    'wildcard': '*',
    'wildcard_with_credentials': ('*', True)
}

# Scan Profiles
SCAN_PROFILES = {
    "passive": {
        "display_name": "Quick Scan",
        "description": "Passive reconnaissance only (no active vulnerability testing)",
        "enable_vuln_scanners": False,
        "enable_fuzzer": False,
        "enable_data_leakage": True,
        "enable_cookie_analysis": True,
        "max_redirects": 5,
        "timeout": 10,
    },
    "standard": {
        "display_name": "Full Scan",
        "description": "Standard scan (passive + active vulnerability testing)",
        "enable_vuln_scanners": True,
        "enable_fuzzer": True,
        "enable_data_leakage": True,
        "enable_cookie_analysis": True,
        "max_redirects": 10,
        "timeout": 10,
        "max_paths": 300,
    },
    "extended": {
        "display_name": "Deep Audit",
        "description": "Extended scan (comprehensive analysis with all checks enabled)",
        "enable_vuln_scanners": True,
        "enable_fuzzer": True,
        "enable_data_leakage": True,
        "enable_cookie_analysis": True,
        "max_redirects": 15,
        "timeout": 15,
        "max_paths": 500,
    },
}

# Ethical Disclaimer
ETHICAL_DISCLAIMER = (
    "DISCLAIMER: This report was generated by Safe Web Vulnerability Checker, "
    "an academic security assessment tool. This tool is intended for authorized "
    "security testing and educational purposes only. Unauthorized scanning of "
    "systems you do not own or have explicit permission to test may violate "
    "applicable laws. Always obtain written authorization before conducting "
    "security assessments."
)
