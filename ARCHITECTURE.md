# Project Architecture - CyberDev Security Scanner v3.0

## Overview

A comprehensive web vulnerability scanner written in Python. It performs reconnaissance, content analysis, web technology intelligence, and vulnerability testing across a 25-step pipeline, producing scored reports with executive summaries.

## Project Tree

```
CyberDev/
|-- main.py                    # Application entry point
|-- cli.py                     # CLI interface and argument parsing
|-- config.py                  # Central configuration and constants
|-- models.py                  # Data models (Finding, ReconData, ScanResult)
|-- requirements.txt           # Dependencies
|
|-- scanner/                   # Core scan engine
|   |-- core/                  # Core orchestration
|   |   |-- scanner_orchestrator.py  # 25-step scan orchestrator
|   |   |-- http_handler.py          # HTTP request handler
|   |   |-- requester.py             # Request manager with retry logic
|   |   +-- base_check.py            # Base check class
|   |
|   |-- recon/                 # Reconnaissance & analysis modules
|   |   |-- recon_analyzer.py        # Whois/DNS/GeoIP/SSL/Hosting/Port Risk
|   |   |-- headers_analyzer.py      # Security headers analysis
|   |   |-- cors_analyzer.py         # CORS analysis (passive + active)
|   |   |-- cookie_analyzer.py       # Cookie security analysis
|   |   |-- content_analyzer.py      # Content and secrets analysis
|   |   |-- data_leakage_scanner.py  # Data leakage detection
|   |   |-- web_tech_analyzer.py     # CMS/JS framework/API key/Form detection
|   |   |-- robots_check.py          # robots.txt analysis
|   |   |-- link_crawler.py          # Web crawler for URL discovery
|   |   +-- explore_fuzzer.py        # Directory fuzzing & sensitive files
|   |
|   +-- vulnerabilities/       # Vulnerability scanners (18)
|       |-- vuln_sqli.py             # SQL Injection
|       |-- vuln_xss.py              # Cross-Site Scripting
|       |-- vuln_rce.py              # Remote Code Execution
|       |-- vuln_lfi.py              # Local File Inclusion
|       |-- vuln_ssrf.py             # Server-Side Request Forgery
|       |-- vuln_ssti.py             # Template Injection
|       |-- vuln_xxe.py              # XML External Entity
|       |-- vuln_jwt.py              # JWT Security
|       |-- vuln_graphql.py          # GraphQL Security
|       |-- vuln_redirect.py         # Open Redirect
|       |-- vuln_host_header.py      # Host Header Injection
|       |-- vuln_cache_poisoning.py  # Cache Poisoning
|       |-- vuln_auth_workflow.py    # Authentication Flaws
|       |-- vuln_upload_checks.py    # File Upload Security
|       |-- vuln_api_security.py     # API Security
|       |-- vuln_websocket.py        # WebSocket Security
|       +-- vuln_deserialization.py  # Insecure Deserialization
|
|-- report/                    # Report system
|   +-- report_formatter.py   # Formats: CLI, JSON, HTML, Markdown, CSV
|
|-- sessions/                  # Session persistence
|   |-- session_logger.py      # Session save/load
|   +-- scan_sessions/         # Saved scan JSON files
|
|-- ui/                        # User interface
|   |-- menus.py               # Interactive menus with score display
|   |-- scan_progress.py       # Progress bar with severity-colored symbols
|   |-- colors.py              # ANSI color constants
|   |-- logo.py                # Tool logo
|   +-- progress.py            # Progress bar utility
|
+-- utils/                     # Utilities
    |-- helpers.py             # General helper functions
    |-- network.py             # Network utilities
    |-- severity.py            # Severity level classification
    |-- scoring.py             # Security scoring engine (grade, sections, posture)
    +-- owasp_mapping.py       # CWE-to-OWASP category mapping
```

---

## 25-Step Scan Pipeline

### Phase 1: Reconnaissance (Steps 1-4)

```
Step 1: recon_analyzer.py
  |-- Whois lookup & domain info
  |-- DNS resolution & SPF/DMARC
  |-- Port scanning (parallel)
  |-- Geolocation (ip-api.com)
  |-- Hosting provider detection
  |-- CDN/WAF detection
  |-- SSL/TLS certificate analysis
  +-- Subdomain enumeration (crt.sh)

Step 2: recon_analyzer.classify_port_risks()
  +-- Generates findings for dangerous open ports
      (MySQL, Redis, MongoDB, PostgreSQL, etc.)

Step 3: headers_analyzer.py
  +-- Security headers check (CSP, HSTS, X-Frame-Options, etc.)

Step 4: cors_analyzer.py
  |-- Passive: wildcard ACAO, credential exposure, null origin
  +-- Active: Origin reflection test (sends Origin: https://evil.com)
```

### Phase 2: Content Analysis (Steps 5-8)

```
Step 5: cookie_analyzer.py
  +-- Cookie security flags (Secure, HttpOnly, SameSite)

Step 6: content_analyzer.py
  +-- Secrets and sensitive data in HTML

Step 7: data_leakage_scanner.py
  +-- Data leakage patterns detection

Step 8: robots_check.py
  +-- robots.txt analysis for sensitive paths
```

### Phase 3: Intelligence & Discovery (Steps 9-11)

```
Step 9: web_tech_analyzer.py
  |-- CMS detection (WordPress, Joomla, Drupal)
  |-- CMS version probing
  |-- JS framework detection (React, Angular, Vue, jQuery, etc.)
  |-- JS file extraction
  |-- API key scanning in JS files (10 patterns)
  +-- Form enumeration with CSRF check

Step 10: link_crawler.py
  +-- Web crawling for URLs with parameters

Step 11: explore_fuzzer.py
  +-- Directory fuzzing & sensitive file detection
```

### Phase 4: Vulnerability Testing (Steps 12-24)

```
Step 12: vuln_sqli.py        # SQL Injection
Step 13: vuln_xss.py         # Cross-Site Scripting
Step 14: vuln_rce.py         # Remote Code Execution
Step 15: vuln_lfi.py         # Local File Inclusion
Step 16: vuln_ssrf.py        # SSRF
Step 17: vuln_ssti.py        # Template Injection
Step 18: vuln_redirect.py    # Open Redirect
Step 19: vuln_host_header.py # Host Header Injection
Step 20: vuln_jwt.py + vuln_graphql.py + vuln_deserialization.py
Step 21: vuln_auth_workflow.py  # Authentication & Session
Step 22: vuln_upload_checks.py + vuln_xxe.py  # File Upload & XXE
Step 23: vuln_api_security.py + vuln_websocket.py  # API & WebSocket
Step 24: vuln_cache_poisoning.py  # Cache Poisoning
```

### Phase 5: Scoring & Output (Step 25)

```
Step 25: scoring.py
  |-- Calculate weighted security score (0-100)
  |-- Assign letter grade (A-F)
  |-- Section-level breakdown
  +-- Generate executive summary with posture text
```

---

## Data Models (models.py)

### Finding
```python
@dataclass
class Finding:
    title: str              # Finding name
    severity: str           # CRITICAL|HIGH|MEDIUM|LOW|INFO
    description: str        # Explanation
    location: str           # URL or component
    recommendation: str     # How to fix
    cwe_reference: str      # CWE ID
    confidence: str         # High|Medium|Low
    owasp_category: str     # Auto-mapped from CWE
    evidence: str           # Proof (max 500 chars)
    category: str           # Header Security, Injection, etc.
    hit_count: int          # Deduplication merge count
    finding_id: str         # Unique ID (auto-generated)
```

### ReconData
```python
@dataclass
class ReconData:
    ip_address: str
    domain_info: Dict       # Whois data
    server_os: str
    technologies: List[str]
    open_ports: List[int]
    dns_security: Dict      # SPF/DMARC
    subdomains: List[str]
    geolocation: Dict       # Country, city, ISP, ASN
    hosting_provider: Dict  # Provider, type, cloud platform
    cdn_waf: Dict           # CDN name, WAF name
    ssl_info: Dict          # Version, cipher, issuer, expiry
```

### ScanResult
```python
@dataclass
class ScanResult:
    session_id: str
    target_url: str
    timestamp: datetime
    findings: List[Finding]
    https_enabled: bool
    redirect_chain: List[str]
    recon: ReconData
    scan_duration: float        # Seconds
    scan_profile: str           # passive, standard, extended
    score_data: Dict            # Grade, score, sections
    executive_summary: Dict     # Posture, risks, recommendations
    attack_surface: Dict        # CMS, JS, forms, API keys, ports
    tool_version: str
```

All models support `to_dict()` and `from_dict()` for full JSON serialization round-trips.

---

## Security Scoring Engine (utils/scoring.py)

### Score Calculation
- Starts at 100, deducts per finding based on severity
- Penalties: CRITICAL=20, HIGH=10, MEDIUM=5, LOW=3, INFO=1
- Per-severity caps: CRITICAL=60, HIGH=40, MEDIUM=25, LOW=12, INFO=5
- Highest severity caps the posture text

### Grade Boundaries
| Grade | Score | Posture |
|-------|-------|---------|
| A | >= 90 | EXCELLENT |
| B | >= 75 | GOOD |
| C | >= 60 | MODERATE |
| D | >= 40 | WEAK |
| F | < 40 | CRITICAL/POOR |

### Section Scoring
Findings are grouped into sections via `CATEGORY_TO_SECTION` mapping:
- Transport Security
- Header Security
- Content Security
- Cookie Security
- CORS Security
- Network Security
- Authentication & Session
- Injection Vulnerabilities
- Application Security
- API Security

---

## Report Formatter (report/report_formatter.py)

### Supported Formats

```python
ReportFormatter(scan_result)
|-- format_cli_output()    # Colored terminal output
|-- format_json()          # Full JSON via to_dict()
|-- format_html()          # HTML with score dashboard, charts, evidence
|-- format_markdown()      # Markdown with tables
+-- format_csv()           # CSV with metadata + attack surface + findings
```

All formats include:
- Scan metadata (target, session, profile, duration)
- Security score and grade
- Executive summary (posture, risks, recommendations)
- Reconnaissance (target info, technologies, geolocation, hosting, CDN/WAF, SSL, DNS, subdomains)
- Attack surface overview (CMS, JS frameworks, JS files, forms, API keys, ports)
- Findings summary (severity counts)
- Detailed findings with CWE/OWASP references

---

## Configuration (config.py)

```python
TOOL_NAME = "Safe Web Vulnerability Checker"
TOOL_VERSION = "1.0.0"

SCAN_PROFILES = {
    'passive':  {'display_name': 'Quick Scan',  ...},
    'standard': {'display_name': 'Full Scan',   ...},
    'extended': {'display_name': 'Deep Audit',  ...},
}

CRAWLER_MAX_DEPTH = 2
CRAWLER_MAX_URLS = 30
COMMON_PORTS = [80, 443, 22, 21, 25, 53, 3306, 5432, 8080, 8443]
```

---

## Data Flow

```
User Input (URL)
    |
    v
CLI Interface (cli.py / menus.py)
    |
    v
Scanner Orchestrator (25 steps)
    |
    |-- Step 1: Reconnaissance (Whois, DNS, Ports, Geo, SSL)
    |-- Step 2: Port Risk Classification
    |-- Step 3: Security Headers
    |-- Step 4: CORS (Passive + Active)
    |-- Step 5-8: Cookie, Content, Data Leakage, Robots
    |-- Step 9: Web Tech Intelligence (CMS, JS, API Keys)
    |-- Step 10-11: Link Crawling, Directory Fuzzing
    |-- Step 12-24: Vulnerability Scanners (18 types)
    |-- Step 25: Security Scoring + Executive Summary
    |
    v
Finding Deduplication (dedup_key: title + location)
    |
    v
ScanResult Object
    |
    +-- Session Logger (auto-save JSON)
    |
    v
Report Formatter
    |
    +-- CLI / JSON / HTML / Markdown / CSV
```

---

## Adding a New Scanner

1. Create `scanner/vulnerabilities/vuln_new.py`:
```python
from models import Finding
import logging

logger = logging.getLogger(__name__)

class NewScanner:
    def scan(self, url, headers=None):
        findings = []
        # scanning logic...
        return findings
```

2. Import and wire in `scanner_orchestrator.py`:
```python
from scanner.vulnerabilities.vuln_new import NewScanner
# In __init__:
self.new_scanner = NewScanner()
# In scan():
step_findings = self.new_scanner.scan(url)
```

3. Update `steps_total` count.

---

## Dependencies

```
requests          # HTTP requests
beautifulsoup4    # HTML parsing
python-whois      # Whois lookups
dnspython         # DNS queries
fake-useragent    # Random User-Agents
certifi           # SSL certificates
urllib3           # Warning suppression
```

---

**CyberDev Security Scanner**
**Version:** 3.0
**Date:** February 2026
