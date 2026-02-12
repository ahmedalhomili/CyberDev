# Change Log - CyberDev Security Scanner

## [v3.0.0] - 2026-02-12

### New Modules
- **Web Technology Analyzer** (`scanner/recon/web_tech_analyzer.py`)
  - CMS detection: WordPress, Joomla, Drupal with version probing
  - JS framework detection: React, Angular, Vue, jQuery, Next.js, Nuxt.js, Bootstrap, Tailwind, Svelte
  - API key scanning in JS files (10 patterns: Google, AWS, Stripe, GitHub, Slack, etc.)
  - HTML form enumeration with CSRF token absence check
- **Cookie Analyzer** (`scanner/recon/cookie_analyzer.py`)
  - Cookie security flags: Secure, HttpOnly, SameSite
- **Data Leakage Scanner** (`scanner/recon/data_leakage_scanner.py`)
  - Detects data leakage patterns in responses
- **Security Scoring Engine** (`utils/scoring.py`)
  - Weighted score (0-100) with severity penalties: CRITICAL=20, HIGH=10, MEDIUM=5, LOW=3, INFO=1
  - Per-severity caps prevent disproportionate scoring
  - Letter grades: A (>=90), B (>=75), C (>=60), D (>=40), F (<40)
  - Section-level breakdown (10 sections)
  - Executive summary with dynamic posture text
- **OWASP Mapping** (`utils/owasp_mapping.py`)
  - CWE-to-OWASP Top 10 category auto-mapping

### Enhanced Modules
- **CORS Analyzer** - Added active origin reflection test (sends `Origin: https://evil.com`)
- **Recon Analyzer** - Added `classify_port_risks()` for dangerous port detection (11 ports), fixed orphaned subdomain enumeration code
- **Scanner Orchestrator** - Expanded from 21 to 25 steps, integrated all new modules
- **Report Formatter** - All 4 export formats (HTML/JSON/CSV/MD) now include:
  - Security score and grade
  - Executive summary
  - Infrastructure data (geolocation, hosting, CDN/WAF, SSL)
  - Attack surface overview (CMS, JS frameworks, forms, API keys)
- **CSV Export** - Complete rewrite with metadata, attack surface, and findings sections
- **HTML Export** - Added Infrastructure section with geolocation, hosting, CDN, SSL
- **Markdown Export** - Added geolocation, hosting, CDN/WAF, SSL/TLS sections

### Data Model Updates
- **ReconData** - Added proper fields: `geolocation`, `hosting_provider`, `cdn_waf`, `ssl_info` (were dynamic attributes, now dataclass fields with full serialization)
- **ScanResult** - Added `attack_surface` field with `to_dict()`/`from_dict()` support
- **Finding** - `dedup_key` property for deduplication, `hit_count` for merge tracking

### UX Improvements
- Scan profiles with display names: Quick Scan, Full Scan, Deep Audit
- Progress bar with severity-colored check marks
- Score/grade display in scan summary
- INFO count added to summary output
- `show` command now renders full formatted report (was raw JSON)
- Session history viewer uses `ScanResult.from_dict()` for complete data restoration
- Suppressed urllib3 `InsecureRequestWarning` spam

### Configuration
- Added `display_name` to each scan profile in `SCAN_PROFILES`
- CLI `--profile` help text shows display names

---

## [v1.1.1] - 2026-02-02

### New Features

#### help and man commands
- Added `help` command - quick help guide with examples
  ```bash
  python main.py help
  ```
- Added `man` command - comprehensive manual (Linux man page style)
  ```bash
  python main.py man
  ```

#### Updates
- Updated `--help` to show new commands
- Added scan level documentation
- Added advanced usage examples

---

## [v1.1.0] - 2026-02-02

### Critical Fixes

1. **Deleted** duplicate `utils/allMenus.py`
2. **Added** `--level` CLI argument in `cli.py`
3. **Added** `from_dict()` deserialization methods in `models.py`

### Quality Improvements

4. **Moved** hardcoded values to `config.py`:
   ```python
   CRAWLER_MAX_DEPTH = 2
   CRAWLER_MAX_URLS = 30
   CRAWLER_TIMEOUT = 10
   PORT_SCAN_TIMEOUT = 1.5
   ```

### Verification
```bash
models.py import successful
Config loaded: depth=2, urls=30, port_timeout=1.5
Finding serialization works
ReconData serialization works
CLI --level argument working
```

### Files Modified
1. Deleted: `utils/allMenus.py`
2. Modified: `cli.py` (+3 lines)
3. Modified: `models.py` (+58 lines)
4. Modified: `config.py` (+11 lines)
5. Modified: `scanner/core/scanner_orchestrator.py`
