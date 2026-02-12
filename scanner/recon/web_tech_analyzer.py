"""
Web Technology Intelligence Module.
Detects CMS platforms, JavaScript frameworks, extracts JS files,
scans for API keys in JavaScript, and enumerates HTML forms.
"""
import re
import logging
import requests
import urllib3
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin, urlparse
from models import Finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class WebTechAnalyzer:
    """Passive and semi-active web technology fingerprinting and intelligence."""

    # CMS fingerprint signatures: marker -> CMS name
    CMS_SIGNATURES = {
        "wordpress": {
            "markers": ["wp-content", "wp-includes", "wp-admin", "wp-json"],
            "meta_generator": r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]*)',
            "version_paths": [
                "/readme.html",
                "/wp-includes/version.php",
            ],
            "version_regex": r'Version\s+([\d.]+)',
        },
        "joomla": {
            "markers": ["/administrator", "/components/com_", "/media/jui/"],
            "meta_generator": r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla[!]?\s*([\d.]*)',
            "version_paths": [
                "/administrator/manifests/files/joomla.xml",
            ],
            "version_regex": r'<version>([\d.]+)</version>',
        },
        "drupal": {
            "markers": ["/sites/default/files", "Drupal.settings", "/misc/drupal.js"],
            "meta_generator": r'<meta[^>]+name=["\']Generator["\'][^>]+content=["\']Drupal\s*([\d.]*)',
            "version_paths": [
                "/CHANGELOG.txt",
            ],
            "version_regex": r'Drupal\s+([\d.]+)',
        },
    }

    # JS framework detection patterns in HTML/JS content
    JS_FRAMEWORK_SIGNATURES = {
        "React": [r'react\.production\.min\.js', r'react-dom', r'__REACT_DEVTOOLS', r'data-reactroot', r'_reactRootContainer'],
        "Angular": [r'angular\.min\.js', r'ng-app', r'ng-controller', r'angular\.module', r'ng-version'],
        "Vue.js": [r'vue\.min\.js', r'vue\.js', r'__vue__', r'v-bind', r'v-model', r'data-v-'],
        "jQuery": [r'jquery[-.][\d.]+\.min\.js', r'jquery\.min\.js', r'jquery\.js'],
        "Next.js": [r'_next/static', r'__NEXT_DATA__', r'next/dist'],
        "Nuxt.js": [r'__nuxt', r'_nuxt/', r'nuxt\.js'],
        "Bootstrap": [r'bootstrap\.min\.css', r'bootstrap\.min\.js', r'bootstrap\.bundle'],
        "Tailwind CSS": [r'tailwindcss', r'tailwind\.min\.css'],
        "Svelte": [r'svelte-', r'__svelte'],
    }

    # API key patterns to scan in JavaScript files
    JS_API_KEY_PATTERNS = {
        "Google API Key": r'AIza[0-9A-Za-z_\\-]{35}',
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "Stripe Publishable Key": r'pk_(?:live|test)_[0-9a-zA-Z]{24,}',
        "Stripe Secret Key": r'sk_(?:live|test)_[0-9a-zA-Z]{24,}',
        "GitHub Token": r'gh[ps]_[A-Za-z0-9_]{36,}',
        "Slack Token": r'xox[baprs]-[0-9A-Za-z\-]{10,}',
        "Firebase Key": r'AIza[0-9A-Za-z_\\-]{35}',
        "Generic API Key": r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
        "Generic Secret": r'(?:secret|password|passwd|token)\s*[:=]\s*["\'][a-zA-Z0-9_\-/+=]{12,}["\']',
        "Private Key Block": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    }

    def __init__(self):
        self.attack_surface: Dict[str, Any] = {
            "cms": None,
            "cms_version": None,
            "js_frameworks": [],
            "js_files": [],
            "forms": [],
            "api_keys_found": 0,
        }

    def analyze(self, url: str, html_content: str) -> List[Finding]:
        """
        Run all web technology analyses.

        Args:
            url: Target URL
            html_content: HTML page content

        Returns:
            List of Finding objects
        """
        if not html_content:
            return []

        findings = []

        # 1. CMS Detection
        cms_findings = self._detect_cms(url, html_content)
        findings.extend(cms_findings)

        # 2. JS Framework Detection
        self._detect_js_frameworks(html_content)

        # 3. JS File Extraction
        js_files = self._extract_js_files(url, html_content)
        self.attack_surface["js_files"] = js_files

        # 4. API Key Scanning in JS files
        api_key_findings = self._scan_js_for_api_keys(js_files)
        findings.extend(api_key_findings)

        # 5. Form Enumeration
        form_findings = self._enumerate_forms(url, html_content)
        findings.extend(form_findings)

        return findings

    def get_attack_surface_data(self) -> Dict[str, Any]:
        """Return collected attack surface intelligence for reporting."""
        return self.attack_surface.copy()

    def _detect_cms(self, url: str, html_content: str) -> List[Finding]:
        """Detect CMS platform and attempt version identification."""
        findings = []
        content_lower = html_content.lower()

        for cms_name, config in self.CMS_SIGNATURES.items():
            detected = False

            # Check HTML markers
            for marker in config["markers"]:
                if marker.lower() in content_lower:
                    detected = True
                    break

            # Check meta generator tag
            if not detected and config.get("meta_generator"):
                match = re.search(config["meta_generator"], html_content, re.IGNORECASE)
                if match:
                    detected = True

            if detected:
                display_name = cms_name.capitalize()
                self.attack_surface["cms"] = display_name

                findings.append(Finding(
                    title=f"CMS Detected: {display_name}",
                    severity="INFO",
                    description=f"The target appears to be running {display_name} CMS. "
                               f"This information can be used to search for known vulnerabilities.",
                    location=url,
                    recommendation=f"Keep {display_name} and all plugins updated to the latest version.",
                    confidence="High",
                    category="Information Disclosure",
                    evidence=f"CMS fingerprint markers found in page content.",
                ))

                # Attempt version detection
                version = self._detect_cms_version(url, cms_name, config, html_content)
                if version:
                    self.attack_surface["cms_version"] = version
                    findings.append(Finding(
                        title=f"{display_name} Version Disclosed: {version}",
                        severity="LOW",
                        description=f"{display_name} version {version} detected. "
                                   f"Version disclosure helps attackers identify known vulnerabilities for this specific version.",
                        location=url,
                        recommendation=f"Remove version information from public-facing pages. "
                                      f"Update to the latest {display_name} version.",
                        cwe_reference="CWE-200",
                        confidence="High",
                        category="Information Disclosure",
                        evidence=f"Version: {version}",
                    ))

                break  # Only report the first CMS match

        return findings

    def _detect_cms_version(self, url: str, cms_name: str, config: dict, html_content: str) -> Optional[str]:
        """Attempt to detect CMS version from meta tags or version files."""
        # Check meta generator for version
        if config.get("meta_generator"):
            match = re.search(config["meta_generator"], html_content, re.IGNORECASE)
            if match and match.group(1):
                return match.group(1).strip()

        # Probe version files
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for version_path in config.get("version_paths", []):
            try:
                resp = requests.get(
                    urljoin(base_url, version_path),
                    timeout=5,
                    verify=False,
                    allow_redirects=False,
                )
                if resp.status_code == 200 and config.get("version_regex"):
                    match = re.search(config["version_regex"], resp.text)
                    if match:
                        return match.group(1).strip()
            except Exception:
                continue

        return None

    def _detect_js_frameworks(self, html_content: str):
        """Detect JavaScript frameworks from page content."""
        detected = []
        for framework, patterns in self.JS_FRAMEWORK_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    detected.append(framework)
                    break

        self.attack_surface["js_frameworks"] = detected

    def _extract_js_files(self, url: str, html_content: str) -> List[str]:
        """Extract all JavaScript file URLs from HTML."""
        js_files = []
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        # Find all script src attributes
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        matches = re.findall(script_pattern, html_content, re.IGNORECASE)

        for src in matches:
            if src.startswith("//"):
                full_url = f"https:{src}"
            elif src.startswith("http"):
                full_url = src
            elif src.startswith("/"):
                full_url = urljoin(base_url, src)
            else:
                full_url = urljoin(url, src)

            js_files.append(full_url)

        return js_files

    def _scan_js_for_api_keys(self, js_files: List[str]) -> List[Finding]:
        """Download and scan JavaScript files for embedded API keys."""
        findings = []
        scanned = 0
        max_files = 10

        for js_url in js_files[:max_files]:
            # Skip external CDN libraries
            parsed = urlparse(js_url)
            if any(cdn in parsed.netloc for cdn in [
                "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
                "ajax.googleapis.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
            ]):
                continue

            try:
                resp = requests.get(js_url, timeout=5, verify=False)
                if resp.status_code != 200 or len(resp.text) > 2_000_000:
                    continue

                js_content = resp.text
                scanned += 1

                for key_name, pattern in self.JS_API_KEY_PATTERNS.items():
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    if matches:
                        # Mask the key for safe evidence
                        safe_match = self._mask_key(str(matches[0]))
                        self.attack_surface["api_keys_found"] += 1

                        findings.append(Finding(
                            title=f"API Key in JavaScript: {key_name}",
                            severity="HIGH",
                            description=f"A potential {key_name} was found embedded in JavaScript file. "
                                       f"Exposed API keys can be harvested and abused by attackers.",
                            location=f"JS File: {js_url}",
                            recommendation="Remove API keys from client-side JavaScript. "
                                          "Use server-side proxies or environment variables. "
                                          "Rotate the exposed key immediately.",
                            cwe_reference="CWE-798",
                            confidence="Medium",
                            category="Data Leakage",
                            evidence=f"Pattern: {key_name} | Match: {safe_match}",
                        ))

            except Exception as e:
                logger.debug(f"Failed to scan JS file {js_url}: {e}")
                continue

        return findings

    def _enumerate_forms(self, url: str, html_content: str) -> List[Finding]:
        """Extract HTML forms and check for missing CSRF tokens."""
        findings = []
        forms = []

        # Extract form tags with attributes
        form_pattern = r'<form\s([^>]*)>([\s\S]*?)</form>'
        form_matches = re.finditer(form_pattern, html_content, re.IGNORECASE)

        for match in form_matches:
            attrs_str = match.group(1)
            form_body = match.group(2)

            # Parse action and method
            action_match = re.search(r'action=["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)

            action = action_match.group(1) if action_match else ""
            method = (method_match.group(1) if method_match else "GET").upper()

            # Extract input fields
            inputs = []
            input_pattern = r'<input\s[^>]*name=["\']([^"\']+)["\'][^>]*>'
            for inp in re.finditer(input_pattern, form_body, re.IGNORECASE):
                inputs.append(inp.group(1))

            form_info = {
                "action": action,
                "method": method,
                "inputs": inputs,
            }
            forms.append(form_info)

            # Check POST forms for CSRF token
            if method == "POST":
                has_csrf = False
                csrf_indicators = ["csrf", "_token", "csrfmiddlewaretoken", "authenticity_token", "__requestverificationtoken"]
                form_body_lower = form_body.lower()

                for indicator in csrf_indicators:
                    if indicator in form_body_lower:
                        has_csrf = True
                        break

                if not has_csrf:
                    findings.append(Finding(
                        title="POST Form Without CSRF Protection",
                        severity="MEDIUM",
                        description=f"A POST form (action='{action}') does not appear to include "
                                   f"a CSRF token. This may allow Cross-Site Request Forgery attacks.",
                        location=f"Form: {action or url}",
                        recommendation="Add CSRF tokens to all POST forms. Use framework-provided "
                                      "CSRF protection mechanisms.",
                        cwe_reference="CWE-352",
                        confidence="Medium",
                        category="Vulnerability",
                        evidence=f"Method: POST | Action: {action} | Inputs: {', '.join(inputs[:5])}",
                    ))

        self.attack_surface["forms"] = forms
        return findings

    @staticmethod
    def _mask_key(value: str) -> str:
        """Mask sensitive key values for safe evidence display."""
        if len(value) > 12:
            visible = max(4, len(value) // 4)
            return value[:visible] + "*" * (len(value) - visible * 2) + value[-visible:]
        return value[:3] + "***"
