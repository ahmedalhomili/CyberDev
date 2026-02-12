"""
Parameter Discovery Module.
Discovers endpoints and query parameters from multiple sources
(HTML forms, JavaScript files, common parameter bruteforce)
to feed into vulnerability scanners that require parameterized URLs.
"""
import re
import logging
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Set
from bs4 import BeautifulSoup
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)


class ParamDiscovery:
    """Discovers endpoints and parameters from multiple sources."""

    # Common parameter names relevant to security testing, ordered by priority
    COMMON_PARAMS = [
        "id", "file", "path", "url", "redirect", "next", "return",
        "cmd", "exec", "command", "include", "load", "read", "download",
        "q", "search", "query", "page", "view", "template",
        "callback", "cb", "src", "dest", "ref",
        "name", "user", "username", "email", "login",
        "action", "type", "format", "lang", "locale",
        "cat", "category", "item", "product", "article",
        "sort", "order", "filter", "data", "input", "value",
        "content", "text", "token", "key", "source",
    ]

    # Skip these form field names (not useful for injection testing)
    SKIP_FIELD_NAMES = {
        'submit', 'csrf_token', '_token', 'csrfmiddlewaretoken',
        'csrf', '__requestverificationtoken', 'authenticity_token',
        '_csrf', 'captcha', 'recaptcha', 'g-recaptcha-response',
    }

    # Regex patterns for extracting endpoints from JavaScript
    JS_ENDPOINT_PATTERNS = [
        re.compile(r'''(?:fetch|axios\.get|axios\.post|axios\.put|axios\.delete)\s*\(\s*['"]([^'"]+?)['"]'''),
        re.compile(r'''\$\.(?:ajax|get|post)\s*\(\s*['"]([^'"]+?)['"]'''),
        re.compile(r'''\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE)['"]\s*,\s*['"]([^'"]+?)['"]'''),
        re.compile(r'''url\s*:\s*['"]([^'"]+?)['"]'''),
        re.compile(r'''['"](\/?api\/[a-zA-Z0-9_\-\/]+)['"]'''),
        re.compile(r'''['"](\/?v[0-9]+\/[a-zA-Z0-9_\-\/]+)['"]'''),
    ]

    # Regex patterns for extracting parameter names from JavaScript
    JS_PARAM_PATTERNS = [
        re.compile(r'''(?:URLSearchParams|searchParams).*?(?:append|set|get)\s*\(\s*['"]([a-zA-Z0-9_]+)['"]'''),
        re.compile(r'''[?&]([a-zA-Z0-9_]+)='''),
    ]

    # Static asset extensions to ignore
    STATIC_EXTENSIONS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                         '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map'}

    def __init__(self, max_js_files: int = 10, max_params_per_path: int = 5,
                 max_brute_params: int = 15, request_timeout: int = 5):
        self.requester = Requester()
        self.max_js_files = max_js_files
        self.max_params_per_path = max_params_per_path
        self.max_brute_params = max_brute_params
        self.request_timeout = request_timeout

    def discover(self, base_url: str, crawled_paths: List[str] = None) -> List[str]:
        """
        Run all discovery strategies and return deduplicated testable URLs.

        Args:
            base_url: The target website URL
            crawled_paths: URLs already discovered by LinkCrawler

        Returns:
            List of URLs with query parameters for vulnerability testing
        """
        discovered_urls: Set[str] = set()

        # Fetch the main page content once for form + JS analysis
        html_content = ''
        try:
            main_response = self.requester.get(base_url, timeout=self.request_timeout)
            if main_response.status_code == 200:
                html_content = main_response.text
        except Exception as e:
            logger.debug(f"Error fetching base URL for param discovery: {e}")

        # Strategy 1: HTML Form Input Extraction
        form_urls = self._discover_form_params(base_url, html_content)
        discovered_urls.update(form_urls)
        logger.info(f"Form discovery found {len(form_urls)} testable URLs")

        # Strategy 2: JavaScript Endpoint Discovery
        js_urls = self._discover_js_endpoints(base_url, html_content)
        discovered_urls.update(js_urls)
        logger.info(f"JS endpoint discovery found {len(js_urls)} testable URLs")

        # Strategy 3: Common Parameter Bruteforce
        all_paths = set()
        parsed_base = urlparse(base_url)
        base_path = parsed_base.path or '/'
        all_paths.add(base_path)

        if crawled_paths:
            for cp in crawled_paths:
                p = urlparse(cp).path
                if p:
                    all_paths.add(p)

        robot_paths = self._extract_robots_paths(base_url)
        all_paths.update(robot_paths)

        brute_urls = self._discover_by_bruteforce(base_url, list(all_paths))
        discovered_urls.update(brute_urls)
        logger.info(f"Parameter bruteforce found {len(brute_urls)} testable URLs")

        result = list(discovered_urls)
        logger.info(f"ParamDiscovery total: {len(result)} unique testable URLs discovered")
        return result

    def _discover_form_params(self, base_url: str, html_content: str) -> List[str]:
        """Extract parameter names from HTML form inputs and build testable URLs."""
        discovered = []
        if not html_content:
            return discovered

        soup = BeautifulSoup(html_content, 'html.parser')
        parsed_base = urlparse(base_url)

        for form in soup.find_all('form'):
            action = form.get('action', '')
            form_url = urljoin(base_url, action) if action else base_url

            # Only test same-domain forms
            if urlparse(form_url).netloc != parsed_base.netloc:
                continue

            param_names = []
            seen = set()
            for tag_name in ['input', 'select', 'textarea']:
                for element in form.find_all(tag_name, attrs={'name': True}):
                    name = element.get('name', '').strip()
                    if not name or name.lower() in self.SKIP_FIELD_NAMES:
                        continue
                    # Skip hidden type=submit/button/image
                    input_type = element.get('type', '').lower()
                    if input_type in ('submit', 'button', 'image', 'reset'):
                        continue
                    if name not in seen:
                        param_names.append(name)
                        seen.add(name)

            if param_names:
                params = {name: '1' for name in param_names[:self.max_params_per_path]}
                query_string = urlencode(params)
                clean_path = urlparse(form_url).path or '/'
                test_url = f"{parsed_base.scheme}://{parsed_base.netloc}{clean_path}?{query_string}"
                discovered.append(test_url)
                logger.debug(f"Form params discovered: {param_names} -> {test_url}")

        return discovered

    def _discover_js_endpoints(self, base_url: str, html_content: str) -> List[str]:
        """Extract endpoints and parameters from JavaScript files."""
        discovered = []
        if not html_content:
            return discovered

        soup = BeautifulSoup(html_content, 'html.parser')
        parsed_base = urlparse(base_url)
        js_urls = []

        # Collect JS file URLs from <script src=""> tags
        for script in soup.find_all('script', src=True):
            src = script['src']
            absolute_src = urljoin(base_url, src)
            if urlparse(absolute_src).netloc == parsed_base.netloc:
                js_urls.append(absolute_src)

        js_urls = js_urls[:self.max_js_files]

        # Also analyze inline <script> content
        all_js_content = []
        for script in soup.find_all('script'):
            if script.string and len(script.string) > 20:
                all_js_content.append(script.string)

        # Download external JS files
        for js_url in js_urls:
            try:
                response = self.requester.get(js_url, timeout=self.request_timeout)
                if response.status_code == 200:
                    all_js_content.append(response.text)
            except Exception as e:
                logger.debug(f"Error downloading JS file {js_url}: {e}")

        # Process all JS content
        endpoints = set()
        js_params = set()

        for js_content in all_js_content:
            # Extract endpoints
            for pattern in self.JS_ENDPOINT_PATTERNS:
                for match in pattern.findall(js_content):
                    path = match.strip()
                    if not path or len(path) > 200:
                        continue
                    # Skip static assets
                    ext = '.' + path.rsplit('.', 1)[-1].lower() if '.' in path.split('/')[-1] else ''
                    if ext in self.STATIC_EXTENSIONS:
                        continue
                    # Skip data URIs, mailto, etc.
                    if path.startswith(('data:', 'mailto:', 'javascript:', '#')):
                        continue
                    endpoints.add(path)

            # Extract parameter names
            for pattern in self.JS_PARAM_PATTERNS:
                for match in pattern.findall(js_content):
                    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]{0,30}$', match):
                        js_params.add(match)

            # Extract params from data/params objects: { key: value, key2: value2 }
            data_pattern = re.compile(r'(?:data|params|body)\s*:\s*\{([^}]+)\}')
            for match in data_pattern.findall(js_content):
                keys = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:', match)
                js_params.update(keys)

        # Build testable URLs
        for endpoint in endpoints:
            abs_url = urljoin(base_url, endpoint)
            parsed_ep = urlparse(abs_url)

            if parsed_ep.netloc != parsed_base.netloc:
                continue

            existing_params = parse_qs(parsed_ep.query)
            if existing_params:
                discovered.append(abs_url)
            elif js_params:
                param_dict = {p: '1' for p in list(js_params)[:self.max_params_per_path]}
                query = urlencode(param_dict)
                test_url = f"{parsed_ep.scheme}://{parsed_ep.netloc}{parsed_ep.path}?{query}"
                discovered.append(test_url)

        return discovered

    def _discover_by_bruteforce(self, base_url: str, paths: List[str]) -> List[str]:
        """Try common parameter names on paths and detect accepted ones."""
        discovered = []
        parsed_base = urlparse(base_url)

        # Limit paths to avoid excessive requests
        test_paths = paths[:5]

        for path in test_paths:
            test_base = f"{parsed_base.scheme}://{parsed_base.netloc}{path}"

            # Get baseline response
            try:
                baseline = self.requester.get(test_base, timeout=self.request_timeout)
                baseline_len = len(baseline.text)
                baseline_status = baseline.status_code
            except Exception:
                continue

            accepted_params = []
            params_to_try = self.COMMON_PARAMS[:self.max_brute_params]

            for param_name in params_to_try:
                try:
                    test_url = f"{test_base}?{param_name}=1"
                    response = self.requester.get(test_url, timeout=self.request_timeout)

                    response_len = len(response.text)
                    len_diff = abs(response_len - baseline_len)
                    threshold = max(50, baseline_len * 0.05)

                    # Parameter accepted if response changes meaningfully
                    if (response.status_code != baseline_status and
                            response.status_code not in (301, 302, 403, 404, 405)):
                        accepted_params.append(param_name)
                    elif len_diff > threshold and response.status_code == 200:
                        accepted_params.append(param_name)

                except Exception:
                    continue

                # Early stop if enough params found for this path
                if len(accepted_params) >= self.max_params_per_path:
                    break

            if accepted_params:
                param_dict = {p: '1' for p in accepted_params}
                query_string = urlencode(param_dict)
                discovered_url = f"{test_base}?{query_string}"
                discovered.append(discovered_url)
                logger.debug(f"Bruteforce discovered params {accepted_params} on {path}")

        return discovered

    def _extract_robots_paths(self, base_url: str) -> List[str]:
        """Extract disallowed paths from robots.txt for parameter testing."""
        paths = []
        robots_url = base_url.rstrip('/') + '/robots.txt'

        try:
            response = self.requester.get(robots_url, timeout=self.request_timeout)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    stripped = line.strip()
                    if stripped.lower().startswith('disallow:'):
                        path = stripped.split(':', 1)[1].strip()
                        if path and path != '/' and '*' not in path:
                            paths.append(path)
        except Exception as e:
            logger.debug(f"Error fetching robots.txt for param discovery: {e}")

        return paths
