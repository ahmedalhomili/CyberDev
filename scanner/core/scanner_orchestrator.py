"""
Main security scanning orchestrator.
Coordinates all analyzers and manages scan workflow.
"""
from typing import List
from scanner.core.http_handler import HTTPAnalyzer
from scanner.recon.headers_analyzer import HeadersAnalyzer
from scanner.recon.cors_analyzer import CORSAnalyzer
from scanner.recon.recon_analyzer import ReconAnalyzer
from scanner.recon.content_analyzer import ContentAnalyzer
from scanner.recon.robots_check import RobotsAnalyzer
from scanner.recon.link_crawler import LinkCrawler
from scanner.vulnerabilities.vuln_sqli import SQLiScanner
from scanner.vulnerabilities.vuln_xss import XSSScanner
from scanner.vulnerabilities.vuln_rce import RCEScanner
from scanner.vulnerabilities.vuln_lfi import LFIScanner
from scanner.vulnerabilities.vuln_ssti import SSTIScanner
from scanner.vulnerabilities.vuln_redirect import OpenRedirectScanner
from scanner.vulnerabilities.vuln_ssrf import SSRFScanner
from scanner.vulnerabilities.vuln_host_header import HostHeaderScanner
from scanner.vulnerabilities.vuln_jwt import JWTScanner
from scanner.vulnerabilities.vuln_graphql import GraphQLScanner
from scanner.vulnerabilities.vuln_deserialization import DeserializationScanner
from scanner.vulnerabilities.vuln_cache_poisoning import CachePoisoningScanner
from scanner.vulnerabilities.vuln_auth_workflow import AuthScanner
from scanner.vulnerabilities.vuln_upload_checks import FileUploadScanner
from scanner.vulnerabilities.vuln_xxe import XXEScanner
from scanner.vulnerabilities.vuln_api_security import APISecurityScanner
from scanner.vulnerabilities.vuln_websocket import WebSocketScanner
from scanner.recon.explore_fuzzer import DirectoryFuzzer
from models import Finding, ScanResult
from sessions.session_logger import SessionLogger
import logging

from utils.severity import normalize_severity, SEVERITY_LEVELS
from config import CRAWLER_MAX_DEPTH, CRAWLER_MAX_URLS

logger = logging.getLogger(__name__)

class SecurityScanner:
    """Main scanning orchestrator."""
    
    def __init__(self, session_logger: SessionLogger):
        """
        Initialize scanner.
        
        Args:
            session_logger: SessionLogger instance for logging scans
        """
        self.http_analyzer = HTTPAnalyzer()
        self.recon_analyzer = ReconAnalyzer()
        self.content_analyzer = ContentAnalyzer()
        self.robots_analyzer = RobotsAnalyzer(self.http_analyzer)
        self.link_crawler = LinkCrawler(max_depth=CRAWLER_MAX_DEPTH, max_urls=CRAWLER_MAX_URLS)
        
        # Active Vulnerability Scanners
        self.sqli_scanner = SQLiScanner()
        self.xss_scanner = XSSScanner()
        self.rce_scanner = RCEScanner()
        self.lfi_scanner = LFIScanner()
        self.ssti_scanner = SSTIScanner()
        self.redirect_scanner = OpenRedirectScanner()
        self.ssrf_scanner = SSRFScanner()
        self.host_header_scanner = HostHeaderScanner()
        
        # Advanced Modern Scanners
        self.jwt_scanner = JWTScanner()
        self.graphql_scanner = GraphQLScanner()
        self.deserialization_scanner = DeserializationScanner()
        self.cache_poisoning_scanner = CachePoisoningScanner()
        
        # New High-Impact Scanners
        self.auth_scanner = AuthScanner()
        self.upload_scanner = FileUploadScanner()
        self.xxe_scanner = XXEScanner()
        self.api_scanner = APISecurityScanner()
        self.websocket_scanner = WebSocketScanner()
        
        self.dir_fuzzer = DirectoryFuzzer()
        
        self.session_logger = session_logger
    
    def _calculate_stats(self, findings: List[Finding]) -> dict:
        """Calculate stats for a list of findings."""
        if not findings:
            return {'count': 0, 'max_severity': None}
            
        max_sev_val = -1
        max_sev_str = "INFO"
        
        for f in findings:
            s_str = normalize_severity(f.severity)
            s_val = SEVERITY_LEVELS.get(s_str, 0)
            if s_val > max_sev_val:
                max_sev_val = s_val
                max_sev_str = s_str
                
        return {'count': len(findings), 'max_severity': max_sev_str}

    def scan(self, url: str, verbose: bool = False, progress_callback=None) -> ScanResult:
        """
        Execute complete security scan on target URL.
        
        Args:
            url: Target URL to scan
            verbose: Enable detailed output
            progress_callback: Function to call for progress updates func(current_step, total_steps, message, stats=None)
            
        Returns:
            ScanResult object with all findings
        """
        # Initialize Session
        session_id = self.session_logger.generate_session_id(url)
        start_time = self.session_logger.get_timestamp()

        steps_total = 21
        prev_stats = None
        
        if verbose:
            print(f"Starting scan for: {url}")
        
        # Step 1: Reconnaissance (Target Info)
        if progress_callback: progress_callback(1, steps_total, "Gathering Target Information (Whois, DNS, Subdomains)...", prev_stats)
        recon_data = self.recon_analyzer.analyze(url, headers=None)
        # Recon is informational, treat as info finding if we got something
        prev_stats = {'count': 1, 'max_severity': 'INFO'} if recon_data else {'count': 0, 'max_severity': None}

        # Step 2: Fetch HTTP Headers & Enrich Recon
        if progress_callback: progress_callback(2, steps_total, "Establishing Connection & Fingerprinting...", prev_stats)
        headers_response = self.http_analyzer.fetch_headers(url)
        if not headers_response['success']:
            raise Exception(f"Unable to reach {url}: {headers_response.get('error')}")
        
        headers = headers_response['headers']
        response_obj = headers_response.get('response_object') # Expecting full response object here if possible, or we need to pass it
        redirect_chain = headers_response.get('redirect_history', [])
        
        # Enhance recon with findings from headers
        self.recon_analyzer.enrich_with_headers(recon_data, headers)
        prev_stats = {'count': len(headers), 'max_severity': 'INFO'}

        if progress_callback: progress_callback(3, steps_total, "Verifying HTTPS Enforcement...", prev_stats)

        # Step 3: Check HTTPS enforcement
        https_response = self.http_analyzer.check_https_redirect(url)
        https_enforced = https_response.get('is_https_enforced', False)
        if 'redirect_chain' in https_response:
             # Merge redirect chains if different (HEAD vs GET behavior)
             redirect_chain = list(set(redirect_chain + https_response['redirect_chain']))
        prev_stats = {'count': 1 if https_enforced else 0, 'max_severity': 'INFO'}

        if progress_callback: progress_callback(4, steps_total, "Analyzing Security Headers...", prev_stats)

        # Step 4: Run security header analysis
        headers_analyzer = HeadersAnalyzer(headers)
        header_findings = headers_analyzer.analyze_all()
        prev_stats = self._calculate_stats(header_findings)
        
        if progress_callback: progress_callback(5, steps_total, "Checking CORS Policies...", prev_stats)

        # Step 5: Run CORS analysis
        cors_analyzer = CORSAnalyzer(headers)
        cors_findings = cors_analyzer.analyze_all()
        prev_stats = self._calculate_stats(cors_findings)

        if progress_callback: progress_callback(6, steps_total, "Analyzing Page Content (Secrets/Comments)...", prev_stats)

        # Step 6: Content Analysis (Body)
        content_findings = []
        page_content_response = self.http_analyzer.fetch_page_content(url)
        if page_content_response['success']:
             content_findings = self.content_analyzer.analyze(page_content_response['content'], url)
        prev_stats = self._calculate_stats(content_findings)

        if progress_callback: progress_callback(7, steps_total, "Checking Robots.txt & Hidden Paths...", prev_stats)

        # Step 7: Robots.txt Analysis
        robots_findings = self.robots_analyzer.analyze(url)
        prev_stats = self._calculate_stats(robots_findings)
        
        # Step 8: Directory Fuzzing
        if progress_callback: progress_callback(8, steps_total, "Fuzzing Directories & Files...", prev_stats)
        fuzzer_findings = self.dir_fuzzer.scan(url)
        prev_stats = self._calculate_stats(fuzzer_findings)
        
        # Step 8.5: Crawl for testable URLs (NEW)
        # Always show crawler status regardless of verbose mode
        logger.info("Starting link crawler to discover testable URLs...")
        
        crawled_urls = self.link_crawler.crawl(url)
        testable_urls = self.link_crawler.get_testable_urls(limit=15)
        
        logger.info(f"Crawler found {len(crawled_urls)} total URLs, {len(testable_urls)} testable URLs with parameters")
        
        # If no testable URLs found, use base URL
        if not testable_urls:
            logger.warning("No URLs with parameters found, using base URL only for vulnerability scanning")
            testable_urls = [url]
        else:
            logger.info(f"Will test {len(testable_urls)} URLs: {testable_urls[:3]}...")
        
        # Step 9: active_findings init
        active_findings = []

        # Step 9: SQL Injection
        step_findings = []
        for test_url in testable_urls:
            step_findings.extend(self.sqli_scanner.scan(test_url))
        active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(9, steps_total, "Scanning for SQL Injection (SQLi)...", prev_stats)

        # Step 10: XSS
        step_findings = []
        for test_url in testable_urls:
            step_findings.extend(self.xss_scanner.scan(test_url))
        active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(10, steps_total, "Scanning for Cross-Site Scripting (XSS)...", prev_stats)

        # Step 11: RCE
        step_findings = []
        for test_url in testable_urls:
            step_findings.extend(self.rce_scanner.scan(test_url))
        active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(11, steps_total, "Auditing for Remote Code Execution (RCE)...", prev_stats)

        # Step 12: LFI
        step_findings = []
        for test_url in testable_urls:
            step_findings.extend(self.lfi_scanner.scan(test_url))
        active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(12, steps_total, "Checking for Local File Inclusion (LFI)...", prev_stats)

        # Step 13: SSTI
        step_findings = []
        for test_url in testable_urls:
            step_findings.extend(self.ssti_scanner.scan(test_url))
        active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(13, steps_total, "Testing for Server-Side Template Injection (SSTI)...", prev_stats)

        # Step 14: SSRF
        step_findings = []
        for test_url in testable_urls:
            step_findings.extend(self.ssrf_scanner.scan(test_url))
        active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(14, steps_total, "Analyzing for Server-Side Request Forgery (SSRF)...", prev_stats)

        # Step 15: Open Redirect
        step_findings = []
        for test_url in testable_urls:
            step_findings.extend(self.redirect_scanner.scan(test_url))
        active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(15, steps_total, "Checking for Open Redirect Vulnerabilities...", prev_stats)

        # Step 16: Host Header
        step_findings = self.host_header_scanner.scan(url)
        active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(16, steps_total, "Analyzing Host Header Risks...", prev_stats)

        # Step 17: Advanced Misconfigurations (JWT, GraphQL, Serialization)
        step_findings = self.jwt_scanner.scan(url) + self.graphql_scanner.scan(url) + self.deserialization_scanner.scan(url)
        active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(17, steps_total, "Inspecting JWT, GraphQL, & Serialization...", prev_stats)

        # Step 18: Authentication & Session Management
        step_findings = []
        if response_obj:
            step_findings = self.auth_scanner.scan(url, response_obj)
            active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(18, steps_total, "Checking Authentication & Session Security...", prev_stats)

        # Step 19: File Upload & XXE
        step_findings = []
        if response_obj:
            step_findings += self.upload_scanner.scan(url, response_obj.text)
            step_findings += self.xxe_scanner.check_response_for_xxe_potential(response_obj)
            active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(19, steps_total, "Analyzing File Upload & XXE Risks...", prev_stats)

        # Step 20: API & WebSocket Security
        step_findings = self.api_scanner.scan(url) + self.websocket_scanner.scan(url)
        active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(20, steps_total, "Inspecting API Endpoints & WebSockets...", prev_stats)

        # Step 21: Cache Poisoning checks
        step_findings = self.cache_poisoning_scanner.check_cache_headers(headers, url)
        active_findings.extend(step_findings)
        prev_stats = self._calculate_stats(step_findings)
        if progress_callback: progress_callback(21, steps_total, "Analyzing Web Cache Poisoning Risks...", prev_stats)

        # Final signal for last step
        if progress_callback: progress_callback(steps_total + 1, steps_total, "Scan Finished", prev_stats)

        # Final Compilation (with deduplication)
        all_findings_raw = header_findings + cors_findings + content_findings + robots_findings + fuzzer_findings + active_findings
        seen = set()
        all_findings = []
        for f in all_findings_raw:
            key = (f.title, f.location)
            if key not in seen:
                seen.add(key)
                all_findings.append(f)

        scan_result = ScanResult(
            session_id=session_id,
            target_url=url,
            timestamp=start_time,
            findings=all_findings,
            https_enabled=https_enforced,
            redirect_chain=redirect_chain,
            recon=recon_data
        )
        
        self.session_logger.save_session(scan_result)
        return scan_result
