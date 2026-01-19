"""
Main security scanning orchestrator.
Coordinates all analyzers and manages scan workflow.
"""
from typing import List
from scanner.http_handler import HTTPAnalyzer
from scanner.headers_analyzer import HeadersAnalyzer
from scanner.cors_analyzer import CORSAnalyzer
from scanner.recon_analyzer import ReconAnalyzer
from scanner.content_analyzer import ContentAnalyzer
from scanner.robots_check import RobotsAnalyzer
from models import Finding, ScanResult
from sessions.session_logger import SessionLogger
import logging

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
        self.session_logger = session_logger
    
    def scan(self, url: str, verbose: bool = False, progress_callback=None) -> ScanResult:
        """
        Execute complete security scan on target URL.
        
        Args:
            url: Target URL to scan
            verbose: Enable detailed output
            progress_callback: Function to call for progress updates func(current_step, total_steps, message)
            
        Returns:
            ScanResult object with all findings
        """
        steps_total = 8
        
        if verbose:
            print(f"Starting scan for: {url}")
        
        # Step 1: Reconnaissance (Target Info)
        if progress_callback: progress_callback(1, steps_total, "Gathering Target Information (Whois, DNS, Subdomains)...")
        recon_data = self.recon_analyzer.analyze(url, headers=None)

        # Step 2: Fetch HTTP Headers & Enrich Recon
        if progress_callback: progress_callback(2, steps_total, "Establishing Connection & Fingerprinting...")
        headers_response = self.http_analyzer.fetch_headers(url)
        if not headers_response['success']:
            raise Exception(f"Unable to reach {url}: {headers_response.get('error')}")
        
        headers = headers_response['headers']
        redirect_chain = headers_response.get('redirect_history', [])
        
        # Enhance recon with findings from headers
        self.recon_analyzer.enrich_with_headers(recon_data, headers)

        if progress_callback: progress_callback(3, steps_total, "Verifying HTTPS Enforcement...")

        # Step 3: Check HTTPS enforcement
        https_response = self.http_analyzer.check_https_redirect(url)
        https_enforced = https_response.get('is_https_enforced', False)
        if 'redirect_chain' in https_response:
             # Merge redirect chains if different (HEAD vs GET behavior)
             redirect_chain = list(set(redirect_chain + https_response['redirect_chain']))

        if progress_callback: progress_callback(4, steps_total, "Analyzing Security Headers...")

        # Step 4: Run security header analysis
        headers_analyzer = HeadersAnalyzer(headers)
        header_findings = headers_analyzer.analyze_all()
        
        if progress_callback: progress_callback(5, steps_total, "Checking CORS Policies...")

        # Step 5: Run CORS analysis
        cors_analyzer = CORSAnalyzer(headers)
        cors_findings = cors_analyzer.analyze_all()

        if progress_callback: progress_callback(6, steps_total, "Analyzing Page Content (Secrets/Comments)...")

        # Step 6: Content Analysis (Body)
        content_findings = []
        page_content_response = self.http_analyzer.fetch_page_content(url)
        if page_content_response['success']:
             content_findings = self.content_analyzer.analyze(page_content_response['content'], url)

        if progress_callback: progress_callback(7, steps_total, "Checking Robots.txt & Hidden Paths...")

        # Step 7: Robots.txt Analysis
        robots_findings = self.robots_analyzer.analyze(url)
        
        # Step 8: Aggregate findings
        all_findings = header_findings + cors_findings + content_findings + robots_findings
        
        if progress_callback: progress_callback(8, steps_total, "Finalizing & Logging...")

        # Create scan result
        scan_result = ScanResult(
            session_id=self.session_logger.generate_session_id(url),
            target_url=url,
            timestamp=self.session_logger.get_timestamp(),
            findings=all_findings,
            https_enabled=https_enforced,
            redirect_chain=redirect_chain,
            recon=recon_data
        )
        
        # Step 7: Log session
        self.session_logger.save_session(scan_result)
        
        if verbose:
            print(f"Scan complete for {url}: {len(all_findings)} findings")
            
        return scan_result
