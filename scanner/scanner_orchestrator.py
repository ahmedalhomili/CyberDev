"""
Main security scanning orchestrator.
Coordinates all analyzers and manages scan workflow.
"""
from typing import List
from scanner.http_handler import HTTPAnalyzer
from scanner.headers_analyzer import HeadersAnalyzer
from scanner.cors_analyzer import CORSAnalyzer
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
        steps_total = 5
        
        if verbose:
            print(f"Starting scan for: {url}")
        
        if progress_callback: progress_callback(1, steps_total, "Fetching HTTP Headers...")

        # Step 1: Fetch HTTP headers
        headers_response = self.http_analyzer.fetch_headers(url)
        if not headers_response['success']:
            raise Exception(f"Unable to reach {url}: {headers_response.get('error')}")
        
        headers = headers_response['headers']
        redirect_chain = headers_response.get('redirect_history', [])
        
        if progress_callback: progress_callback(2, steps_total, "Verifying HTTPS Enforcement...")

        # Step 2: Check HTTPS enforcement
        https_response = self.http_analyzer.check_https_redirect(url)
        https_enforced = https_response.get('is_https_enforced', False)
        if 'redirect_chain' in https_response:
             # Merge redirect chains if different (HEAD vs GET behavior)
             redirect_chain = list(set(redirect_chain + https_response['redirect_chain']))

        if progress_callback: progress_callback(3, steps_total, "Analyzing Security Headers...")

        # Step 3: Run security header analysis
        headers_analyzer = HeadersAnalyzer(headers)
        header_findings = headers_analyzer.analyze_all()
        
        if progress_callback: progress_callback(4, steps_total, "Checking CORS Policies...")

        # Step 4: Run CORS analysis
        cors_analyzer = CORSAnalyzer(headers)
        cors_findings = cors_analyzer.analyze_all()
        
        # Step 5: Aggregate findings
        all_findings = header_findings + cors_findings
        
        if progress_callback: progress_callback(5, steps_total, "Finalizing & Logging...")

        # Step 6: Create scan result
        scan_result = ScanResult(
            session_id=self.session_logger.generate_session_id(url),
            target_url=url,
            timestamp=self.session_logger.get_timestamp(),
            findings=all_findings,
            https_enabled=https_enforced,
            redirect_chain=redirect_chain
        )
        
        # Step 7: Log session
        self.session_logger.save_session(scan_result)
        
        if verbose:
            print(f"Scan complete for {url}: {len(all_findings)} findings")
            
        return scan_result
