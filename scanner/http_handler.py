"""
HTTP request handling and HTTPS validation module.
Responsible for all network communication.
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse
from typing import Dict, List, Optional
import logging

class HTTPAnalyzer:
    """Handles HTTP requests and protocol analysis."""
    
    DEFAULT_USER_AGENT = 'Safe-Web-Vulnerability-Checker/1.0 (+http://example.com)'
    TIMEOUT = 10
    
    def __init__(self, verify_ssl: bool = True, timeout: int = TIMEOUT):
        """
        Initialize HTTP analyzer.
        
        Args:
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        self.session = requests.Session()
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._setup_session()
    
    def _setup_session(self):
        """Configure requests session with retries and timeout."""
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.headers.update({'User-Agent': self.DEFAULT_USER_AGENT})
    
    def fetch_headers(self, url: str) -> Dict:
        """
        Fetch HTTP headers from target URL.
        
        Args:
            url: Target URL to analyze
            
        Returns:
            Dict containing:
                - 'success': bool
                - 'headers': dict of response headers
                - 'status_code': int
                - 'final_url': str (after redirects)
                - 'error': str (if failed)
        """
        # Ensure URL has schema
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        try:
            # Using GET instead of HEAD because some servers strip headers on HEAD
            response = self.session.get(url, timeout=self.timeout, 
                                        allow_redirects=True, 
                                        verify=self.verify_ssl,
                                        stream=True) # Stream to avoid downloading full body
            # Consume a small part of content to ensure connection is valid then close
            response.raw.read(100) 
            response.close()

            return {
                'success': True,
                'headers': dict(response.headers),
                'status_code': response.status_code,
                'final_url': response.url,
                'redirect_history': [r.url for r in response.history]
            }
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Request timeout'}
        except requests.exceptions.ConnectionError:
            return {'success': False, 'error': 'Connection failed'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def check_https_redirect(self, url: str) -> Dict:
        """
        Check if HTTP requests are redirected to HTTPS.
        
        Args:
            url: Target URL
            
        Returns:
            Dict containing:
                - 'is_https_enforced': bool
                - 'redirect_chain': list of URLs in redirect
                - 'final_protocol': 'http' or 'https'
                - 'status_codes': list of status codes
        """
        # Ensure HTTP protocol for testing upgrade
        http_url = url
        if http_url.startswith('https://'):
            http_url = http_url.replace('https://', 'http://', 1)
        elif not http_url.startswith('http://'):
            http_url = f'http://{http_url}'
        
        try:
            response = self.session.get(http_url, timeout=self.timeout,
                                       allow_redirects=True, 
                                       verify=self.verify_ssl)
            redirect_chain = [r.url for r in response.history]
            redirect_chain.append(response.url)
            status_codes = [r.status_code for r in response.history]
            status_codes.append(response.status_code)
            
            final_protocol = urlparse(response.url).scheme
            
            return {
                'is_https_enforced': final_protocol == 'https',
                'redirect_chain': redirect_chain,
                'final_protocol': final_protocol,
                'status_codes': status_codes
            }
        except Exception as e:
            return {'is_https_enforced': False, 'error': str(e)}
