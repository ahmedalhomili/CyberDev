"""
Requester module.
Provides a centralized way to make HTTP requests with consistent configuration,
timeouts, and User-Agent rotation.
"""

import requests
import logging
from fake_useragent import UserAgent
from typing import Optional

logger = logging.getLogger(__name__)

class Requester:
    """
    Centralized HTTP requester helper.
    Wraps requests to provide default headers, timeouts, and error handling.
    """
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        # Try to initialize generic User-Agent rotator
        try:
            self.ua = UserAgent()
        except Exception:
            self.ua = None
            
        self.session = requests.Session()

    def _get_headers(self, headers: Optional[dict] = None) -> dict:
        default_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        
        # Add random User-Agent
        if self.ua:
            try:
                default_headers["User-Agent"] = self.ua.random
            except Exception:
                default_headers["User-Agent"] = "Safe-Web-Vulnerability-Checker/1.0"
        else:
            default_headers["User-Agent"] = "Safe-Web-Vulnerability-Checker/1.0"

        if headers:
            default_headers.update(headers)
            
        return default_headers

    def get(self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None, timeout: Optional[int] = None) -> requests.Response:
        """
        Perform a GET request.
        
        Args:
            url: Target URL
            params: Query parameters
            headers: Custom headers
            timeout: Request timeout override
            
        Returns:
            requests.Response object
        """
        req_headers = self._get_headers(headers)
        req_timeout = timeout if timeout is not None else self.timeout
        
        try:
            response = self.session.get(
                url, 
                params=params, 
                headers=req_headers, 
                timeout=req_timeout, 
                verify=self.verify_ssl,
                allow_redirects=True
            )
            return response
        except requests.RequestException as e:
            # Re-raise to let logic specific handlers catch it.
            raise e

    def post(self, url: str, data: Optional[dict] = None, json: Optional[dict] = None, headers: Optional[dict] = None, timeout: Optional[int] = None) -> requests.Response:
        """
        Perform a POST request.
        """
        req_headers = self._get_headers(headers)
        req_timeout = timeout if timeout is not None else self.timeout
        
        try:
            response = self.session.post(
                url, 
                data=data, 
                json=json,
                headers=req_headers, 
                timeout=req_timeout, 
                verify=self.verify_ssl,
                allow_redirects=True
            )
            return response
        except requests.RequestException as e:
            raise e

def fetch_response(url: str) -> dict:
    """
    Legacy helper for backward compatibility.
    """
    requester = Requester()
    try:
        resp = requester.get(url)
        return {
            "status": True,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:100000], 
            "final_url": resp.url,
            "error": None
        }
    except Exception as e:
        return {
            "status": False,
            "status_code": None,
            "headers": {},
            "body": "",
            "final_url": "",
            "error": str(e)
        }
