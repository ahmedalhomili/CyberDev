"""
Link Crawler - Discovers internal links and parameters for vulnerability testing.
"""
import logging
import re
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Set, Dict
from bs4 import BeautifulSoup
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class LinkCrawler:
    """Crawls website to discover testable URLs with parameters."""
    
    def __init__(self, max_depth: int = 2, max_urls: int = 50):
        """
        Initialize crawler.
        
        Args:
            max_depth: Maximum crawl depth (default: 2)
            max_urls: Maximum URLs to crawl (default: 50)
        """
        self.requester = Requester()
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited_urls: Set[str] = set()
        self.discovered_urls: List[Dict] = []
        
    def crawl(self, base_url: str) -> List[Dict]:
        """
        Crawl website starting from base_url.
        
        Returns:
            List of dictionaries with 'url', 'params', and 'depth'
        """
        parsed_base = urlparse(base_url)
        self.base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
        
        # Start crawling from base URL
        self._crawl_recursive(base_url, depth=0)
        
        # Add base URL if it has parameters
        if parse_qs(urlparse(base_url).query):
            self.discovered_urls.insert(0, {
                'url': base_url,
                'params': list(parse_qs(urlparse(base_url).query).keys()),
                'depth': 0
            })
        
        logger.info(f"Crawled {len(self.visited_urls)} URLs, discovered {len(self.discovered_urls)} testable URLs")
        return self.discovered_urls
    
    def _crawl_recursive(self, url: str, depth: int):
        """Recursively crawl URLs."""
        # Stop conditions
        if depth > self.max_depth:
            return
        if len(self.visited_urls) >= self.max_urls:
            return
        if url in self.visited_urls:
            return
        
        # Mark as visited
        self.visited_urls.add(url)
        
        try:
            # Fetch page
            response = self.requester.get(url, timeout=5)
            
            if response.status_code != 200:
                return
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links
            links = self._extract_links(soup, url)
            
            # Process each link
            for link in links:
                parsed_link = urlparse(link)
                
                # Check if link has parameters (testable)
                params = parse_qs(parsed_link.query)
                if params and len(self.discovered_urls) < self.max_urls:
                    # Add to discovered URLs for testing
                    self.discovered_urls.append({
                        'url': link,
                        'params': list(params.keys()),
                        'depth': depth + 1
                    })
                    logger.debug(f"Discovered testable URL: {link}")
                
                # Continue crawling if within same domain
                if depth < self.max_depth and link not in self.visited_urls:
                    if self._is_same_domain(link):
                        self._crawl_recursive(link, depth + 1)
                        
        except Exception as e:
            logger.debug(f"Error crawling {url}: {e}")
    
    def _extract_links(self, soup: BeautifulSoup, current_url: str) -> List[str]:
        """Extract all links from HTML."""
        links = []
        
        # Find all <a> tags
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            # Convert relative URLs to absolute
            absolute_url = urljoin(current_url, href)
            
            # Clean URL (remove fragments)
            parsed = urlparse(absolute_url)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean_url += f"?{parsed.query}"
            
            links.append(clean_url)
        
        # Also check forms for action URLs
        for form in soup.find_all('form', action=True):
            action = form['action']
            if action:
                absolute_url = urljoin(current_url, action)
                links.append(absolute_url)
        
        return links
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the same domain."""
        parsed = urlparse(url)
        url_domain = f"{parsed.scheme}://{parsed.netloc}"
        return url_domain == self.base_domain
    
    def get_testable_urls(self, limit: int = 20) -> List[str]:
        """
        Get list of URLs with parameters for vulnerability testing.
        
        Args:
            limit: Maximum number of URLs to return
            
        Returns:
            List of URLs with parameters
        """
        return [item['url'] for item in self.discovered_urls[:limit]]
