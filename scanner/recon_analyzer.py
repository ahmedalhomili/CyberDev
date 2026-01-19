"""
Reconnaissance analyzer for gathering initial target information.
Performs Whois, Port Scanning, Tech Detection, and OS Fingerprinting.
"""
import socket
import logging
import requests
import dns.resolver
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional
import whois
from models import ReconData

logger = logging.getLogger(__name__)

class ReconAnalyzer:
    """Performs passive and active reconnaissance on target."""

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443]

    def analyze(self, url: str, headers: Dict[str, str] = None) -> ReconData:
        """
        Run all recon checks.
        
        Args:
            url: Target URL
            headers: HTTP response headers (optional, for tech/OS detection)
            
        Returns:
            ReconData object
        """
        domain = self._extract_domain(url)
        ip = self._resolve_ip(domain)
        
        # 1. Whois Info
        try:
            w = whois.whois(domain)
            # Serialize dates and objects to simple types
            domain_info = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
                "expiration_date": str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date),
                "org": w.org,
                "country": w.country
            }
        except Exception as e:
            logger.warning(f"Whois lookup failed: {e}")
            domain_info = {"error": "Whois lookup failed"}

        # 2. Open Ports
        open_ports = []
        if ip:
            open_ports = self._scan_ports(ip)

        # 3. Technologies & OS (Placeholder, enriched later if headers provided)
        techs = []
        os_info = "Unknown"

        # 4. DNS Security (SPF/DMARC)
        dns_sec = self._check_email_security(domain)
        
        # 5. Passive Subdomain Enumeration
        subdomains = self._fetch_subdomains_crtsh(domain)

        data = ReconData(
            ip_address=ip,
            domain_info=domain_info,
            server_os=os_info,
            technologies=list(set(techs)),
            open_ports=open_ports,
            dns_security=dns_sec,
            subdomains=subdomains
        )
        
        if headers:
            self.enrich_with_headers(data, headers)
            
        return data

    def enrich_with_headers(self, data: ReconData, headers: Dict[str, str]):
        """Update active recon data with insights from HTTP headers."""
        techs = data.technologies
        os_info = data.server_os
        
        # Server Header
        server = headers.get("Server", "")
        if server:
            techs.append(f"Server: {server}")
            if "Ubuntu" in server: os_info = "Ubuntu Linux"
            elif "Debian" in server: os_info = "Debian Linux"
            elif "CentOS" in server: os_info = "CentOS Linux"
            elif "IIS" in server or "Microsoft" in server: os_info = "Windows Server"
            elif "Apache" in server: os_info = "Likely Linux (Apache)"
            elif "nginx" in server: os_info = "Likely Linux (Nginx)"

        # X-Powered-By
        powered = headers.get("X-Powered-By", "")
        if powered:
            techs.append(f"Powered By: {powered}")
            if "ASP.NET" in powered:
                    os_info = "Windows Server"
        
        # Cookies
        cookie_header = headers.get("Set-Cookie", "")
        if "PHPSESSID" in cookie_header: techs.append("PHP")
        if "JSESSIONID" in cookie_header: techs.append("Java/JSP")
        if "ASP.NET_SessionId" in cookie_header: techs.append("ASP.NET")
        if "csrftoken" in cookie_header: techs.append("Django/Python")
        
        # Update object
        data.technologies = list(set(techs))
        if os_info != "Unknown":
            data.server_os = os_info

    def _extract_domain(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]

    def _resolve_ip(self, domain: str) -> Optional[str]:
        try:
            # Strip port if present
            hostname = domain.split(':')[0]
            return socket.gethostbyname(hostname)
        except:
            return None

    def _scan_ports(self, ip: str) -> List[int]:
        open_ports = []
        # Quick scan with short timeout
        for port in self.COMMON_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports

    def _check_email_security(self, domain: str) -> Dict[str, Any]:
        """Check SPF and DMARC records."""
        results = {"spf": None, "dmarc": None, "vulnerable": False}
        
        # SPF
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=spf1'):
                    results['spf'] = txt
        except Exception:
            pass

        # DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=DMARC1'):
                    results['dmarc'] = txt
        except Exception:
            pass

        # Simple Logic: Vulnerable if no DMARC or DMARC is p=none
        if not results['dmarc'] or "p=none" in results['dmarc']:
            results['vulnerable'] = True
            
        return results

    def _fetch_subdomains_crtsh(self, domain: str) -> List[str]:
        """Fetch subdomains from crt.sh (Certificate Transparency Logs)."""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # Split multiline names and clean
                    for sub in name_value.split('\n'):
                        if '*' not in sub and sub.endswith(domain):
                            subdomains.add(sub.lower())
        except Exception as e:
            logger.warning(f"CRT.sh lookup failed: {e}")
        
        # Return top 15 to avoid flooding output
        return sorted(list(subdomains))[:15]
