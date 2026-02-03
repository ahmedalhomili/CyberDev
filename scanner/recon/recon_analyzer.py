"""
Reconnaissance analyzer for gathering initial target information.
Performs Whois, Port Scanning, Tech Detection, OS Fingerprinting, Hosting Detection, and Geolocation.
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
        
        # 6. Geolocation & Hosting Information (NEW)
        geo_info = self._get_geolocation(ip) if ip else {}
        hosting_info = self._detect_hosting_provider(domain, ip, headers) if ip else {}
        
        # 7. CDN & WAF Detection (NEW)
        cdn_waf = self._detect_cdn_waf(domain, headers) if headers else {}
        
        # 8. SSL/TLS Information (NEW)
        ssl_info = self._get_ssl_info(domain)

        data = ReconData(
            ip_address=ip,
            domain_info=domain_info,
            server_os=os_info,
            technologies=list(set(techs)),
            open_ports=open_ports,
            dns_security=dns_sec,
            subdomains=subdomains
        )
        
        # Add new fields
        if hasattr(data, '__dict__'):
            data.__dict__['geolocation'] = geo_info
            data.__dict__['hosting_provider'] = hosting_info
            data.__dict__['cdn_waf'] = cdn_waf
            data.__dict__['ssl_info'] = ssl_info
        
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
        """Scan for open ports with improved accuracy."""
        open_ports = []
        logger.info(f"Scanning common ports on {ip}...")
        
        # Critical ports that are most likely to be legitimately open
        PRIORITY_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443]
        
        # Scan priority ports first
        for port in PRIORITY_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    logger.info(f"  ✓ Port {port} is OPEN")
                    open_ports.append(port)
                sock.close()
            except Exception as e:
                logger.debug(f"Error scanning port {port}: {e}")
                try:
                    sock.close()
                except:
                    pass
        
        # If too many ports appear open, likely false positive - only report priority ports
        if len(open_ports) > 10:
            logger.warning(f"Unusual: {len(open_ports)} ports detected as open - filtering to common web/SSH ports only")
            open_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 22]]
        
        logger.info(f"Port scan complete: {len(open_ports)} open ports found")
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
    
    def _get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation information for IP address."""
        geo_info = {}
        try:
            # Using ip-api.com (free, no API key required)
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,region,regionName,city,isp,org,as,asname,hosting", timeout=5)
            if response.status_code == 200:
                data = response.json()
                geo_info = {
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                    "asn": data.get("as"),
                    "as_name": data.get("asname"),
                    "is_hosting": data.get("hosting", False)
                }
        except Exception as e:
            logger.debug(f"Geolocation lookup failed: {e}")
        
        return geo_info
    
    def _detect_hosting_provider(self, domain: str, ip: str, headers: Dict = None) -> Dict[str, Any]:
        """Detect hosting provider and cloud platform."""
        hosting = {"provider": "Unknown", "type": "Unknown", "cloud_platform": None}
        
        try:
            # Check for cloud providers via IP ranges and headers
            
            # AWS Detection
            if self._is_aws(ip, headers):
                hosting["provider"] = "Amazon Web Services (AWS)"
                hosting["cloud_platform"] = "AWS"
                hosting["type"] = "Cloud Hosting"
            
            # Azure Detection
            elif self._is_azure(ip, headers):
                hosting["provider"] = "Microsoft Azure"
                hosting["cloud_platform"] = "Azure"
                hosting["type"] = "Cloud Hosting"
            
            # Google Cloud Detection
            elif self._is_gcp(ip, headers):
                hosting["provider"] = "Google Cloud Platform"
                hosting["cloud_platform"] = "GCP"
                hosting["type"] = "Cloud Hosting"
            
            # Cloudflare Detection
            elif self._is_cloudflare(headers):
                hosting["provider"] = "Cloudflare"
                hosting["type"] = "CDN/Proxy"
            
            # DigitalOcean Detection
            elif "digitalocean" in str(headers).lower() or self._is_digitalocean(ip):
                hosting["provider"] = "DigitalOcean"
                hosting["type"] = "VPS/Cloud"
            
            # Generic detection via reverse DNS
            else:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    if "amazonaws" in hostname:
                        hosting["provider"] = "Amazon Web Services (AWS)"
                        hosting["cloud_platform"] = "AWS"
                    elif "googleusercontent" in hostname or "google" in hostname:
                        hosting["provider"] = "Google Cloud Platform"
                        hosting["cloud_platform"] = "GCP"
                    elif "cloudapp.azure" in hostname:
                        hosting["provider"] = "Microsoft Azure"
                        hosting["cloud_platform"] = "Azure"
                    elif "ovh" in hostname:
                        hosting["provider"] = "OVH"
                    elif "godaddy" in hostname:
                        hosting["provider"] = "GoDaddy"
                    elif "bluehost" in hostname:
                        hosting["provider"] = "Bluehost"
                    elif "hostgator" in hostname:
                        hosting["provider"] = "HostGator"
                    else:
                        hosting["provider"] = hostname
                except:
                    pass
                    
        except Exception as e:
            logger.debug(f"Hosting detection failed: {e}")
        
        return hosting
    
    def _is_aws(self, ip: str, headers: Dict = None) -> bool:
        """Check if hosted on AWS."""
        if headers:
            server = headers.get("Server", "").lower()
            if "amazonwebservices" in server or "aws" in server:
                return True
        
        # Check AWS IP ranges (simplified check)
        # AWS uses many IP ranges, this is a basic check
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return "amazonaws" in hostname
        except:
            return False
    
    def _is_azure(self, ip: str, headers: Dict = None) -> bool:
        """Check if hosted on Azure."""
        if headers:
            server = headers.get("Server", "").lower()
            if "azure" in server or "microsoft" in server:
                return True
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return "cloudapp.azure" in hostname or "azurewebsites" in hostname
        except:
            return False
    
    def _is_gcp(self, ip: str, headers: Dict = None) -> bool:
        """Check if hosted on Google Cloud."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return "googleusercontent" in hostname or "google.com" in hostname
        except:
            return False
    
    def _is_cloudflare(self, headers: Dict) -> bool:
        """Check if using Cloudflare."""
        if not headers:
            return False
        
        cf_headers = ["CF-RAY", "CF-Cache-Status", "cf-request-id"]
        return any(h in headers for h in cf_headers)
    
    def _is_digitalocean(self, ip: str) -> bool:
        """Check if hosted on DigitalOcean."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return "digitalocean" in hostname
        except:
            return False
    
    def _detect_cdn_waf(self, domain: str, headers: Dict) -> Dict[str, Any]:
        """Detect CDN and WAF (Web Application Firewall)."""
        result = {"cdn": None, "waf": None}
        
        if not headers:
            return result
        
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # CDN Detection
        if "cf-ray" in headers_lower or "cf-cache-status" in headers_lower:
            result["cdn"] = "Cloudflare"
            result["waf"] = "Cloudflare WAF"
        elif "x-amz-cf-id" in headers_lower:
            result["cdn"] = "Amazon CloudFront"
        elif "x-cache" in headers_lower:
            cache_header = headers_lower["x-cache"]
            if "cloudfront" in cache_header:
                result["cdn"] = "Amazon CloudFront"
            elif "akamai" in cache_header:
                result["cdn"] = "Akamai"
        elif "server" in headers_lower:
            server = headers_lower["server"]
            if "cloudflare" in server:
                result["cdn"] = "Cloudflare"
                result["waf"] = "Cloudflare WAF"
            elif "akamai" in server:
                result["cdn"] = "Akamai"
        
        # WAF Detection
        if "x-sucuri-id" in headers_lower:
            result["waf"] = "Sucuri"
        elif "x-mod-security" in headers_lower:
            result["waf"] = "ModSecurity"
        elif "wordfence" in str(headers).lower():
            result["waf"] = "Wordfence"
        
        return result
    
    def _get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL/TLS certificate information."""
        ssl_info = {"enabled": False}
        
        try:
            import ssl
            import certifi
            
            context = ssl.create_default_context(cafile=certifi.where())
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        "enabled": True,
                        "version": ssock.version(),
                        "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "san": cert.get('subjectAltName', [])
                    }
        except Exception as e:
            logger.debug(f"SSL info lookup failed: {e}")
        
        return ssl_info
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
