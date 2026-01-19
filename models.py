"""
Data models for scan results and findings.
"""
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import List, Optional, Dict, Any

@dataclass
class ReconData:
    """Stores reconnaissance information."""
    ip_address: Optional[str] = None
    domain_info: Optional[Dict[str, Any]] = None  # Whois simple data
    server_os: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    dns_security: Optional[Dict[str, Any]] = None # SPF, DMARC info
    subdomains: List[str] = field(default_factory=list) # Passive subdomains
    
    def to_dict(self):
        return asdict(self)

@dataclass
class Finding:
    """Represents a single security finding."""
    title: str
    severity: str  # 'HIGH', 'MEDIUM', 'LOW'
    description: str
    location: str  # Which header/component
    recommendation: str
    cwe_reference: Optional[str] = None  # CWE ID if applicable
    
    def to_dict(self):
        return asdict(self)

@dataclass
class ScanResult:
    """Aggregates findings from a single scan execution."""
    session_id: str
    target_url: str
    timestamp: datetime
    findings: List[Finding]
    https_enabled: bool
    redirect_chain: List[str]
    recon: Optional[ReconData] = None
    
    def summary(self):
        """Return statistics about findings."""
        return {
            'total': len(self.findings),
            'critical': sum(1 for f in self.findings if f.severity == 'CRITICAL'),
            'high': sum(1 for f in self.findings if f.severity == 'HIGH'),
            'medium': sum(1 for f in self.findings if f.severity == 'MEDIUM'),
            'low': sum(1 for f in self.findings if f.severity == 'LOW')
        }
    
    def to_dict(self):
        """Convert to JSON-serializable format."""
        return {
            'session_id': self.session_id,
            'target_url': self.target_url,
            'timestamp': self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            'findings': [f.to_dict() for f in self.findings],
            'https_enabled': self.https_enabled,
            'redirect_chain': self.redirect_chain,
            'recon': self.recon.to_dict() if self.recon else None,
            'summary': self.summary()
        }
