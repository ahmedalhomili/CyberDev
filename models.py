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
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReconData':
        """Create ReconData from dictionary."""
        if not data:
            return None
        return cls(
            ip_address=data.get('ip_address'),
            domain_info=data.get('domain_info'),
            server_os=data.get('server_os'),
            technologies=data.get('technologies', []),
            open_ports=data.get('open_ports', []),
            dns_security=data.get('dns_security'),
            subdomains=data.get('subdomains', [])
        )

@dataclass
class Finding:
    """Represents a single security finding."""
    title: str
    severity: str  # 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'CRITICAL'
    description: str
    location: str  # Which header/component
    recommendation: str
    cwe_reference: Optional[str] = None  # CWE ID if applicable
    confidence: str = "High" # 'High', 'Medium', 'Low'
    
    def to_dict(self):
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create Finding from dictionary."""
        return cls(
            title=data['title'],
            severity=data['severity'],
            description=data['description'],
            location=data['location'],
            recommendation=data['recommendation'],
            cwe_reference=data.get('cwe_reference'),
            confidence=data.get('confidence', 'High')
        )

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
            'low': sum(1 for f in self.findings if f.severity == 'LOW'),
            'info': sum(1 for f in self.findings if f.severity == 'INFO'),
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
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanResult':
        """Create ScanResult from dictionary."""
        timestamp = data['timestamp']
        if isinstance(timestamp, str):
            from datetime import datetime
            timestamp = datetime.fromisoformat(timestamp)
        
        return cls(
            session_id=data['session_id'],
            target_url=data['target_url'],
            timestamp=timestamp,
            findings=[Finding.from_dict(f) for f in data.get('findings', [])],
            https_enabled=data.get('https_enabled', False),
            redirect_chain=data.get('redirect_chain', []),
            recon=ReconData.from_dict(data.get('recon')) if data.get('recon') else None
        )
