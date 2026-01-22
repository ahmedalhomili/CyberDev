from typing import List
from models import Finding

class WebSocketScanner:
    """
    Scanner for WebSocket Security.
    """
    def scan(self, url: str) -> List[Finding]:
        findings = []
        if url.startswith("ws://") or url.startswith("wss://"):
             findings.append(Finding(
                title="WebSocket Detected",
                severity="INFO",
                description="Target uses WebSockets. Check for Origin validation and Authentication.",
                location=url,
                recommendation="Validate 'Origin' header during handshake. Use WSS (TLS).",
                cwe_reference="CWE-1385"
            ))
        return findings
