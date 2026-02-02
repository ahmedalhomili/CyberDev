"""
WebSocket Security Scanner.
Tests WebSocket connections for security misconfigurations.
"""
import logging
from typing import List
from models import Finding
from scanner.core.requester import Requester
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class WebSocketScanner:
    """
    Scanner for WebSocket Security.
    """
    def __init__(self):
        self.requester = Requester()
    
    def scan(self, url: str) -> List[Finding]:
        findings = []
        
        # 1. Check if URL is a WebSocket URL
        if url.lower().startswith("ws://") or url.lower().startswith("wss://"):
            findings.append(Finding(
                title="WebSocket Protocol Detected",
                severity="INFO",
                description="Target uses WebSocket protocol. Further security testing recommended.",
                location=url,
                recommendation="Validate 'Origin' header during handshake. Use WSS (TLS). Implement authentication and authorization.",
                cwe_reference="CWE-1385"
            ))
            
            # Test for unencrypted WebSocket
            if url.lower().startswith("ws://"):
                findings.append(Finding(
                    title="Unencrypted WebSocket Connection (WS)",
                    severity="HIGH",
                    description="WebSocket connection is not encrypted (using WS instead of WSS). Data transmitted is vulnerable to interception.",
                    location=url,
                    recommendation="Use WSS (WebSocket Secure) protocol instead of WS to encrypt communications.",
                    cwe_reference="CWE-319"
                ))
            
            # Try to test WebSocket connection
            findings.extend(self._test_websocket_handshake(url))
        else:
            # Check if HTTP endpoint might support WebSocket upgrade
            findings.extend(self._check_for_websocket_upgrade(url))
        
        return findings
    
    def _test_websocket_handshake(self, ws_url: str) -> List[Finding]:
        """Test WebSocket handshake for security issues."""
        findings = []
        
        try:
            # Convert ws:// to http:// for testing
            parsed = urlparse(ws_url)
            if parsed.scheme == 'ws':
                http_url = ws_url.replace('ws://', 'http://')
            elif parsed.scheme == 'wss':
                http_url = ws_url.replace('wss://', 'https://')
            else:
                return findings
            
            # Test 1: Handshake without Origin header
            headers_no_origin = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13'
            }
            
            response_no_origin = self.requester.get(http_url, headers=headers_no_origin, timeout=5)
            
            # If we get 101 Switching Protocols without Origin validation
            if response_no_origin.status_code == 101:
                findings.append(Finding(
                    title="WebSocket Missing Origin Validation",
                    severity="HIGH",
                    description="WebSocket handshake succeeded without Origin header. This allows Cross-Site WebSocket Hijacking (CSWSH) attacks.",
                    location=ws_url,
                    recommendation="Validate the Origin header during WebSocket handshake. Only accept connections from trusted origins.",
                    cwe_reference="CWE-346"
                ))
            
            # Test 2: Handshake with malicious Origin
            evil_origin = "https://evil-attacker.com"
            headers_evil_origin = headers_no_origin.copy()
            headers_evil_origin['Origin'] = evil_origin
            
            response_evil = self.requester.get(http_url, headers=headers_evil_origin, timeout=5)
            
            if response_evil.status_code == 101:
                findings.append(Finding(
                    title="WebSocket Accepts Arbitrary Origin",
                    severity="CRITICAL",
                    description=f"WebSocket handshake succeeded with arbitrary Origin header '{evil_origin}'. This allows Cross-Site WebSocket Hijacking attacks from any domain.",
                    location=ws_url,
                    recommendation="Implement strict Origin header validation. Maintain a whitelist of allowed origins.",
                    cwe_reference="CWE-346"
                ))
            
            # Test 3: Check for authentication
            # If 101 is returned without any auth headers/cookies, it might be missing auth
            if response_no_origin.status_code == 101:
                # Check if we sent any auth
                if not any(h.lower() in ['authorization', 'cookie'] for h in headers_no_origin):
                    findings.append(Finding(
                        title="WebSocket Missing Authentication",
                        severity="HIGH",
                        description="WebSocket connection established without authentication. Anyone can connect to the WebSocket endpoint.",
                        location=ws_url,
                        recommendation="Implement authentication for WebSocket connections using tokens, session cookies, or other secure methods.",
                        cwe_reference="CWE-306"
                    ))
                    
        except Exception as e:
            logger.debug(f"Error testing WebSocket handshake: {e}")
        
        return findings
    
    def _check_for_websocket_upgrade(self, url: str) -> List[Finding]:
        """Check if HTTP endpoint supports WebSocket upgrade."""
        findings = []
        
        try:
            # Try WebSocket upgrade request
            headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13'
            }
            
            response = self.requester.get(url, headers=headers, timeout=5)
            
            # Check for WebSocket upgrade indicators
            if response.status_code == 101 or \
               'upgrade' in response.headers.get('Connection', '').lower() or \
               'websocket' in response.headers.get('Upgrade', '').lower():
                
                findings.append(Finding(
                    title="WebSocket Upgrade Supported",
                    severity="INFO",
                    description="Endpoint supports WebSocket protocol upgrade. Security testing recommended.",
                    location=url,
                    recommendation="Ensure WebSocket connections implement proper Origin validation, authentication, and use WSS protocol.",
                    cwe_reference="CWE-1385"
                ))
                
        except Exception:
            pass
        
        return findings
