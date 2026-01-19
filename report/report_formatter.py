"""
Report formatting and output generation module.
Formats scan results for various output formats.
"""
from typing import List
from models import ScanResult, Finding
import json
from config import SEVERITY_LEVELS
from utils.color import RED, YELLOW, GREEN, CYAN, RESET, BLUE

class ReportFormatter:
    """Formats scan results for various output formats."""
    
    def __init__(self, scan_result: ScanResult):
        """
        Initialize formatter with scan result.
        
        Args:
            scan_result: ScanResult object to format
        """
        self.result = scan_result
    
    def format_cli_output(self) -> str:
        """
        Generate CLI-friendly formatted output with colors and symbols.
        
        Returns:
            Formatted string for terminal output
        """
        # Helper for aligned printing
        def label_val(label, val):
            return f"{label:<14}: {val}"
            
        output = []
        # Header
        output.append(f"{CYAN}╔{'═'*76}╗{RESET}")
        output.append(f"{CYAN}║ {GREEN}{'SAFE WEB VULNERABILITY CHECKER - SCAN REPORT':^74}{CYAN} ║{RESET}")
        output.append(f"{CYAN}╚{'═'*76}╝{RESET}")
        output.append("")
        
        # Metadata
        timestamp_str = self.result.timestamp
        if hasattr(self.result.timestamp, 'isoformat'):
            timestamp_str = self.result.timestamp.strftime("%Y-%m-%d %H:%M:%S")

        output.append(f"{BLUE}[ SCAN METADATA ]{RESET}")
        output.append(f"{BLUE}{'─'*17}{RESET}")
        output.append(f" ➤ {label_val('Session ID', self.result.session_id)}")
        output.append(f" ➤ {label_val('Target URL', self.result.target_url)}")
        output.append(f" ➤ {label_val('Timestamp', timestamp_str)}")
        https_status = f"{GREEN}✓ Enabled{RESET}" if self.result.https_enabled else f"{RED}✗ Disabled{RESET}"
        output.append(f" ➤ {label_val('HTTPS', https_status)}")
        output.append("")

        # Reconnaissance
        if self.result.recon:
            recon = self.result.recon
            output.append(f"{BLUE}[ 🕵️  RECONNAISSANCE ]{RESET}")
            output.append(f"{BLUE}{'─'*20}{RESET}")
            
            # Target Info Group
            output.append(f"{YELLOW}➤ Target Info:{RESET}")
            output.append(f"   • {label_val('IP Address', recon.ip_address)}")
            if recon.server_os and recon.server_os != "Unknown":
                output.append(f"   • {label_val('Server OS', recon.server_os)}")
            
            if recon.domain_info and 'error' not in recon.domain_info:
                di = recon.domain_info
                if di.get('registrar'): output.append(f"   • {label_val('Registrar', di['registrar'])}")
                if di.get('org'): output.append(f"   • {label_val('Organization', f'{di['org']} ({di.get('country', 'Unknown')})')}")
                if di.get('creation_date'): output.append(f"   • {label_val('Created', str(di['creation_date']).split(' ')[0])}")
            
            output.append("")

            # Technologies Group
            if recon.technologies:
                output.append(f"{YELLOW}➤ Technologies:{RESET}")
                for tech in recon.technologies:
                    output.append(f"   • {tech}")
                output.append("")

            # Network Group
            output.append(f"{YELLOW}➤ Network & Security:{RESET}")
            ports = ', '.join(map(str, recon.open_ports)) if recon.open_ports else "None Detected"
            output.append(f"   • {label_val('Open Ports', ports)}")
            
            if recon.dns_security:
                dns = recon.dns_security
                vuln_status = f"{RED}⚠️  Vulnerable{RESET}" if dns.get('vulnerable') else f"{GREEN}✓ Secure{RESET}"
                output.append(f"   • {label_val('Email Sec', vuln_status)}")
                
                spf_val = dns.get('spf') or f"{RED}Missing{RESET}"
                dmarc_val = dns.get('dmarc') or f"{RED}Missing{RESET}"
                
                output.append(f"       - SPF   : {spf_val}")
                output.append(f"       - DMARC : {dmarc_val}")
            
            output.append("")

            if recon.subdomains:
                output.append(f"{YELLOW}➤ Subdomains (Top {len(recon.subdomains)}):{RESET}")
                for sub in recon.subdomains[:5]:
                     output.append(f"   • {sub}")
                if len(recon.subdomains) > 5:
                    output.append(f"   • ... and {len(recon.subdomains) - 5} more")
                output.append("")

        # Summary
        summary = self.result.summary()
        output.append(f"{BLUE}[ 📊 SUMMARY OF FINDINGS ]{RESET}")
        output.append(f"{BLUE}{'─'*26}{RESET}")
        output.append(f"  {RED}🔴 HIGH    : {summary['high']}{RESET}")
        output.append(f"  {YELLOW}🟠 MEDIUM  : {summary['medium']}{RESET}")
        output.append(f"  {GREEN}🟢 LOW     : {summary['low']}{RESET}")
        output.append(f"  {BLUE}{'-'*12}{RESET}")
        output.append(f"  {BLUE}📊 TOTAL   : {summary['total']}{RESET}")
        output.append("")
        
        # Findings
        if self.result.findings:
            output.append(f"{BLUE}[ 🔍 DETAILED FINDINGS ]{RESET}")
            output.append(f"{BLUE}{'─'*24}{RESET}")
            
            findings_by_severity = self._group_findings_by_severity()
            
            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                findings = findings_by_severity.get(severity, [])
                if findings:
                    color = RED if severity == "HIGH" else YELLOW if severity == "MEDIUM" else GREEN
                    
                    for finding in findings:
                        output.append(f"\n{color}{severity} | {finding.title}{RESET}")
                        output.append(f"{color}{'-'*78}{RESET}")
                        output.append(f"   {label_val('Location', finding.location)}")
                        output.append(f"   {label_val('Description', finding.description)}")
                        output.append(f"   {label_val('Fix', f'{CYAN}{finding.recommendation}{RESET}')}")
                        if finding.cwe_reference:
                            output.append(f"   {label_val('Reference', finding.cwe_reference)}")
                        output.append("")
        else:
            output.append(f"\n{GREEN}✓ Great job! No security issues found based on passive analysis.{RESET}\n")

        # Footer
        output.append(f"{CYAN}═{'═'*76}═{RESET}")
        
        return "\n".join(output)
    
    def format_json(self) -> str:
        """
        Generate JSON-formatted report.
        
        Returns:
            JSON string with full scan data
        """
        return json.dumps(self.result.to_dict(), indent=2)
    
    def format_markdown(self) -> str:
        """
        Generate markdown-formatted report.
        
        Returns:
            Markdown formatted report
        """
        md = []
        md.append(f"# Safe Web Vulnerability Checker Report")
        md.append(f"\n**Session ID:** `{self.result.session_id}`")
        md.append(f"\n**Target:** {self.result.target_url}")
        md.append(f"\n**Scanned:** {self.result.timestamp.isoformat() if hasattr(self.result.timestamp, 'isoformat') else self.result.timestamp}")
        md.append(f"\n**HTTPS Status:** {'✅ Enabled' if self.result.https_enabled else '❌ Disabled'}")
        
        # Reconnaissance
        if self.result.recon:
            md.append(f"\n## 🕵️ Reconnaissance\n")
            md.append(f"- **IP Address**: `{self.result.recon.ip_address}`")
            if self.result.recon.server_os:
                md.append(f"- **Server OS**: {self.result.recon.server_os}")
            if self.result.recon.technologies:
                md.append(f"- **Technologies**: {', '.join(self.result.recon.technologies)}")
            if self.result.recon.open_ports:
                md.append(f"- **Open Ports**: {', '.join(map(str, self.result.recon.open_ports))}")
                
            if self.result.recon.domain_info and 'error' not in self.result.recon.domain_info:
                di = self.result.recon.domain_info
                md.append("\n**Domain Info:**")
                md.append(f"- Registrar: {di.get('registrar')}")
                md.append(f"- Created: {di.get('creation_date')}")
                md.append(f"- Org: {di.get('org')}")
                md.append(f"- Country: {di.get('country')}")

            if self.result.recon.dns_security:
                dns_sec = self.result.recon.dns_security
                md.append(f"\n**DNS Security:**")
                md.append(f"- **Status**: {'⚠️ Vulnerable to Spoofing' if dns_sec.get('vulnerable') else '✅ Secure'}")
                md.append(f"- **SPF Record**: `{dns_sec.get('spf') or 'Missing'}`")
                md.append(f"- **DMARC Record**: `{dns_sec.get('dmarc') or 'Missing'}`")

            if self.result.recon.subdomains:
                md.append(f"\n**Subdomains Discovered (Top Result):**")
                for sub in self.result.recon.subdomains:
                    md.append(f"- {sub}")

        # Summary
        summary = self.result.summary()
        md.append(f"\n## Summary\n")
        md.append(f"| Severity | Count |")
        md.append(f"|----------|-------|")
        md.append(f"| 🔴 High  | {summary['high']} |")
        md.append(f"| 🟠 Medium| {summary['medium']} |")
        md.append(f"| 🟢 Low   | {summary['low']} |")
        md.append(f"| 📊 Total | {summary['total']} |")
        
        # Findings
        if self.result.findings:
            md.append(f"\n## Findings\n")
            # Flatten scan result logic needs findings to be objects. 
            # In new architecture they are Finding objects.
            sorted_findings = sorted(self.result.findings, 
                                 key=lambda f: ['HIGH', 'MEDIUM', 'LOW'].index(f.severity))
            
            for finding in sorted_findings:
                severity_info = SEVERITY_LEVELS[finding.severity]
                md.append(f"### {severity_info['symbol']} {finding.title}")
                md.append(f"\n**Severity:** {finding.severity}")
                md.append(f"\n**Location:** {finding.location}")
                md.append(f"\n{finding.description}")
                md.append(f"\n**Recommendation:** {finding.recommendation}")
                if finding.cwe_reference:
                    md.append(f"\n**Reference:** {finding.cwe_reference}")
                md.append(f"\n---\n")
        else:
            md.append(f"\n## Results\n✅ No security issues detected!\n")
        
        return "\n".join(md)
    
    def format_html(self) -> str:
        """
        Generate HTML report.
        """
        summary = self.result.summary()
        timestamp = self.result.timestamp.isoformat() if hasattr(self.result.timestamp, 'isoformat') else self.result.timestamp
        https_status = "<span class='badge success'>✓ Enabled</span>" if self.result.https_enabled else "<span class='badge danger'>✗ Disabled</span>"
        
        # Recon HTML Generation
        recon_html = ""
        if self.result.recon:
            r = self.result.recon
            
            # Target Info
            target_info = f"""
            <div class='recon-group'>
                <h4>➤ Target Info</h4>
                <ul>
                    <li><strong>IP Address:</strong> {r.ip_address}</li>
                    <li><strong>Server OS:</strong> {r.server_os}</li>
            """
            if r.domain_info and 'error' not in r.domain_info:
                di = r.domain_info
                target_info += f"""
                    <li><strong>Registrar:</strong> {di.get('registrar', 'N/A')}</li>
                    <li><strong>Organization:</strong> {di.get('org', 'N/A')} ({di.get('country', 'N/A')})</li>
                    <li><strong>Created:</strong> {di.get('creation_date', 'N/A')}</li>
                """
            target_info += "</ul></div>"

            # Tech & Net
            tech_net = "<div class='recon-group'><h4>➤ Technologies & Network</h4><ul>"
            if r.technologies:
                tech_net += f"<li><strong>Stack:</strong> {', '.join(r.technologies)}</li>"
            
            ports = ', '.join(map(str, r.open_ports)) if r.open_ports else "None Detected"
            tech_net += f"<li><strong>Open Ports:</strong> {ports}</li>"
            
            if r.dns_security:
                d = r.dns_security
                status = "<span class='text-danger'>⚠️ Vulnerable</span>" if d.get('vulnerable') else "<span class='text-success'>✓ Secure</span>"
                tech_net += f"""
                    <li><strong>Email Security:</strong> {status}</li>
                    <ul>
                        <li>SPF: {d.get('spf') or 'Missing'}</li>
                        <li>DMARC: {d.get('dmarc') or 'Missing'}</li>
                    </ul>
                """
            tech_net += "</ul></div>"

            # Subdomains
            subdomains = ""
            if r.subdomains:
                subdomains = "<div class='recon-group'><h4>➤ Discovered Subdomains</h4><ul>"
                for sub in r.subdomains[:10]:
                    subdomains += f"<li>{sub}</li>"
                if len(r.subdomains) > 10:
                    subdomains += f"<li>... and {len(r.subdomains) - 10} more</li>"
                subdomains += "</ul></div>"
            
            recon_html = f"""
            <div class="section">
                <h2 class="section-title">🕵️ Reconnaissance (Intelligence)</h2>
                <div class="recon-container">
                    {target_info}
                    {tech_net}
                    {subdomains}
                </div>
            </div>
            """

        # Findings HTML
        findings_html = ""
        sorted_findings = sorted(self.result.findings, key=lambda f: ['HIGH', 'MEDIUM', 'LOW'].index(f.severity))
        
        for finding in sorted_findings:
            severity_class = finding.severity.lower()
            findings_html += f"""
            <div class="finding-card {severity_class}-border">
                <div class="finding-header {severity_class}-bg">
                    <h3>[{finding.severity}] {finding.title}</h3>
                </div>
                <div class="finding-body">
                    <p><strong>📍 Location:</strong> {finding.location}</p>
                    <p><strong>📝 Description:</strong> {finding.description}</p>
                    <p><strong>🛡️ Recommendation:</strong> <span class="fix-code">{finding.recommendation}</span></p>
                    <p class="reference"><strong>Reference:</strong> {finding.cwe_reference or 'N/A'}</p>
                </div>
            </div>
            """
            
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Scan Report - {self.result.target_url}</title>
            <style>
                :root {{ --primary: #2c3e50; --secondary: #34495e; --accent: #3498db; --bg: #f5f6fa; --text: #2c3e50; }}
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; margin: 0; padding: 20px; }}
                .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }}
                
                /* Header */
                header {{ text-align: center; border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }}
                h1 {{ color: var(--primary); margin: 0; }}
                .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; text-align: left; background: #f8f9fa; padding: 15px; border-radius: 8px; }}
                
                /* Sections */
                .section {{ margin-bottom: 40px; }}
                .section-title {{ border-left: 5px solid var(--accent); padding-left: 15px; color: var(--secondary); }}
                
                /* Recon */
                .recon-container {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
                .recon-group {{ background: #fff; border: 1px solid #eee; padding: 15px; border-radius: 8px; }}
                .recon-group ul {{ list-style: none; padding: 0; }}
                .recon-group li {{ margin-bottom: 8px; font-size: 0.95em; }}
                
                /* Summary */
                .summary-stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat-box {{ text-align: center; padding: 15px; border-radius: 8px; min-width: 100px; color: white; }}
                .stat-high {{ background: #e74c3c; }} .stat-medium {{ background: #f39c12; }} .stat-low {{ background: #27ae60; }} .stat-total {{ background: #7f8c8d; }}
                
                /* Findings */
                .finding-card {{ border: 1px solid #ddd; border-radius: 8px; margin-bottom: 20px; overflow: hidden; background: white; }}
                .finding-header {{ padding: 10px 20px; color: white; }}
                .finding-body {{ padding: 20px; }}
                .high-bg {{ background: #e74c3c; }} .medium-bg {{ background: #f39c12; }} .low-bg {{ background: #27ae60; }}
                .high-border {{ border-color: #e74c3c; }} .medium-border {{ border-color: #f39c12; }} .low-border {{ border-color: #27ae60; }}
                
                /* Utils */
                .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 0.85em; color: white; }}
                .success {{ background: #27ae60; }} .danger {{ background: #e74c3c; }}
                .text-danger {{ color: #e74c3c; font-weight: bold; }} .text-success {{ color: #27ae60; font-weight: bold; }}
                .fix-code {{ background: #eee; padding: 2px 5px; border-radius: 3px; font-family: monospace; color: #c0392b; }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>🛡️ Safe Web Vulnerability Scan Report</h1>
                    <div class="meta-grid">
                        <div><strong>Session ID:</strong><br>{self.result.session_id}</div>
                        <div><strong>Target:</strong><br><a href="{self.result.target_url}">{self.result.target_url}</a></div>
                        <div><strong>Date:</strong><br>{timestamp}</div>
                        <div><strong>HTTPS:</strong><br>{https_status}</div>
                    </div>
                </header>

                {recon_html}

                <div class="section">
                    <h2 class="section-title">📊 Executive Summary</h2>
                    <div class="summary-stats">
                        <div class="stat-box stat-high">
                            <h3>{summary['high']}</h3>
                            <span>HIGH</span>
                        </div>
                        <div class="stat-box stat-medium">
                            <h3>{summary['medium']}</h3>
                            <span>MEDIUM</span>
                        </div>
                        <div class="stat-box stat-low">
                            <h3>{summary['low']}</h3>
                            <span>LOW</span>
                        </div>
                        <div class="stat-box stat-total">
                            <h3>{summary['total']}</h3>
                            <span>TOTAL</span>
                        </div>
                    </div>
                </div>

                <div class="section">
                    <h2 class="section-title">🔍 Detailed Findings</h2>
                    {findings_html if findings_html else "<div style='text-align:center; padding:40px; background:#f8f9fa; border-radius:8px;'><h3>✅ Excellent! No security issues found.</h3></div>"}
                </div>
                
                <footer style="text-align: center; margin-top: 50px; color: #7f8c8d; font-size: 0.9em;">
                    Generated by Safe Web Vulnerability Checker
                </footer>
            </div>
        </body>
        </html>
        """
        return html_template

    def format_csv(self) -> str:
        """
        Generate CSV content.
        """
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write Header
        writer.writerow(['Session ID', 'Timestamp', 'Target URL', 'Finding Title', 'Severity', 'Location', 'Description', 'Recommendation', 'CWE'])
        
        # Write Data
        timestamp = self.result.timestamp.isoformat() if hasattr(self.result.timestamp, 'isoformat') else self.result.timestamp
        
        if not self.result.findings:
            writer.writerow([self.result.session_id, timestamp, self.result.target_url, 'No Findings', 'N/A', 'N/A', 'No issues found', 'N/A', 'N/A'])
        else:
            for finding in self.result.findings:
                writer.writerow([
                    self.result.session_id,
                    timestamp,
                    self.result.target_url,
                    finding.title,
                    finding.severity,
                    finding.location,
                    finding.description,
                    finding.recommendation,
                    finding.cwe_reference
                ])
                
        return output.getvalue()

    def _group_findings_by_severity(self) -> dict:
        """Group findings by severity level."""
        grouped = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for finding in self.result.findings:
            if finding.severity in grouped:
                grouped[finding.severity].append(finding)
        return grouped
