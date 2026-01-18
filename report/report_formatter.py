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
        output = []
        output.append("=" * 70)
        output.append("SAFE WEB VULNERABILITY CHECKER - SCAN REPORT")
        output.append("=" * 70)
        output.append("")
        
        # Scan metadata
        output.append(f"Session ID:  {self.result.session_id}")
        output.append(f"Target URL:  {self.result.target_url}")
        output.append(f"Timestamp:   {self.result.timestamp.isoformat() if hasattr(self.result.timestamp, 'isoformat') else self.result.timestamp}")
        output.append(f"HTTPS:       {f'{GREEN}✓ Enabled{RESET}' if self.result.https_enabled else f'{RED}✗ Disabled{RESET}'}")
        output.append("")
        
        # Summary
        summary = self.result.summary()
        output.append("SUMMARY")
        output.append("-" * 70)
        output.append(f"{RED}🔴 HIGH:     {summary['high']}{RESET}")
        output.append(f"{YELLOW}🟠 MEDIUM:   {summary['medium']}{RESET}")
        output.append(f"{GREEN}🟢 LOW:      {summary['low']}{RESET}")
        output.append(f"📊 TOTAL:    {summary['total']}")
        output.append("")
        
        # Findings grouped by severity
        if self.result.findings:
            output.append("FINDINGS")
            output.append("-" * 70)
            
            # Sort findings by severity
            findings_by_severity = self._group_findings_by_severity()
            
            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                findings = findings_by_severity.get(severity, [])
                if findings:
                    symbol = SEVERITY_LEVELS[severity]['symbol']
                    color = RED if severity == "HIGH" else YELLOW if severity == "MEDIUM" else GREEN
                    output.append(f"\n{color}{symbol} {severity}{RESET}")
                    
                    for finding in findings:
                        output.append(f"  • {finding.title}")
                        output.append(f"    Location: {finding.location}")
                        output.append(f"    {finding.description}")
                        output.append(f"    {CYAN}Fix: {finding.recommendation}{RESET}")
                        if finding.cwe_reference:
                            output.append(f"    CWE: {finding.cwe_reference}")
                        output.append("")
        else:
            output.append(f"{GREEN}✓ No security issues found!{RESET}")
            output.append("")
        
        # Recommendations
        output.append("NEXT STEPS")
        output.append("-" * 70)
        output.append("1. Review findings above, prioritized by severity")
        output.append("2. Implement recommended fixes")
        output.append("3. Re-scan after changes to verify improvements")
        output.append("")
        output.append("=" * 70)
        
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
        https_status = "✅ Enabled" if self.result.https_enabled else "❌ Disabled"
        
        findings_html = ""
        for finding in self.result.findings:
            severity_color = "red" if finding.severity == "HIGH" else "orange" if finding.severity == "MEDIUM" else "green"
            findings_html += f"""
            <div class="finding">
                <h3 style="color: {severity_color};">{finding.title} ({finding.severity})</h3>
                <p><strong>Location:</strong> {finding.location}</p>
                <p>{finding.description}</p>
                <p><strong>Recommendation:</strong> {finding.recommendation}</p>
                <p><em>Reference: {finding.cwe_reference}</em></p>
                <hr>
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
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2 {{ color: #333; }}
                .summary-box {{ background-color: #f4f4f4; padding: 15px; border-radius: 5px; }}
                .finding {{ margin-bottom: 20px; }}
                hr {{ border: 0; border-top: 1px solid #ccc; }}
            </style>
        </head>
        <body>
            <h1>Safe Web Vulnerability Checker Report</h1>
            <div class="summary-box">
                <p><strong>Session ID:</strong> {self.result.session_id}</p>
                <p><strong>Target:</strong> <a href="{self.result.target_url}">{self.result.target_url}</a></p>
                <p><strong>Timestamp:</strong> {timestamp}</p>
                <p><strong>HTTPS Status:</strong> {https_status}</p>
                <h3>Summary</h3>
                <ul>
                    <li style="color: red;">HIGH: {summary['high']}</li>
                    <li style="color: orange;">MEDIUM: {summary['medium']}</li>
                    <li style="color: green;">LOW: {summary['low']}</li>
                    <li><strong>TOTAL: {summary['total']}</strong></li>
                </ul>
            </div>
            <h2>Detailed Findings</h2>
            {findings_html if findings_html else "<p>No security issues found.</p>"}
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
