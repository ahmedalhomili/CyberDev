"""
Safe Web Vulnerability Checker - Main Entry Point
Passive web security analysis tool for educational purposes.
"""
import sys
import logging
from cli import parse_arguments
from scanner.core.scanner_orchestrator import SecurityScanner
from sessions.session_logger import SessionLogger
from report.report_formatter import ReportFormatter
from ui.menus import mainMenu

# Configure logging
# Redirect logs to a file to prevent interfering with the CLI progress bar
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='scanner_debug.log',
    filemode='a'
)
logger = logging.getLogger(__name__)

def show_detailed_help():
    """Display detailed help and usage examples."""
    help_text = """
╔════════════════════════════════════════════════════════════════╗
║         Safe Web Vulnerability Checker - Help Guide           ║
╚════════════════════════════════════════════════════════════════╝

📖 AVAILABLE COMMANDS:

  scan         Scan a target URL for security vulnerabilities
  history      View previous scan sessions
  show         Display detailed report for a specific session
  help         Show this help message
  man          Show comprehensive manual with examples
  --help       Show quick command reference

🎯 QUICK EXAMPLES:

  # Interactive Mode (GUI)
  python main.py

  # Basic Scan
  python main.py scan https://example.com

  # Scan with specific depth level
  python main.py scan https://example.com --level 3

  # Scan with verbose output
  python main.py scan https://example.com --verbose

  # Export results to multiple formats
  python main.py scan https://example.com --json report.json --html report.html

  # View last 5 scans
  python main.py history --limit 5

  # Show specific scan details
  python main.py show SWVC-20260202-XXXXXX

📊 SCAN LEVELS:

  Level 1 (Basic)    - Quick passive checks only
  Level 2 (Medium)   - Passive + basic active tests
  Level 3 (Advanced) - Extended vulnerability scanning
  Level 4 (Full)     - Complete comprehensive scan [Default]

📁 EXPORT FORMATS:

  --json FILE        JSON format (machine-readable)
  --markdown FILE    Markdown format (readable report)
  --html FILE        HTML format (web browser)
  --csv FILE         CSV format (spreadsheet)

💡 TIPS:

  • Use --verbose for detailed scan progress
  • Combine multiple export formats in one scan
  • Sessions are auto-saved in sessions/scan_sessions/
  • Use 'history' to find session IDs for 'show' command

🔗 MORE INFO:

  Run 'python main.py man' for comprehensive documentation
  Run 'python main.py scan --help' for scan-specific options

════════════════════════════════════════════════════════════════
    """
    print(help_text)

def show_manual():
    """Display comprehensive manual and documentation."""
    manual_text = """
╔════════════════════════════════════════════════════════════════╗
║     Safe Web Vulnerability Checker - Manual (man page)        ║
╚════════════════════════════════════════════════════════════════╝

NAME
    CyberDev Security Scanner - Safe Web Vulnerability Checker
    A hybrid passive/active web security analysis tool

SYNOPSIS
    python main.py [COMMAND] [OPTIONS]

DESCRIPTION
    CyberDev is an educational security scanner designed to identify
    common web vulnerabilities. It performs both passive reconnaissance
    and active vulnerability testing in a safe, ethical manner.

COMMANDS

    (no command)
        Launch interactive GUI mode with menu-driven interface.
        Best for beginners or step-by-step scanning.

    scan URL [OPTIONS]
        Execute security scan on target URL.
        
        OPTIONS:
            -v, --verbose
                Enable detailed progress output during scan.
                Shows each test as it runs.
                
            -l, --level {1,2,3,4}
                Set scan depth/intensity level.
                Default: 4 (full scan)
                
                Level 1: Basic passive reconnaissance only
                    • HTTP headers analysis
                    • SSL/TLS configuration
                    • Technology detection
                    
                Level 2: Passive + basic active tests
                    • Everything in Level 1
                    • robots.txt analysis
                    • Directory enumeration
                    • Basic security headers
                    
                Level 3: Extended vulnerability scanning
                    • Everything in Level 2
                    • SQL Injection testing
                    • XSS detection
                    • LFI/RFI checks
                    
                Level 4: Complete comprehensive scan
                    • Everything in Level 3
                    • RCE testing
                    • SSRF detection
                    • API security checks
                    • JWT vulnerabilities
                    • File upload testing
                    • All 18+ vulnerability checks
            
            -j, --json FILE
                Export results to JSON format.
                Machine-readable, ideal for automation.
                
            -m, --markdown FILE
                Export results to Markdown format.
                Human-readable report with formatting.
                
            --html FILE
                Export results to HTML format.
                Professional report viewable in browser.
                
            --csv FILE
                Export results to CSV format.
                Suitable for Excel/spreadsheet analysis.

    history [--limit N]
        Display list of previous scan sessions.
        
        OPTIONS:
            --limit N
                Show only last N sessions (default: 10)

    show SESSION_ID
        Display detailed report for specific scan session.
        Use 'history' command to find session IDs.

    help
        Display quick help guide with examples.

    man
        Display this comprehensive manual.

VULNERABILITY CHECKS

    The scanner tests for 18+ vulnerability types:
    
    🔴 Critical/High:
        • SQL Injection (SQLi)
        • Cross-Site Scripting (XSS)
        • Remote Code Execution (RCE)
        • Server-Side Request Forgery (SSRF)
        • XML External Entity (XXE)
        • Insecure Deserialization
        • File Upload Vulnerabilities
        
    🟠 Medium:
        • Local File Inclusion (LFI)
        • Open Redirect
        • Host Header Injection
        • CORS Misconfiguration
        • Cache Poisoning
        • JWT Vulnerabilities
        
    🟢 Low/Info:
        • Missing Security Headers
        • SSL/TLS Issues
        • Information Disclosure
        • API Security Misconfigurations

RECONNAISSANCE FEATURES

    • IP Geolocation
    • Domain WHOIS information
    • DNS security (SPF, DMARC)
    • Technology stack detection
    • Open ports scanning
    • CDN/WAF detection
    • Hosting provider identification
    • SSL certificate analysis

FILES

    sessions/scan_sessions/
        Directory containing all scan session logs in JSON format.
        Each session is saved with unique ID and timestamp.
    
    scanner_debug.log
        Detailed debug log of scanner operations.
        Useful for troubleshooting.
    
    CODE_REVIEW.md
        Code quality review and improvement recommendations.
    
    ARCHITECTURE.md
        Detailed project architecture documentation.

EXAMPLES

    Basic usage:
        $ python main.py scan https://testphp.vulnweb.com
    
    Quick scan with JSON export:
        $ python main.py scan https://example.com -l 2 -j quick.json
    
    Full scan with all export formats:
        $ python main.py scan https://example.com \\
            --json full.json \\
            --html full.html \\
            --markdown full.md \\
            --csv full.csv
    
    Verbose scan for debugging:
        $ python main.py scan https://example.com -v
    
    View recent scans:
        $ python main.py history --limit 5
    
    Inspect specific scan:
        $ python main.py show SWVC-20260202-221805-example.com-abc123

NOTES

    • Always obtain permission before scanning any website
    • This tool is for educational purposes only
    • Some tests may trigger WAF/IDS alerts
    • Scanning without permission may be illegal
    • Use responsibly and ethically

SEE ALSO

    README.md              - Project overview and setup
    QUICK_START.md         - Quick start guide for beginners
    DEVELOPMENT_GUIDE.md   - Developer documentation
    ARCHITECTURE.md        - System architecture details

AUTHOR

    CyberDev Security Scanner
    Educational Security Tool - Version 1.1.0

BUGS

    Report issues to: [Your contact/GitHub]

════════════════════════════════════════════════════════════════
    """
    print(manual_text)

def main():
    """Main application entry point."""
    try:
        # Check if arguments are provided, otherwise launch interactive menu
        if len(sys.argv) == 1:
            mainMenu()
            return

        args = parse_arguments()
        
        if not args.command:
            # Should be handled by len(sys.argv) check, but just in case
            mainMenu()
            return
        
        session_logger = SessionLogger()
        
        if args.command == 'scan':
            # Execute scan
            scanner = SecurityScanner(session_logger)
            try:
                # Default to level 4 (all) if not specified via CLI (though CLI default handles it)
                lvl = getattr(args, 'level', '4')
                result = scanner.scan(args.url, args.verbose, level=lvl)
                
                # Display CLI output
                formatter = ReportFormatter(result)
                print(formatter.format_cli_output())
                
                # Export if requested
                if args.json:
                    with open(args.json, 'w') as f:
                        f.write(formatter.format_json())
                    print(f"\n✓ JSON report saved to: {args.json}")
                
                if args.markdown:
                    with open(args.markdown, 'w', encoding='utf-8') as f:
                        f.write(formatter.format_markdown())
                    print(f"✓ Markdown report saved to: {args.markdown}")
                
                if args.html:
                    with open(args.html, 'w', encoding='utf-8') as f:
                        f.write(formatter.format_html())
                    print(f"✓ HTML report saved to: {args.html}")

                if args.csv:
                    with open(args.csv, 'w', encoding='utf-8') as f:
                        f.write(formatter.format_csv())
                    print(f"✓ CSV report saved to: {args.csv}")

            except Exception as e:
                print(f"Scan failed: {str(e)}")
        
        elif args.command == 'history':
            # Show scan history
            sessions = session_logger.list_sessions(args.limit)
            if sessions:
                print(f"Recent Scans (last {len(sessions)}):\n")
                print(f"{'Session ID':<30} | {'Target':<30} | {'Findings':<10}")
                print("-" * 80)
                for s in sessions:
                    print(f"{s['session_id']:<30} | {s['target_url']:<30} | {s['total_findings']:<10}")
            else:
                print("No scan sessions found.")
        
        elif args.command == 'show':
            # Show specific session
            session_data = session_logger.load_session(args.session_id)
            if session_data:
                # We need to reconstruct ScanResult/Finding objects to use formatter
                # simpler to just print JSON or a simple summary for now if we don't want to deserialize fully
                # But let's try to use the Formatter format_cli_output if possible
                # Ideally Models should have from_dict method
                print(f"Detailed view for session: {args.session_id}")
                import json
                print(json.dumps(session_data, indent=2))
            else:
                print(f"Session not found: {args.session_id}")
        
        elif args.command == 'help':
            # Show detailed help
            show_detailed_help()
        
        elif args.command == 'man':
            # Show comprehensive manual
            show_manual()
    
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        # logger.error(f"Error: {str(e)}") # Keep logs file based maybe?
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()