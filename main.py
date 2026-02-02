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
    
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        # logger.error(f"Error: {str(e)}") # Keep logs file based maybe?
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()