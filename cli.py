"""
Command-line interface for Safe Web Vulnerability Checker.
Handles argument parsing and user interaction.
"""
import argparse


def parse_arguments():
    """
    Parse and return command-line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description='Safe Web Vulnerability Checker - Passive Security Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py scan https://example.com
  python main.py scan https://example.com --json report.json
  python main.py history --limit 5
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a URL for vulnerabilities')
    scan_parser.add_argument('url', help='Target URL to scan')
    scan_parser.add_argument('-v', '--verbose', action='store_true', 
                           help='Enable verbose output')
    scan_parser.add_argument('-j', '--json', metavar='FILE',
                           help='Export report as JSON to file')
    scan_parser.add_argument('-m', '--markdown', metavar='FILE',
                           help='Export report as Markdown to file')
    scan_parser.add_argument('--html', metavar='FILE',
                           help='Export report as HTML to file')
    scan_parser.add_argument('--csv', metavar='FILE',
                           help='Export report as CSV to file')
    scan_parser.add_argument('-p', '--profile', choices=['passive', 'standard', 'extended'],
                           default='standard',
                           help='Scan profile: passive=Quick Scan (recon only), standard=Full Scan (default), extended=Deep Audit (comprehensive)')
    
    # History command
    history_parser = subparsers.add_parser('history', help='View scan history')
    history_parser.add_argument('--limit', type=int, default=10,
                              help='Number of sessions to display (default: 10)')
    
    # Show command
    show_parser = subparsers.add_parser('show', help='Show detailed scan report')
    show_parser.add_argument('session_id', help='Session ID to display')
    
    # Help command (alias for --help)
    help_parser = subparsers.add_parser('help', help='Show detailed help and usage examples')
    
    # Man command (manual/documentation)
    man_parser = subparsers.add_parser('man', help='Show comprehensive manual and documentation')

    # Interactive mode (default if no args)
    # No explicit command needed, logic in main will handle empty args
    
    return parser.parse_args()
