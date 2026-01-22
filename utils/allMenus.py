"""
Interactive Menu Handling using new Architecture.
"""
import sys
import time

from report.report_formatter import ReportFormatter
from scanner.scanner_orchestrator import SecurityScanner
from sessions.session_logger import SessionLogger
from utils.color import RED, GREEN, BLUE, RESET, YELLOW, CYAN, MAGENTA
from utils.domain2Ip import domain2ip
from utils.util import clear_screen, is_valid_url

# Initialize core components
session_logger = SessionLogger()
scanner = SecurityScanner(session_logger)

def mainMenu():
    clear_screen()
    print(f"{CYAN}╔═════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}║ {GREEN}SWVC v1.0 - Safe Web Vulnerability Checker{CYAN}  ║{RESET}")
    print(f"{CYAN}║           {YELLOW}(Hybrid Passive/Active){CYAN}           ║{RESET}")
    print(f"{CYAN}╚═════════════════════════════════════════════╝{RESET}")
    
    menuOp = [
        f'{GREEN}[1] Start New Scan{RESET}',
        f'{GREEN}[2] View History{RESET}',
        f'{GREEN}[3] About{RESET}',
        f'{RED}[0] Exit{RESET}',
    ]
    
    print("\n" + "\n".join(menuOp))
    
    try:
        choice = input(f"\n{BLUE}Select option >> {RESET}")
    except KeyboardInterrupt:
        sys.exit(0)

    if choice == '1':
        start_new_scan_flow()
    elif choice == '2':
        history_menu()
    elif choice == '3':
        aboutMenu()
    elif choice == '0':
        print(f"\n{MAGENTA}Goodbye!{RESET}")
        sys.exit(0)
    else:
        print(f"{RED}Invalid selection!{RESET}")
        time.sleep(1)
        mainMenu()

def start_new_scan_flow():
    clear_screen()
    print(f"{CYAN}=== Start New Scan ==={RESET}\n")
    print(f"{YELLOW}Enter target URL (e.g., https://example.com){RESET}")
    print(f"{MAGENTA}Type '0' to return to main menu.{RESET}\n")
    
    url = input(f"{BLUE}Target URL >> {RESET}").strip()

    if url == '0':
        mainMenu()
        return

    if not is_valid_url(url):
        print(f"\n{RED}[!] Invalid URL format. Please include http:// or https://{RESET}")
        time.sleep(2)
        start_new_scan_flow()
        return

    print(f"{CYAN}[INFO]{RESET} {GREEN}Resolved IP address for the given domain:{RESET} {domain2ip(url)}")


    print(f"\n{GREEN}[*] Initializing scan for: {url}{RESET}\n")
    
    # Progress Handler
    progress_state = {'last_msg': None, 'last_step': 0}
    
    def progress_handler(step, total, msg):
        # Clear current line (Active Progress Bar)
        sys.stdout.write('\r' + ' ' * 100 + '\r')
        
        # If we moved to a new step, mark the previous one as Done
        if progress_state['last_msg'] and step > progress_state['last_step']:
            print(f"{GREEN}[✓]{RESET} {progress_state['last_msg']}")
            
        # Draw Progress Bar for Current Step
        percent = 100 * (step / float(total))
        bar_len = 30
        filled = int(bar_len * step // total)
        bar = '█' * filled + '░' * (bar_len - filled)
        
        sys.stdout.write(f"{CYAN}[Step {step:02d}/{total}]{RESET} [{GREEN}{bar}{RESET}] {percent:3.0f}% {msg}")
        sys.stdout.flush()
        
        progress_state['last_msg'] = msg
        progress_state['last_step'] = step

    try:
        # Run the full scan using the orchestrator
        start_time = time.time()
        scan_result = scanner.scan(url, verbose=False, progress_callback=progress_handler)
        end_time = time.time()
        
        # Finalize the last step
        sys.stdout.write('\r' + ' ' * 100 + '\r')
        if progress_state['last_msg']:
             print(f"{GREEN}[✓]{RESET} {progress_state['last_msg']}")
        
        # Brief pause
        time.sleep(0.5)
        
        print(f"\n{GREEN}[✓] Scan Finished Successfully!{RESET}")
        
        # Executive Summary
        duration_sec = end_time - start_time
        mins, secs = divmod(int(duration_sec), 60)
        duration_str = f"{mins:02d}:{secs:02d}"
        
        summary = scan_result.summary()
        
        print(f"\n{CYAN}════════════ Scan Summary ════════════{RESET}")
        print(f"Target        : {scan_result.target_url}")
        print(f"Critical      : {RED}{summary.get('critical', 0)}{RESET}")
        print(f"High          : {RED}{summary['high']}{RESET}")
        print(f"Medium        : {YELLOW}{summary['medium']}{RESET}")
        print(f"Low           : {CYAN}{summary['low']}{RESET}")
        print(f"Scan Duration : {duration_str}")
        print(f"{CYAN}══════════════════════════════════════{RESET}")
        
        print(f"{CYAN}Session ID: {scan_result.session_id}{RESET}")
        
        formatter = ReportFormatter(scan_result)
        
        while True:
            print(f"\n{YELLOW}Select an action:{RESET}")
            print(f"{GREEN}[1] View Full Report (On Screen){RESET}")
            print(f"{GREEN}[2] Export Report (JSON, HTML, MD, CSV){RESET}")
            print(f"{RED}[0] Return to Main Menu{RESET}")
            
            sub = input(f"\n{BLUE}Option >> {RESET}").strip()
            
            if sub == '1':
                clear_screen()
                print(formatter.format_cli_output())
                print(f"\n{YELLOW}(End of Report){RESET}")
                # Don't return, loop back to allow export after viewing
            
            elif sub == '2':
                print(f"\n{CYAN}Select formats to export:{RESET}")
                print(f"{GREEN}[1] JSON  [2] Markdown  [3] HTML  [4] CSV{RESET}")
                export_choice = input(f"{BLUE}Formats (e.g. 1,3) >> {RESET}").strip()
                
                if export_choice:
                    choices = export_choice.replace(',', ' ').split()
                    timestamp = time.strftime("%Y%m%d_%H%M%S")
                    base_name = f"report_{timestamp}"
                    
                    for c in choices:
                        if c == '1':
                            with open(f"{base_name}.json", 'w', encoding='utf-8') as f:
                                f.write(formatter.format_json())
                            print(f"{GREEN}Saved: {base_name}.json{RESET}")
                        elif c == '2':
                            with open(f"{base_name}.md", 'w', encoding='utf-8') as f:
                                f.write(formatter.format_markdown())
                            print(f"{GREEN}Saved: {base_name}.md{RESET}")
                        elif c == '3':
                            with open(f"{base_name}.html", 'w', encoding='utf-8') as f:
                                f.write(formatter.format_html())
                            print(f"{GREEN}Saved: {base_name}.html{RESET}")
                        elif c == '4':
                            with open(f"{base_name}.csv", 'w', encoding='utf-8') as f:
                                f.write(formatter.format_csv())
                            print(f"{GREEN}Saved: {base_name}.csv{RESET}")
                    print(f"\n{GREEN}Export complete!{RESET}")
            
            elif sub == '0':
                mainMenu()
                return
            else:
                print(f"{RED}Invalid option!{RESET}")

    except Exception as e:
        print(f"\n{RED}[!] Scan failed: {str(e)}{RESET}")
        input(f"\n{BLUE}Press Enter to return to menu...{RESET}")
        mainMenu()
    
    # input(f"\n{BLUE}Press Enter to return to menu...{RESET}") # Handled in loop
    # mainMenu()

def history_menu():
    clear_screen()
    print(f"{CYAN}=== Scan History ==={RESET}\n")
    
    sessions = session_logger.list_sessions(limit=10)
    
    if not sessions:
        print(f"{YELLOW}No scan history found.{RESET}")
        input(f"\n{BLUE}Press Enter to return...{RESET}")
        mainMenu()
        return

    print(f"{'#':<4} | {'Target':<30} | {'Findings':<10} | {'Timestamp'}")
    print("-" * 70)
    
    for i, s in enumerate(sessions, 1):
        target = s['target_url'][:27] + '...' if len(s['target_url']) > 27 else s['target_url']
        print(f"{i:<4} | {target:<30} | {s['total_findings']:<10} | {s['timestamp']}")
        
    print("-" * 70)
    print(f"\n{GREEN}[ID] Enter number to view details{RESET}")
    print(f"{RED}[D] Delete all history{RESET}")
    print(f"{MAGENTA}[0] Back{RESET}")
    
    choice = input(f"\n{BLUE}Select >> {RESET}").strip().upper()
    
    if choice == '0':
        mainMenu()
        return
    elif choice == 'D':
        confirm = input(f"{RED}Are you sure you want to delete ALL history? (y/n): {RESET}")
        if confirm.lower() == 'y':
            session_logger.delete_history()
            print(f"{GREEN}History deleted.{RESET}")
            time.sleep(1)
        history_menu()
        history_menu()
        return
    
    # Try to parse selection
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(sessions):
            show_session_details(sessions[idx]['session_id'])
        else:
            print(f"{RED}Invalid selection.{RESET}")
            time.sleep(1)
            history_menu()
    except ValueError:
        print(f"{RED}Invalid input.{RESET}")
        time.sleep(1)
        history_menu()

def show_session_details(session_id):
    clear_screen()
    session_data = session_logger.load_session(session_id)
    
    if not session_data:
        print(f"{RED}Could not load session data.{RESET}")
    else:
        # Since we stored as dict, we can't directly use ReportFormatter without reconstructing objects.
        # But we can reconstruct a simple object or just print prettified JSON
        # Or, ideally, modify SessionLogger to return ScanResult object. 
        # For UX "Improvement", let's reconstruct the ScanResult object roughly to use the nice formatter.
        from models import ScanResult, Finding
        
        # Reconstruct Findings
        findings_list = []
        for f in session_data.get('findings', []):
            findings_list.append(Finding(
                title=f.get('title'),
                severity=f.get('severity'),
                description=f.get('description'),
                location=f.get('location'),
                recommendation=f.get('recommendation'),
                cwe_reference=f.get('cwe_reference')
            ))
            
        result = ScanResult(
            session_id=session_data.get('session_id'),
            target_url=session_data.get('target_url'),
            timestamp=session_data.get('timestamp'),
            findings=findings_list,
            https_enabled=session_data.get('https_enabled'),
            redirect_chain=session_data.get('redirect_chain')
        )
        
        formatter = ReportFormatter(result)
        print(formatter.format_cli_output())
        
    input(f"\n{BLUE}Press Enter to return to history...{RESET}")
    history_menu()

def aboutMenu():
    clear_screen()
    print(f"""
{CYAN}Safe Web Vulnerability Checker (SWVC){RESET}

{GREEN}Version:{RESET} 1.0 (Educational)
{GREEN}Mode:{RESET}    Passive Analysis

{YELLOW}Features:{RESET}
- HTTPS Enforcement Verification
- Security Headers Analysis (HSTS, CSP, X-Frame, etc.)
- CORS Policy Validation
- Session Logging & Reporting

{RED}Disclaimer:{RESET}
This tool is for educational purposes only.
Do not use on targets without permission.
""")
    input(f"{BLUE}Press Enter to return...{RESET}")
    mainMenu()
