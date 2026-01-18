from sessions.mangmant_sessions import (
    create_session,
    history_session,
    print_session,
    delete_history,
    get_session,
    save_session
)
from scanner.https_check import check_https_redirect
from scanner.headers_check import check_security_headers
from scanner.cors_check import check_cors
from scanner.requester import fetch_response
from report.formatter import (
    format_https_report,
    format_headers_report,
    format_cors_report,
    print_summary
)
from utils.color import RED, GREEN, RESET, BLUE
from utils.util import clear_screen
from utils.severity import calculate_overall_severity

import time


def mainMenu():
    clear_screen()
    menuOp = [
        f'{GREEN}1-Session Menu{RESET}',
        f'{GREEN}2-About Tool{RESET}',
        f'{RED}00-Exit{RESET}',
    ]
    for op in menuOp:
        print(op)
    try:
        x = int(input(f"{BLUE} Enter select option: {RESET}"))
    except ValueError:
        print(f"{RED}Invalid input!{RESET}")
        time.sleep(1)
        return mainMenu()

    match x:
        case 1:
            sessionMenu()
        case 2:
            aboutMenu()
        case 0:
            exit(0)
        case _:
            print(f"{RED}Invalid selection!{RESET}")
            time.sleep(1)
            mainMenu()


def sessionMenu():
    clear_screen()
    sOp = [
        f'{GREEN}1-Create New Session{RESET}',
        f'{GREEN}2-History Session{RESET}',
        f'{GREEN}3-Run Scan (Latest Session){RESET}',
        f'{GREEN}4-Show Sessions (Details){RESET}',
        f'{RED}99-Delete All History{RESET}',
        f'{RED}00-Back{RESET}',
    ]
    for op in sOp:
        print(op)
    try:
        op = int(input(f"{BLUE} Enter select option: {RESET}"))
    except ValueError:
        print(f"{RED}Invalid input!{RESET}")
        time.sleep(1)
        return sessionMenu()

    match op:
        case 1:
            create_session()
            time.sleep(1.5)
            sessionMenu()
        case 2:
            history_session()
            input(f"{BLUE}Press Enter to return...{RESET}")
            sessionMenu()
        case 3:
            run_scan()
            input(f"{BLUE}Press Enter to return...{RESET}")
            sessionMenu()
        case 4:
            print_session()
            input(f"{BLUE}Press Enter to return...{RESET}")
            sessionMenu()
        case 99:
            delete_history()
            time.sleep(1)
            sessionMenu()
        case 0:
            mainMenu()
        case _:
            print(f"{RED}Invalid selection!{RESET}")
            time.sleep(1)
            sessionMenu()


def aboutMenu():
    clear_screen()
    print(f"""
{GREEN}Safe Web Vulnerability Checker (Passive){RESET}

- Create a session with target URL
- Run scan to perform HTTPS, Headers, and CORS checks
- View and manage scan history
- All scans are passive and safe (No XSS, SQLi, Brute-force, or Port scanning)
""")
    input(f"{BLUE}Press Enter to return...{RESET}")
    mainMenu()


def run_scan():
    """
    Run all scans (HTTPS, Headers, CORS) for the latest session
    and save results.
    """
    session = get_session()
    if not session:
        print(f"{RED}No session found! Create a session first.{RESET}")
        time.sleep(1.5)
        return

    url = session["url"]
    print(f"{GREEN}Running scan for:{RESET} {url}\n")

    # Fetch response safely
    response = fetch_response(url)
    if not response["status"]:
        print(f"{RED}Failed to fetch URL: {response['error']}{RESET}")
        session["status"] = "failed"
        save_session(session["session_id"], session)
        return

    # HTTPS check
    https_result = check_https_redirect(url)

    # Headers check
    headers_result = check_security_headers(url)

    # CORS check
    cors_result = check_cors(url)

    # Collect results
    results = {
        "https": https_result,
        "headers": headers_result,
        "cors": cors_result
    }

    # Display detailed reports
    format_https_report(https_result)
    format_headers_report(headers_result)
    format_cors_report(cors_result)

    # Calculate overall severity
    overall_severity = calculate_overall_severity(results)
    print_summary(results)
    print(f"\nOverall Severity: {overall_severity}\n")

    # Save results to session
    save_session(session["session_id"], results, status="completed")
    print(f"{GREEN}Scan completed and saved!{RESET}")
