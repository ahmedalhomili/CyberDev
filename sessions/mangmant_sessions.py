"""
"""
import json
import time
import os

from utils.color import YELLOW, CYAN, MAGENTA, RESET, GREEN, BLUE, RED
from utils.util import is_valid_url, clear_screen

SESSION_FILE = "sessions/scan_sessions.json"

def _load_sessions():
    if not os.path.exists(SESSION_FILE):
        return []
    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        # Treat invalid/corrupted session file as empty history
        return []


def _save_sessions(data):
    # Ensure the sessions directory exists before writing
    os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)
    with open(SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def _extract_domain(url: str) -> str:
    domain = url.replace("https://", "").replace("http://", "")
    return domain.split("/")[0]


def generate_session_id(url: str) -> str:
    domain = _extract_domain(url)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    return f"{domain}_{timestamp}"

def create_session():
    clear_screen()
    print(f"""
{YELLOW}Please enter a valid URL using one of the following formats:{RESET}
  {CYAN}https://example.com{RESET}
  {CYAN}http://example.com{RESET}
  {CYAN}https://www.example.com/path{RESET}
{MAGENTA}Tip:{RESET} Do not include spaces or unsupported characters.
""")

    url = input(f"{BLUE} Enter URL OR 00-Back {GREEN}>> {RESET}")

    if url == "00":
        from utils.allMenus import sessionMenu
        sessionMenu()
        return

    if not is_valid_url(url):
        print(f"{RED}[✗] Invalid URL format{RESET}")
        time.sleep(1.5)
        return create_session()

    sessions = _load_sessions()

    session = {
        "session_id": generate_session_id(url),
        "domain": _extract_domain(url),
        "url": url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "created",
        "report": {}
    }

    sessions.append(session)
    _save_sessions(sessions)

    print(f"{GREEN}[✓] Session created successfully{RESET}")
    time.sleep(1.5)


def get_session():
    sessions = _load_sessions()
    return sessions[-1] if sessions else None


def save_session(session_id: str, report_data: dict, status="completed"):
    sessions = _load_sessions()

    for s in sessions:
        if s["session_id"] == session_id:
            s["report"] = report_data
            s["status"] = status
            break

    _save_sessions(sessions)


def delete_session():
    clear_screen()
    sessions = _load_sessions()

    if not sessions:
        print(f"{YELLOW}No sessions found.{RESET}")
        time.sleep(1.5)
        return

    for s in sessions:
        print(f"{CYAN}{s['session_id']}{RESET}")

    sid = input(f"{BLUE}Enter Session ID to delete >> {RESET}")

    sessions = [s for s in sessions if s["session_id"] != sid]
    _save_sessions(sessions)

    print(f"{GREEN}[✓] Session deleted{RESET}")
    time.sleep(1.5)


def print_session():
    clear_screen()
    sessions = _load_sessions()

    if not sessions:
        print(f"{YELLOW}No sessions available.{RESET}")
        time.sleep(1.5)
        return

    for s in sessions:
        print(f"""
{CYAN}Session ID:{RESET} {s['session_id']}
{CYAN}Domain:{RESET} {s['domain']}
{CYAN}URL:{RESET} {s['url']}
{CYAN}Time:{RESET} {s['timestamp']}
{CYAN}Status:{RESET} {s['status']}
{'-' * 45}
""")

def get_history():
    return _load_sessions()


def history_session():
    clear_screen()
    sessions = _load_sessions()

    if not sessions:
        print(f"{YELLOW}No scan history found.{RESET}")
        time.sleep(1.5)
        return

    for i, s in enumerate(sessions, start=1):
        print(f"{GREEN}{i}.{RESET} {s['domain']} | {s['timestamp']}")


def delete_history():
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)

    print(f"{GREEN}[✓] All session history deleted{RESET}")
    time.sleep(1.5)

def quit_session():
    print(f"{MAGENTA}Exiting session manager...{RESET}")
    time.sleep(1)
    exit()



def run_scan():
    """
    Run all passive checks against the latest session URL,
    print a formatted report, and save results back to the session store.
    """
    clear_screen()

    sessions = _load_sessions()
    if not sessions:
        print(f"{YELLOW}No sessions found. Please create a session first.{RESET}")
        time.sleep(1.5)
        return

    session = sessions[-1]
    url = session.get("url")

    if not url:
        print(f"{RED}[✗] Latest session has no URL.{RESET}")
        time.sleep(1.5)
        return

    print(f"{BLUE}Scanning Target URL: {CYAN}{url}{RESET}")

    try:
        # Import scanners and formatter lazily to keep startup fast
        from scanner.https_check import check_https_redirect
        from scanner.headers_check import check_security_headers
        from scanner.cors_check import check_cors
        from report.formatter import (
            format_https_report,
            format_headers_report,
            format_cors_report,
            print_summary,
        )

        # Execute passive checks
        https_result = check_https_redirect(url)
        headers_result = check_security_headers(url)
        cors_result = check_cors(url)

        results = {
            "https": https_result,
            "headers": headers_result,
            "cors": cors_result,
        }

        # Display formatted report
        format_https_report(https_result)
        format_headers_report(headers_result)
        format_cors_report(cors_result)
        print_summary(results)

        # Persist results
        save_session(session["session_id"], results, status="completed")
        print(f"\n{GREEN}[✓] Scan completed and saved: {session['session_id']}{RESET}")

    except Exception as e:
        # Best-effort failure handling to keep the app responsive
        err_msg = str(e)
        print(f"{RED}[!] Scan failed: {err_msg}{RESET}")
        try:
            save_session(session["session_id"], {"error": err_msg}, status="failed")
        except Exception:
            # If saving fails, just continue
            pass

    time.sleep(2)
