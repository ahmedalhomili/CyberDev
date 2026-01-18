"""
"""
import json
import time
import random

from utils.color import YELLOW, CYAN, MAGENTA, RESET, GREEN, BLUE
from utils.util import is_valid_url, clear_screen


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
        # Local import to avoid circular import at module load time
        from utils.allMenus import sessionMenu
        sessionMenu()
    elif is_valid_url(url):
        print(f"{GREEN}[✓] Valid URL{RESET}")
    else:
        create_session()


def get_session():
    pass


def save_session():
    pass


def delete_session():
    pass


def print_session():
    pass


def delete_history():
    pass


def get_history():
    pass


def history_session():
    pass


def quit_session():
    pass
