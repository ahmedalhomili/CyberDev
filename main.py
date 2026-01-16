import os

from utils.color import RESET, BLUE, YELLOW, CYAN, MAGENTA, GREEN
from utils.logo import logo
from utils.util import is_valid_url, chack_os


# logo_matrix()


def main():
    os_name = chack_os()
    if os_name == "windows":
        os.system("cls")
    elif os_name == "linux":
        os.system("clear")

    logo(animated=True)
    print(f"""
        {YELLOW}Please enter a valid URL using one of the following formats:{RESET}
          {CYAN}https://example.com{RESET}
          {CYAN}http://example.com{RESET}
          {CYAN}https://www.example.com/path{RESET}
        {MAGENTA}Tip:{RESET} Do not include spaces or unsupported characters.
        """)
    url = input(f"{BLUE} Enter URL: {RESET}")

    if is_valid_url(url):
        print(f"{GREEN}[✓] Valid URL{RESET}")
    else:
        main()


if __name__ == '__main__':
    main()
