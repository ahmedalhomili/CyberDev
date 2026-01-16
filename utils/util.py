import sys


def chack_os():
    if sys.platform.startswith("win"):
        return "windows"
    elif sys.platform.startswith("linux"):
        return "linux"
    return "Unknown"


def is_valid_url(url: str) -> bool:
    if not isinstance(url, str):
        return False

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        return False

    if "." not in url.split("://", 1)[1]:
        return False

    if " " in url:
        return False

    return True
