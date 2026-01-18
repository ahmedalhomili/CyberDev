"""
formatter.py
-------------
Formats and displays scan results in a clear CLI report.

This module does NOT perform any scanning.
"""

from utils.color import GREEN, YELLOW, RED, CYAN, MAGENTA, RESET


def _severity_color(severity: str) -> str:
    if severity == "High":
        return RED
    elif severity == "Medium":
        return YELLOW
    return GREEN


def print_section(title: str):
    print(f"\n{CYAN}{'=' * 50}{RESET}")
    print(f"{MAGENTA}{title}{RESET}")
    print(f"{CYAN}{'=' * 50}{RESET}")


def format_https_report(result: dict):
    color = _severity_color(result["severity"])
    print_section("HTTPS CHECK")
    print(f"{color}Severity:{RESET} {result['severity']}")
    print(f"{color}Result:{RESET} {result['message']}")
    print(f"{CYAN}Remediation:{RESET} {result['remediation']}")


def format_headers_report(result: dict):
    print_section("SECURITY HEADERS CHECK")

    if not result["missing"]:
        print(f"{GREEN}All required security headers are present.{RESET}")
        return

    for item in result["missing"]:
        color = _severity_color(item["severity"])
        print(f"{color}- Missing Header:{RESET} {item['header']}")
        print(f"  Severity: {item['severity']}")
        print(f"  Description: {item['description']}")
        print(f"  Remediation: {item['remediation']}\n")


def format_cors_report(result: dict):
    color = _severity_color(result["severity"])
    print_section("CORS CONFIGURATION CHECK")
    print(f"{color}Severity:{RESET} {result['severity']}")
    print(f"{color}Details:{RESET} {result['message']}")

    if result["allow_origin"]:
        print(f"{CYAN}Access-Control-Allow-Origin:{RESET} {result['allow_origin']}")
    if result["allow_credentials"]:
        print(f"{CYAN}Access-Control-Allow-Credentials:{RESET} {result['allow_credentials']}")


def print_summary(results: dict):
    print_section("SCAN SUMMARY")

    for check, result in results.items():
        color = _severity_color(result["severity"])
        print(f"{color}{check.upper()}:{RESET} {result['severity']}")
