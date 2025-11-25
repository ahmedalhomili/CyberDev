#!/usr/bin/env python3
"""
Fetch contributors from GitHub REST API and replace the section between
<!-- CONTRIBUTORS_START --> and <!-- CONTRIBUTORS_END --> in README.md

This version calculates each contributor's percentage = commits_by_user / total_commits * 100
"""
import os
import requests
import sys
from html import escape

GITHUB_REPO = os.environ.get("GITHUB_REPOSITORY")  # owner/repo
TOKEN = os.environ.get("GITHUB_TOKEN")
README_PATH = os.environ.get("README_PATH", "README.md")  # <-- the required snippet

# Optionally ignore some logins (comma-separated)
IGNORE_USERS = [u.strip() for u in os.environ.get("IGNORE_USERS", "").split(",") if u.strip()]

if not GITHUB_REPO or not TOKEN:
    print("GITHUB_REPOSITORY and GITHUB_TOKEN must be set")
    sys.exit(1)

owner, repo = GITHUB_REPO.split("/")

session = requests.Session()
session.headers.update({
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "update-contributors-script"
})

def fetch_contributors(owner, repo, per_page=100):
    url = f"https://api.github.com/repos/{owner}/{repo}/contributors"
    params = {"per_page": per_page, "anon": "false"}
    resp = session.get(url, params=params)
    resp.raise_for_status()
    return resp.json()

def fetch_user_name(login):
    url = f"https://api.github.com/users/{login}"
    resp = session.get(url)
    if resp.status_code == 200:
        data = resp.json()
        return data.get("name") or login
    return login

def build_table(contributors):
    # Filter ignored users and compute total contributions
    filtered = [c for c in contributors if c.get("login") not in IGNORE_USERS and c.get("type", "").lower() != "bot"]
    total_commits = sum(c.get("contributions", 0) for c in filtered) or 0

    lines = []
    lines.append("| # | الاسم | حساب GitHub | الكوميِتس | النسبة |")
    lines.append("|---:|---|---|---:|---:|")

    for idx, c in enumerate(filtered, start=1):
        login = c.get("login")
        contributions = c.get("contributions", 0)
        try:
            name = fetch_user_name(login)
        except Exception:
            name = login
        name_md = escape(name)
        login_md = f"[@{login}](https://github.com/{login})"
        if total_commits > 0:
            percent = (contributions / total_commits) * 100
            percent_str = f"{percent:0.1f}%"
        else:
            percent_str = "0.0%"
        lines.append(f"| {idx} | {name_md} | {login_md} | {contributions} | {percent_str} |")

    if not filtered:
        lines.append("| - | - | - | 0 | 0.0% |")

    return "\n".join(lines)

def replace_section(readme_text, new_section, start_marker="<!-- CONTRIBUTORS_START -->", end_marker="<!-- CONTRIBUTORS_END -->"):
    if start_marker in readme_text and end_marker in readme_text:
        before, rest = readme_text.split(start_marker, 1)
        _, after = rest.split(end_marker, 1)
        return before + start_marker + "\n\n" + new_section + "\n\n" + end_marker + after
    else:
        return readme_text.rstrip() + "\n\n" + start_marker + "\n\n" + new_section + "\n\n" + end_marker + "\n"

def main():
    try:
        contributors = fetch_contributors(owner, repo)
    except Exception as e:
        print("Error fetching contributors:", e)
        sys.exit(1)

    table_md = build_table(contributors)

    try:
        with open(README_PATH, "r", encoding="utf-8") as f:
            readme = f.read()
    except FileNotFoundError:
        print(f"{README_PATH} not found. Creating new README.")
        readme = "# Contributors\n\n"

    new_readme = replace_section(readme, table_md)
    if new_readme != readme:
        with open(README_PATH, "w", encoding="utf-8") as f:
            f.write(new_readme)
        print("README updated with contributors table.")
    else:
        print("No changes detected.")

if __name__ == "__main__":
    main()
