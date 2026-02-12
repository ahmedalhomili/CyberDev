"""
Directory and File Fuzzer.
Checks for sensitive hidden files and directories.
"""
import requests
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
from models import Finding
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class DirectoryFuzzer:
    """Fuzzer for discovering hidden paths."""

    def __init__(self):
        self.requester = Requester()
        self.common_paths = [
            # ════════════ ملفات البيئة والإعدادات ════════════
    ".env",
    ".env.local",
    ".env.production",
    ".env.backup",
    ".env.old",
    ".env.dev",
    ".env.sample",
    "env",
    "config.php",
    "config.php.bak",
    "config.php.old",
    "config.php~",
    "config.php.save",
    "config.inc.php",
    "configuration.php",
    "settings.php",
    "database.php",
    "db.php",
    "wp-config.php",
    "wp-config.php.bak",
    "wp-config.old",
    "config.yml",
    "config.yaml",
    "config.json",
    "config.xml",
    "app.config",
    "web.config",
    "application.properties",
    "settings.json",
    "local_settings.py",
    
    # ════════════ ملفات النسخ الاحتياطي ════════════
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "backup.tar",
    "backup.rar",
    "database.sql",
    "db.sql",
    "dump.sql",
    "site-backup.zip",
    "www.zip",
    "wwwroot.zip",
    "website.zip",
    "web.zip",
    "public_html.zip",
    "backup.old",
    "site.tar.gz",
    "old.tar.gz",
    
    # ════════════ Git و Version Control ════════════
    ".git/",
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".git/logs/HEAD",
    ".gitignore",
    ".git/refs/heads/master",
    ".git/refs/heads/main",
    ".svn/",
    ".svn/entries",
    ".hg/",
    ".bzr/",
    
    # ════════════ ملفات الويب الحساسة ════════════
    "robots.txt",
    "sitemap.xml",
    "sitemap_index.xml",
    ".htaccess",
    ".htpasswd",
    ".user.ini",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "security.txt",
    ".well-known/security.txt",
    "humans.txt",
    
    # ════════════ صفحات الإدارة ════════════
    "admin/",
    "admin.php",
    "administrator/",
    "wp-admin/",
    "phpmyadmin/",
    "pma/",
    "cpanel/",
    "webmail/",
    "login.php",
    "admin-console/",
    "manager/",
    "controlpanel/",
    "dashboard/",
    
    # ════════════ ملفات PHP المعلوماتية ════════════
    "phpinfo.php",
    "info.php",
    "test.php",
    "php.php",
    "pi.php",
    "phpversion.php",
    
    # ════════════ Server Status والمعلومات ════════════
    "server-status",
    "server-info",
    "status",
    "readme.html",
    "readme.txt",
    "README.md",
    "CHANGELOG",
    "CHANGELOG.md",
    "TODO",
    "LICENSE",
    
    # ════════════ ملفات الأنظمة الحرجة (Linux/Unix) ════════════
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/issue",
    "/etc/group",
    "/proc/self/environ",
    "/proc/version",
    "/proc/cmdline",
    
    # ════════════ ملفات Windows الحرجة ════════════
    "C:/Windows/win.ini",
    "C:/Windows/system.ini",
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/boot.ini",
    "C:/inetpub/wwwroot/web.config",
    "../../../Windows/win.ini",
    "..\\..\\..\\Windows\\win.ini",
    
    # ════════════ ملفات الـ Logs ════════════
    "error.log",
    "error_log",
    "access.log",
    "access_log",
    "debug.log",
    "application.log",
    "app.log",
    "logs/error.log",
    "logs/access.log",
    
    # ════════════ ملفات Source Code ════════════
    "index.php~",
    "index.php.bak",
    "index.php.old",
    "index.php.save",
    "index.php.swp",
    ".index.php.swp",
    "index.php.txt",
    "login.php.bak",
    "config.php.dist",
    
    # ════════════ Kubernetes والـ Cloud ════════════
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    ".aws/credentials",
    ".aws/config",
    
    # ════════════ Docker ════════════
    ".dockerignore",
    "Dockerfile",
    "docker-compose.yml",
    ".docker/config.json",
    
    # ════════════ SSH Keys ════════════
    ".ssh/id_rsa",
    ".ssh/id_dsa",
    ".ssh/id_ecdsa",
    ".ssh/id_ed25519",
    ".ssh/authorized_keys",
    ".ssh/known_hosts",
    "~/.ssh/id_rsa",
    
    # ════════════ ملفات Package Managers ════════════
    "package.json",
    "package-lock.json",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
    "requirements.txt",
    "yarn.lock",
    "pom.xml",
    
    # ════════════ ملفات IDE والمحررات ════════════
    ".vscode/",
    ".idea/",
    ".DS_Store",
    "Thumbs.db",
    ".project",
    ".classpath",
    "nbproject/",
    
    # ════════════ ملفات التاريخ والـ Shell ════════════
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    ".mysql_history",
    
    # ════════════ APIs والـ Swagger ════════════
    "swagger.json",
    "swagger.yaml",
    "swagger-ui.html",
    "api-docs",
    "api/swagger.json",
    "graphql",
    "/graphql",
    
    # ════════════ Frameworks المختلفة ════════════
    # Laravel
    "storage/logs/laravel.log",
    ".env.example",
    "artisan",
    
    # Django
    "settings.py",
    "local_settings.py",
    "manage.py",
    
    # Ruby on Rails
    "config/database.yml",
    "config/secrets.yml",
    
    # Node.js
    ".npmrc",
    ".env.local",
    
    # ════════════ ملفات الـ Backups الإضافية ════════════
    "Copy of config.php",
    "Copy (2) of config.php",
    "config copy.php",
    "config.php.1",
    "config.php.~1~",
    
    # ════════════ Common Sensitive Files ════════════
    "passwords.txt",
    "password.txt",
    "users.txt",
    "credentials.txt",
    "token.txt",
    "api_keys.txt",
    "secrets.txt",
    
    # ════════════ Test Files ════════════
    "test/",
    "tests/",
    "testing/",
    "test.html",
    "demo/",
    "example/",
    "temp/",
    "tmp/",
    
    # ════════════ Upload Directories ════════════
    "uploads/",
    "upload/",
    "files/",
    "media/",
    "images/shell.php",
    
    # ════════════ Debug والتطوير ════════════
    "debug.php",
    "debug.log",
    "error.txt",
    "trace.axd",
    "elmah.axd",
        ]

    def scan(self, base_url: str, max_workers: int = 15) -> List[Finding]:
        """
        Scan a URL for hidden files using concurrent requests.
        """
        findings = []
        if not base_url.endswith('/'):
            base_url += '/'

        def _check_path(path: str) -> Optional[Finding]:
            target_url = base_url + path
            try:
                response = self.requester.get(target_url, timeout=4)

                if response.status_code != 200:
                    return None

                content = response.text.lower()
                severity = "MEDIUM"
                description = f"Found sensitive file/directory: {path}"
                is_valid = False

                # Content-based verification
                if ".env" in path and "DB_HOST=" in response.text:
                    is_valid = True
                elif "config" in path and ("<?php" in response.text or "define(" in response.text):
                    if "password" in content or "secret" in content:
                        is_valid = True
                elif ".git" in path and "ref: refs/" in response.text:
                    is_valid = True
                elif "phpinfo" in path and "php version" in content:
                    is_valid = True
                elif "server-status" in path and "apache status" in content:
                    is_valid = True
                elif "backup" in path and (len(response.content) > 100):
                    is_valid = True
                elif "admin" in path and ("login" in content or "admin" in content or "user" in content):
                    is_valid = True
                    severity = "INFO"
                    description = f"Admin entry point found: {path}"
                elif "swagger" in path and ("swagger" in content or "openapi" in content):
                    is_valid = True
                elif ".htpasswd" in path and ":" in response.text:
                    is_valid = True
                elif "passwd" in path and "root:" in content:
                    is_valid = True
                elif "win.ini" in path and "[extensions]" in content:
                    is_valid = True
                elif ".ssh" in path and ("ssh-" in content or "BEGIN" in content):
                    is_valid = True
                elif ".aws" in path and ("aws_access" in content or "aws_secret" in content):
                    is_valid = True
                elif "docker" in path and ("FROM " in response.text or "image:" in content):
                    is_valid = True
                elif (path.endswith(".log") or path.endswith("_log") or path in ("error.log", "error_log", "access.log", "access_log", "debug.log", "application.log", "app.log", "logs/error.log", "logs/access.log")) and len(response.content) > 200:
                    is_valid = True
                    severity = "LOW"
                    description = f"Log file accessible: {path}"
                elif ".sql" in path and ("INSERT" in response.text or "CREATE" in response.text):
                    is_valid = True
                elif "package.json" in path and "dependencies" in content:
                    is_valid = True
                    severity = "LOW"
                    description = f"Package manifest exposed: {path}"

                if is_valid:
                    # Upgrade severity for critical files
                    if ".env" in path or ("config" in path and severity != "INFO") or "backup" in path:
                        severity = "HIGH"
                        description += " (Contains potentially sensitive configuration or backup data)"
                    if ".git" in path:
                        severity = "HIGH"
                        description += " (Source code repository exposed)"
                    if ".ssh" in path or ".aws" in path or "passwd" in path:
                        severity = "CRITICAL"
                        description += " (Critical credential/key exposure)"

                    return Finding(
                        title="Sensitive File/Directory Discovered",
                        severity=severity,
                        description=description,
                        location=target_url,
                        recommendation="Restrict access to sensitive administrative or configuration files. Remove backup files from the web root.",
                        cwe_reference="CWE-538",
                        confidence="High"
                    )

            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_check_path, path): path for path in self.common_paths}
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    findings.append(result)

        return findings
