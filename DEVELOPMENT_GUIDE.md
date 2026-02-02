# 🚀 دليل التطوير - Development Guide

دليل شامل للمطورين الذين يريدون المساهمة في تطوير وتحسين **CyberDev Security Scanner**.

---

## 📋 جدول المحتويات

1. [الإعداد الأولي](#-الإعداد-الأولي)
2. [هيكل الكود](#-هيكل-الكود)
3. [إضافة فاحص ثغرة جديد](#-إضافة-فاحص-ثغرة-جديد)
4. [معايير البرمجة](#-معايير-البرمجة)
5. [الاختبار](#-الاختبار)
6. [Debugging](#-debugging)
7. [المساهمة](#-المساهمة)

---

## 🛠️ الإعداد الأولي

### 1. تثبيت بيئة التطوير

```bash
# استنساخ المشروع
git clone https://github.com/ahmedalhomili/CyberDev.git
cd CyberDev

# إنشاء بيئة افتراضية (Virtual Environment)
python -m venv venv

# تفعيل البيئة الافتراضية
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# تثبيت المكتبات
pip install -r requirements.txt

# تثبيت أدوات التطوير (اختياري)
pip install pylint black pytest
```

### 2. التحقق من التثبيت

```bash
# تشغيل الماسح
python main.py

# يجب أن يظهر الشعار والقائمة التفاعلية
```

---

## 📐 هيكل الكود

### البنية الأساسية

```
CyberDev/
├── main.py                 # نقطة الدخول
├── cli.py                  # واجهة CLI
├── config.py               # الإعدادات
├── models.py               # Data models
│
├── scanner/
│   ├── core/               # المحرك الأساسي
│   │   ├── scanner_orchestrator.py  # ⭐ المنسق الرئيسي
│   │   ├── http_handler.py
│   │   └── requester.py
│   │
│   ├── recon/              # الاستطلاع
│   │   ├── recon_analyzer.py  # ⭐ محلل الاستطلاع
│   │   ├── link_crawler.py
│   │   └── ...
│   │
│   └── vulnerabilities/    # فاحصات الثغرات
│       ├── vuln_sqli.py
│       ├── vuln_xss.py
│       └── ...
│
├── report/                 # نظام التقارير
│   └── report_formatter.py
│
├── sessions/               # حفظ الجلسات
├── ui/                     # واجهة المستخدم
└── utils/                  # أدوات مساعدة
```

### الملفات الرئيسية

#### 1. **scanner_orchestrator.py** - المنسق الرئيسي
```python
class SecurityScanner:
    """
    المنسق الرئيسي لكل مراحل الفحص.
    """
    
    def scan(self, url: str) -> ScanResult:
        """
        المسار الكامل للفحص:
        1. Reconnaissance
        2. URL Discovery (Crawler)
        3. Vulnerability Scanning
        4. Results Aggregation
        """
```

#### 2. **recon_analyzer.py** - محلل الاستطلاع
```python
class ReconAnalyzer:
    """
    جمع معلومات استخباراتية عن الهدف.
    """
    
    def analyze(self, url: str) -> ReconData:
        """
        ينفذ:
        - Whois lookup
        - DNS analysis
        - Port scanning
        - Tech detection
        - Geolocation
        - Hosting detection
        """
```

#### 3. **models.py** - نماذج البيانات
```python
@dataclass
class Finding:
    """ثغرة واحدة"""
    title: str
    severity: str  # CRITICAL|HIGH|MEDIUM|LOW|INFO
    description: str
    location: str
    recommendation: str
    cwe_reference: Optional[str]
    confidence: str  # High|Medium|Low

@dataclass
class ScanResult:
    """نتيجة الفحص الكاملة"""
    session_id: str
    target_url: str
    timestamp: datetime
    findings: List[Finding]
    recon: ReconData
```

---

## ➕ إضافة فاحص ثغرة جديد

### مثال كامل: إضافة "Command Injection Scanner"

#### الخطوة 1: إنشاء الملف

```bash
# أنشئ الملف
touch scanner/vulnerabilities/vuln_command_injection.py
```

#### الخطوة 2: كتابة الكود

```python
"""
Command Injection Vulnerability Scanner

Description: Detects OS command injection vulnerabilities
Severity: CRITICAL
References: CWE-78 (OS Command Injection)
"""

from models import Finding
import logging
import requests
import time

logger = logging.getLogger(__name__)

class CommandInjectionScanner:
    """
    Scanner for OS Command Injection vulnerabilities.
    
    Tests common injection patterns:
    - Linux: ; whoami, | ls, && cat
    - Windows: & dir, && type
    - Time-based: ; sleep 5
    """
    
    def __init__(self):
        """Initialize scanner with payloads."""
        self.payloads = {
            'linux': [
                '; whoami',
                '| ls -la',
                '&& cat /etc/passwd',
                '`whoami`',
                '$(whoami)'
            ],
            'windows': [
                '& dir',
                '&& type C:\\Windows\\win.ini',
                '| dir'
            ],
            'time_based': [
                '; sleep 5',
                '& timeout 5',
                '| sleep 5'
            ]
        }
        
        self.timeout = 15  # seconds
    
    def scan(self, url: str, headers: dict = None) -> list:
        """
        Scan for command injection vulnerabilities.
        
        Args:
            url: Target URL with parameters (e.g., /exec?cmd=ping)
            headers: Optional HTTP headers
        
        Returns:
            List of Finding objects
        """
        findings = []
        
        if '?' not in url or '=' not in url:
            logger.debug(f"[CMD_INJ] No parameters in URL: {url}")
            return findings
        
        logger.info(f"[CMD_INJ] Scanning {url}...")
        
        # Test 1: Linux payloads
        if self._test_linux_injection(url):
            findings.append(Finding(
                title="OS Command Injection (Linux)",
                severity="CRITICAL",
                description="Command injection vulnerability detected. Server executed injected Linux commands.",
                location=url,
                recommendation="Never pass user input directly to system commands. Use allowlists and sanitize input.",
                cwe_reference="CWE-78",
                confidence="High"
            ))
        
        # Test 2: Windows payloads
        if self._test_windows_injection(url):
            findings.append(Finding(
                title="OS Command Injection (Windows)",
                severity="CRITICAL",
                description="Command injection vulnerability detected. Server executed injected Windows commands.",
                location=url,
                recommendation="Never pass user input directly to system commands. Use allowlists and sanitize input.",
                cwe_reference="CWE-78",
                confidence="High"
            ))
        
        # Test 3: Time-based blind
        if self._test_time_based_injection(url):
            findings.append(Finding(
                title="Blind Command Injection (Time-based)",
                severity="CRITICAL",
                description="Time-based command injection confirmed through delayed response.",
                location=url,
                recommendation="Never pass user input directly to system commands.",
                cwe_reference="CWE-78",
                confidence="High"
            ))
        
        if findings:
            logger.warning(f"[CMD_INJ] ⚠️  Found {len(findings)} command injection vulnerabilities")
        else:
            logger.info(f"[CMD_INJ] ✓ No command injection detected")
        
        return findings
    
    def _test_linux_injection(self, url: str) -> bool:
        """Test Linux command injection payloads."""
        try:
            # Get baseline response
            baseline_resp = requests.get(url, timeout=5)
            
            # Test payloads
            for payload in self.payloads['linux']:
                # Inject payload in parameter
                test_url = url + payload
                
                resp = requests.get(test_url, timeout=self.timeout)
                
                # Check for command output indicators
                indicators = ['root:', 'uid=', 'gid=', '/home/', '/bin/']
                if any(ind in resp.text.lower() for ind in indicators):
                    logger.info(f"[CMD_INJ] ✓ Linux payload triggered: {payload}")
                    return True
        
        except Exception as e:
            logger.debug(f"[CMD_INJ] Linux test error: {e}")
        
        return False
    
    def _test_windows_injection(self, url: str) -> bool:
        """Test Windows command injection payloads."""
        try:
            for payload in self.payloads['windows']:
                test_url = url + payload
                resp = requests.get(test_url, timeout=self.timeout)
                
                # Check for Windows-specific indicators
                indicators = ['volume serial number', 'directory of', 'windows', 'c:\\']
                if any(ind in resp.text.lower() for ind in indicators):
                    logger.info(f"[CMD_INJ] ✓ Windows payload triggered: {payload}")
                    return True
        
        except Exception as e:
            logger.debug(f"[CMD_INJ] Windows test error: {e}")
        
        return False
    
    def _test_time_based_injection(self, url: str) -> bool:
        """Test time-based blind command injection."""
        try:
            # Measure baseline response time
            start = time.time()
            requests.get(url, timeout=self.timeout)
            baseline = time.time() - start
            
            # Test with sleep payload
            for payload in self.payloads['time_based']:
                start = time.time()
                test_url = url + payload
                requests.get(test_url, timeout=self.timeout)
                delay = time.time() - start
                
                # If response delayed by ~5 seconds
                if delay - baseline > 4:
                    logger.info(f"[CMD_INJ] ✓ Time-based payload confirmed: {payload}")
                    return True
        
        except requests.Timeout:
            # Timeout might indicate successful sleep command
            return True
        except Exception as e:
            logger.debug(f"[CMD_INJ] Time-based test error: {e}")
        
        return False
```

#### الخطوة 3: إضافته للـ Orchestrator

```python
# في scanner/core/scanner_orchestrator.py

# 1. أضف الـ import
from scanner.vulnerabilities.vuln_command_injection import CommandInjectionScanner

# 2. في دالة scan()، أضف:
logger.info("[✓] Scanning for Command Injection...")
findings.extend(CommandInjectionScanner().scan(url))
```

#### الخطوة 4: الاختبار

```bash
python main.py
# أدخل: http://example.com/exec.php?cmd=test
```

---

## 📏 معايير البرمجة (Coding Standards)

### 1. Python Style Guide (PEP 8)

```python
# ✅ جيد:
def scan_for_vulnerabilities(url: str, timeout: int = 10) -> list:
    """
    Scan URL for security vulnerabilities.
    
    Args:
        url: Target URL
        timeout: Request timeout in seconds
    
    Returns:
        List of Finding objects
    """
    findings = []
    # Implementation
    return findings

# ❌ سيء:
def ScanForVuln(url,timeout=10):
    f=[]
    return f
```

### 2. Docstrings

```python
class MyScanner:
    """
    Brief description of what this scanner does.
    
    Attributes:
        payloads: List of test payloads
        timeout: Request timeout
    
    Example:
        >>> scanner = MyScanner()
        >>> findings = scanner.scan("http://example.com")
    """
    
    def scan(self, url: str) -> list:
        """
        Main scanning method.
        
        Args:
            url: Target URL to scan
        
        Returns:
            List[Finding]: Detected vulnerabilities
        
        Raises:
            requests.Timeout: If request times out
        """
```

### 3. Logging

```python
import logging

logger = logging.getLogger(__name__)

# ✅ استخدم logging بدلاً من print:
logger.info("[SCANNER] Starting scan...")
logger.warning("[SCANNER] ⚠️  Potential vulnerability detected")
logger.error("[SCANNER] ❌ Scan failed")
logger.debug("[SCANNER] Debug info: payload=test")

# ❌ لا تستخدم:
print("Starting scan...")
```

### 4. Error Handling

```python
# ✅ جيد:
try:
    response = requests.get(url, timeout=10)
    response.raise_for_status()
except requests.Timeout:
    logger.error(f"Timeout connecting to {url}")
except requests.RequestException as e:
    logger.error(f"Request error: {e}")
except Exception as e:
    logger.error(f"Unexpected error: {e}")

# ❌ سيء:
try:
    response = requests.get(url)
except:
    pass
```

### 5. Type Hints

```python
from typing import List, Dict, Optional

def scan(url: str, headers: Optional[Dict[str, str]] = None) -> List[Finding]:
    """Type hints make code more readable."""
    findings: List[Finding] = []
    return findings
```

---

## 🧪 الاختبار (Testing)

### 1. مواقع تجريبية آمنة

```bash
# SQLi:
http://testphp.vulnweb.com/artists.php?artist=1

# XSS:
http://testphp.vulnweb.com/search.php?test=

# OWASP Juice Shop (شامل):
https://juice-shop.herokuapp.com
```

### 2. اختبار يدوي

```bash
# اختبر الفاحص الجديد:
python -c "
from scanner.vulnerabilities.vuln_my_check import MyScanner
scanner = MyScanner()
findings = scanner.scan('http://testphp.vulnweb.com')
print(f'Found {len(findings)} vulnerabilities')
"
```

### 3. Unit Tests (المستقبل)

```python
# tests/test_sqli_scanner.py
import pytest
from scanner.vulnerabilities.vuln_sqli import SQLiScanner

def test_sqli_detection():
    scanner = SQLiScanner()
    findings = scanner.scan("http://testphp.vulnweb.com/artists.php?artist=1")
    assert len(findings) > 0
    assert findings[0].severity == "HIGH"
```

---

## 🐛 Debugging

### 1. تفعيل Debug Mode

```python
# في main.py:
import logging

logging.basicConfig(
    level=logging.DEBUG,  # بدلاً من INFO
    format='%(levelname)s: %(message)s'
)
```

### 2. استخدام Python Debugger

```python
# أضف breakpoint في الكود:
import pdb; pdb.set_trace()

# أو استخدم:
breakpoint()  # Python 3.7+
```

### 3. فحص النتائج

```bash
# عرض آخر ملف جلسة:
python -c "
import json
import glob

files = glob.glob('sessions/scan_sessions/*.json')
latest = max(files, key=lambda x: x)

with open(latest) as f:
    data = json.load(f)
    print(json.dumps(data, indent=2))
"
```

---

## 🤝 المساهمة (Contributing)

### 1. Fork & Clone

```bash
# Fork المشروع على GitHub
# ثم:
git clone https://github.com/YOUR_USERNAME/CyberDev.git
cd CyberDev
git checkout -b feature/my-new-scanner
```

### 2. تطوير الميزة

```bash
# أنشئ الملف
# اكتب الكود
# اختبره
```

### 3. Commit & Push

```bash
git add scanner/vulnerabilities/vuln_my_scanner.py
git commit -m "Add new vulnerability scanner for [name]"
git push origin feature/my-new-scanner
```

### 4. Pull Request

```
افتح Pull Request على GitHub مع:
- شرح الميزة الجديدة
- أمثلة على الاستخدام
- نتائج الاختبار
```

---

## 📚 الموارد الإضافية

### للتعلم:
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Academy](https://portswigger.net/web-security)
- [HackerOne Reports](https://hackerone.com/hacktivity)

### للأدوات:
- [requests Documentation](https://requests.readthedocs.io/)
- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)
- [Python Logging](https://docs.python.org/3/library/logging.html)

---

## ✅ Checklist للمطورين

قبل إرسال Pull Request، تأكد من:

- [ ] الكود يتبع PEP 8
- [ ] جميع الدوال لها docstrings
- [ ] استخدام logging بدلاً من print
- [ ] استخدام type hints
- [ ] معالجة الأخطاء بشكل صحيح
- [ ] الاختبار على موقع تجريبي
- [ ] لا توجد أخطاء syntax
- [ ] الكود لا يحتوي على exploits خطيرة

---

**🎉 شكراً على مساهمتك في تطوير CyberDev!**
