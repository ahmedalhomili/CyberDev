# 🐛 Vulnerabilities - فاحصات الثغرات الأمنية

هذا المجلد يحتوي على **18+ فاحص متخصص** لكشف الثغرات الأمنية الشائعة في تطبيقات الويب.

---

## 📋 الفاحصات المتوفرة

### 🔴 CRITICAL & HIGH Severity

#### 1. **SQL Injection** (`vuln_sqli.py`)
- **الوصف:** حقن أوامر SQL في قاعدة البيانات
- **التقنيات:**
  - Boolean-based Blind SQLi (TRUE vs FALSE responses)
  - Time-based Blind SQLi (SLEEP/WAITFOR DELAY)
- **Payloads:** `' OR '1'='1`, `' AND SLEEP(5)--`, `1' WAITFOR DELAY '0:0:5'--`
- **CWE:** CWE-89

#### 2. **Cross-Site Scripting (XSS)** (`vuln_xss.py`)
- **الوصف:** حقن JavaScript في صفحات الويب
- **الأنواع:**
  - Reflected XSS
  - Stored XSS (إذا أمكن)
- **Payloads:** `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
- **CWE:** CWE-79

#### 3. **Remote Code Execution (RCE)** (`vuln_rce.py`)
- **الوصف:** تنفيذ أوامر على الخادم
- **Payloads:** `; whoami`, `| ls -la`, `&& dir`
- **CWE:** CWE-78

#### 4. **JWT Security** (`vuln_jwt.py`)
- **الوصف:** ثغرات في JSON Web Tokens
- **الفحوصات:**
  - None algorithm attack
  - Weak secret keys
  - Algorithm confusion (RS256 → HS256)
- **CWE:** CWE-347

---

### 🟠 MEDIUM Severity

#### 5. **Local File Inclusion (LFI)** (`vuln_lfi.py`)
- **الوصف:** قراءة ملفات النظام
- **Payloads:** `../../etc/passwd`, `..\\..\\windows\\win.ini`
- **CWE:** CWE-98

#### 6. **Server-Side Request Forgery (SSRF)** (`vuln_ssrf.py`)
- **الوصف:** إجبار الخادم على إرسال طلبات
- **Targets:** `http://localhost`, `http://169.254.169.254/` (AWS metadata)
- **CWE:** CWE-918

#### 7. **XML External Entity (XXE)** (`vuln_xxe.py`)
- **الوصف:** استغلال XML parsers
- **Attacks:**
  - File disclosure
  - SSRF via XXE
- **CWE:** CWE-611

#### 8. **Server-Side Template Injection (SSTI)** (`vuln_ssti.py`)
- **الوصف:** حقن في Template Engines
- **Payloads:** `{{7*7}}`, `{7*7}`, `<%= 7*7 %>`
- **CWE:** CWE-1336

#### 9. **Open Redirect** (`vuln_redirect.py`)
- **الوصف:** إعادة توجيه لمواقع خبيثة
- **Payloads:** `?redirect=https://evil.com`
- **CWE:** CWE-601

#### 10. **Host Header Injection** (`vuln_host_header.py`)
- **الوصف:** تلاعب في Host header
- **Risks:** Password reset poisoning, Cache poisoning
- **CWE:** CWE-644

#### 11. **Cache Poisoning** (`vuln_cache_poisoning.py`)
- **الوصف:** تسميم الذاكرة المؤقتة
- **Techniques:** X-Forwarded-Host, X-Original-URL
- **CWE:** CWE-524

#### 12. **API Security** (`vuln_api_security.py`)
- **الوصف:** ثغرات APIs
- **Checks:**
  - BOLA/IDOR (Broken Object Level Authorization)
  - Mass Assignment
  - Excessive Data Exposure
- **CWE:** CWE-639

#### 13. **Authentication Flaws** (`vuln_auth_workflow.py`)
- **الوصف:** ثغرات المصادقة
- **Checks:**
  - Username enumeration
  - Weak password policies
  - Session fixation
- **CWE:** CWE-287

#### 14. **GraphQL Security** (`vuln_graphql.py`)
- **الوصف:** ثغرات GraphQL
- **Attacks:**
  - Introspection queries
  - Depth-based attacks
- **CWE:** CWE-209

---

### 🟢 LOW Severity & INFO

#### 15. **Rate Limiting** (`vuln_rate_limit.py`)
- **الوصف:** فحص حدود المعدل
- **Test:** إرسال 15 طلب سريع
- **CWE:** CWE-307

#### 16. **File Upload Security** (`vuln_upload_checks.py`)
- **الوصف:** أمان رفع الملفات
- **Checks:**
  - PHP file upload
  - Extension validation
- **CWE:** CWE-434

#### 17. **Insecure Deserialization** (`vuln_deserialization.py`)
- **الوصف:** فك تسلسل غير آمن
- **Languages:** PHP, Java, Python
- **CWE:** CWE-502

#### 18. **WebSocket Security** (`vuln_websocket.py`)
- **الوصف:** أمان WebSocket
- **Checks:**
  - Origin validation
  - Authentication
- **CWE:** CWE-346

---

## 🔄 الهيكل الموحد لكل فاحص

جميع الفاحصات تتبع نفس الهيكل:

```python
"""
Scanner for [Vulnerability Name]

Description: Brief explanation
Severity: HIGH/MEDIUM/LOW
References: CWE-XXX, OWASP
"""

from models import Finding
import logging

logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    """
    Scanner for detecting [specific vulnerability].
    
    Attributes:
        payloads: List of test payloads
        timeout: Request timeout
    """
    
    def __init__(self):
        """Initialize scanner with payloads."""
        self.payloads = [...]
    
    def scan(self, url: str, headers: dict = None) -> list:
        """
        Main scanning method.
        
        Args:
            url: Target URL to scan
            headers: Optional HTTP headers
        
        Returns:
            List[Finding]: Detected vulnerabilities
        """
        findings = []
        
        try:
            # 1. Test payloads
            # 2. Analyze responses
            # 3. Create Finding objects
            
        except Exception as e:
            logger.error(f"Error: {e}")
        
        return findings
    
    def _helper_method(self):
        """Private helper methods."""
        pass
```

---

## 📖 مثال كامل: SQL Injection Scanner

```python
from models import Finding
import logging
import requests
import time

logger = logging.getLogger(__name__)

class SQLiScanner:
    """Scanner for SQL Injection vulnerabilities."""
    
    def __init__(self):
        self.boolean_payloads = [
            ("' OR '1'='1", "' OR '1'='2"),  # TRUE, FALSE
            ("1' OR 1=1--", "1' OR 1=2--")
        ]
        self.time_payloads = [
            "' AND SLEEP(5)--",
            "1' WAITFOR DELAY '0:0:5'--"
        ]
    
    def scan(self, url: str, headers=None) -> list:
        """Scan for SQL Injection."""
        findings = []
        
        # Test Boolean-based
        if self._test_boolean_based(url):
            findings.append(Finding(
                title="SQL Injection (Boolean-based)",
                severity="HIGH",
                description="Boolean-based blind SQL injection detected",
                location=url,
                recommendation="Use parameterized queries",
                cwe_reference="CWE-89"
            ))
        
        # Test Time-based
        if self._test_time_based(url):
            findings.append(Finding(
                title="SQL Injection (Time-based)",
                severity="HIGH",
                description="Time-based blind SQL injection confirmed",
                location=url,
                recommendation="Use parameterized queries",
                cwe_reference="CWE-89"
            ))
        
        return findings
    
    def _test_boolean_based(self, url: str) -> bool:
        """Test Boolean-based blind SQLi."""
        try:
            # Send TRUE payload
            resp_true = requests.get(url.replace("=1", "=' OR '1'='1--"))
            
            # Send FALSE payload
            resp_false = requests.get(url.replace("=1", "=' OR '1'='2--"))
            
            # Compare response lengths
            if len(resp_true.text) != len(resp_false.text):
                return True
                
        except Exception as e:
            logger.debug(f"Boolean test error: {e}")
        
        return False
    
    def _test_time_based(self, url: str) -> bool:
        """Test Time-based blind SQLi."""
        try:
            # Measure baseline
            start = time.time()
            requests.get(url, timeout=10)
            baseline = time.time() - start
            
            # Send SLEEP payload
            start = time.time()
            requests.get(url + "' AND SLEEP(5)--", timeout=15)
            delay = time.time() - start
            
            # If response delayed by ~5 seconds
            if delay - baseline > 4:
                return True
                
        except Exception as e:
            logger.debug(f"Time test error: {e}")
        
        return False
```

---

## 🎯 كيفية الاستخدام

### استخدام فاحص واحد:
```python
from scanner.vulnerabilities.vuln_sqli import SQLiScanner

scanner = SQLiScanner()
findings = scanner.scan("http://example.com/page?id=1")

for f in findings:
    print(f"{f.severity}: {f.title}")
```

### استخدام جميع الفاحصات (عبر Orchestrator):
```python
from scanner.core.scanner_orchestrator import SecurityScanner

scanner = SecurityScanner()
result = scanner.scan("http://example.com")

# الفاحصات تُنفذ تلقائياً
print(result.summary())
```

---

## 🛠️ إضافة فاحص جديد

### خطوات سريعة:

1. **أنشئ ملف:**
```bash
touch scanner/vulnerabilities/vuln_my_new_check.py
```

2. **اكتب الكود:**
```python
from models import Finding
import logging

logger = logging.getLogger(__name__)

class MyNewScanner:
    def scan(self, url, headers=None):
        findings = []
        # Your logic here
        return findings
```

3. **أضفه للـ Orchestrator:**
```python
# في scanner/core/scanner_orchestrator.py
from scanner.vulnerabilities.vuln_my_new_check import MyNewScanner

# في دالة scan():
findings.extend(MyNewScanner().scan(url))
```

---

## 📊 Severity Levels

| Level | Icon | الاستخدام |
|-------|------|----------|
| **CRITICAL** | 🔴 | RCE, SQLi with full access |
| **HIGH** | 🔴 | SQLi, XSS, JWT bypass |
| **MEDIUM** | 🟠 | LFI, SSRF, XXE, SSTI |
| **LOW** | 🟢 | Rate limiting, Upload checks |
| **INFO** | 🔵 | Configuration issues |

---

## ⚡ Best Practices

### ✅ افعل:
- استخدم payloads آمنة (لا تُحدث ضرر)
- أضف timeout للطلبات
- log الأخطاء بشكل صحيح
- استخدم try-except blocks
- أضف docstrings واضحة

### ❌ لا تفعل:
- لا تستخدم payloads خطيرة (DROP TABLE, etc.)
- لا ترسل آلاف الطلبات
- لا تفحص مواقع دون إذن
- لا تكتب exploits حقيقية

---

## 🧪 الاختبار

### مواقع تجريبية آمنة:
```bash
# SQLi:
http://testphp.vulnweb.com/artists.php?artist=1

# XSS:
http://testphp.vulnweb.com/search.php?test=

# LFI:
http://demo.testfire.net/?page=
```

---

## 📚 مراجع

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [PortSwigger Academy](https://portswigger.net/web-security)

---

## 📞 للمزيد

- **شرح الهيكل:** [../ARCHITECTURE.md](../ARCHITECTURE.md)
- **دليل التطوير:** [../DEVELOPMENT_GUIDE.md](../DEVELOPMENT_GUIDE.md)
- **Scanner README:** [./README.md](./README.md)
