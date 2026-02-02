# 📂 Scanner Module - محرك الفحص الأساسي

هذا المجلد يحتوي على **المحرك الأساسي** لعملية الفحص، مقسم إلى 3 مكونات رئيسية:

---

## 📁 المجلدات الفرعية

### 1. 🧠 `core/` - النواة الأساسية
المسؤولة عن **تنسيق وإدارة** عملية الفحص الكاملة.

**الملفات:**
- `scanner_orchestrator.py` - المنسق الرئيسي لكل مراحل الفحص
- `http_handler.py` - معالجة طلبات HTTP
- `requester.py` - إرسال الطلبات مع retry logic

---

### 2. 🕵️ `recon/` - الاستطلاع والاستخبارات
جمع المعلومات عن الهدف قبل الفحص العميق.

**الملفات:**
- `recon_analyzer.py` - **الملف الرئيسي** - ينسق كل عمليات الاستطلاع
- `link_crawler.py` - زاحف الروابط (Web Crawler)
- `content_analyzer.py` - تحليل محتوى الصفحات
- `headers_analyzer.py` - تحليل HTTP headers
- `cors_analyzer.py` - فحص سياسات CORS
- `https_check.py` - التحقق من HTTPS/SSL
- `robots_check.py` - تحليل robots.txt
- `explore_fuzzer.py` - اكتشاف ملفات ومجلدات مخفية

**المهام:**
- ✅ جمع معلومات Whois
- ✅ تحليل DNS (SPF, DMARC)
- ✅ فحص البورتات المفتوحة
- ✅ اكتشاف التقنيات المستخدمة
- ✅ تحديد الموقع الجغرافي
- ✅ الكشف عن مزود الاستضافة (AWS, Azure, GCP)
- ✅ اكتشاف CDN & WAF
- ✅ فحص شهادة SSL/TLS

---

### 3. 🐛 `vulnerabilities/` - فاحصات الثغرات
**18+ فاحص متخصص** لكشف الثغرات الأمنية الشائعة.

**الفاحصات المتوفرة:**

#### الحقن (Injection Attacks):
- `vuln_sqli.py` - **SQL Injection** (Boolean + Time-based Blind)
- `vuln_xss.py` - **Cross-Site Scripting** (Reflected + Stored)
- `vuln_lfi.py` - **Local File Inclusion** (Path Traversal)
- `vuln_rce.py` - **Remote Code Execution**
- `vuln_ssrf.py` - **Server-Side Request Forgery**
- `vuln_ssti.py` - **Server-Side Template Injection**
- `vuln_xxe.py` - **XML External Entity**

#### APIs & Authentication:
- `vuln_jwt.py` - **JWT Security** (None algorithm, Weak secret)
- `vuln_api_security.py` - **API Security** (BOLA, Mass Assignment)
- `vuln_auth_workflow.py` - **Authentication Flaws**
- `vuln_graphql.py` - **GraphQL Security**

#### البنية التحتية:
- `vuln_redirect.py` - **Open Redirect**
- `vuln_host_header.py` - **Host Header Injection**
- `vuln_cache_poisoning.py` - **Cache Poisoning**
- `vuln_deserialization.py` - **Insecure Deserialization**
- `vuln_upload_checks.py` - **File Upload Security**
- `vuln_rate_limit.py` - **Rate Limiting**
- `vuln_websocket.py` - **WebSocket Security**

---

## 🔄 سير العمل (Workflow)

```
1. Scanner Orchestrator يبدأ العملية
          ↓
2. يستدعي Recon Analyzer
          ↓
3. Recon يجمع معلومات أولية
          ↓
4. Link Crawler يكتشف URLs
          ↓
5. Vulnerability Scanners تفحص كل URL
          ↓
6. النتائج تُجمع وتُرسل للـ Report Formatter
```

---

## 📖 أمثلة الاستخدام

### استخدام Scanner Orchestrator:
```python
from scanner.core.scanner_orchestrator import SecurityScanner

# إنشاء scanner
scanner = SecurityScanner()

# فحص موقع
result = scanner.scan("https://example.com")

# الوصول للنتائج
print(result.summary())
print(result.findings)
```

### استخدام Recon Analyzer مباشرة:
```python
from scanner.recon.recon_analyzer import ReconAnalyzer

# إنشاء analyzer
recon = ReconAnalyzer()

# جمع معلومات
data = recon.analyze("https://example.com")

# عرض النتائج
print(data.ip_address)
print(data.open_ports)
print(data.technologies)
```

### استخدام فاحص ثغرة واحد:
```python
from scanner.vulnerabilities.vuln_sqli import SQLiScanner

# إنشاء فاحص
sqli_scanner = SQLiScanner()

# فحص URL
findings = sqli_scanner.scan("http://example.com/page.php?id=1")

# عرض الثغرات المكتشفة
for finding in findings:
    print(f"{finding.severity}: {finding.title}")
```

---

## 🛠️ للمطورين: إضافة فاحص جديد

### 1. أنشئ ملف جديد في `vulnerabilities/`:
```bash
scanner/vulnerabilities/vuln_my_check.py
```

### 2. استخدم Template التالي:
```python
"""
Scanner for [Vulnerability Name]

Description: [What this scanner checks for]
Severity: HIGH/MEDIUM/LOW
"""
from models import Finding
import logging

logger = logging.getLogger(__name__)

class MyVulnerabilityScanner:
    """
    Scanner for detecting [vulnerability name].
    """
    
    def scan(self, url: str, headers: dict = None) -> list:
        """
        Scan the target URL for [vulnerability].
        
        Args:
            url: Target URL
            headers: Response headers (optional)
        
        Returns:
            List of Finding objects
        """
        findings = []
        logger.info(f"[MY_VULN] Scanning {url}...")
        
        try:
            # 1. اختبار Payload
            # 2. تحليل الاستجابة
            # 3. إنشاء Finding إذا وُجدت ثغرة
            
            pass
            
        except Exception as e:
            logger.error(f"Error in MyVulnScanner: {e}")
        
        return findings
```

### 3. أضفه للـ Orchestrator:
```python
# في scanner/core/scanner_orchestrator.py

from scanner.vulnerabilities.vuln_my_check import MyVulnerabilityScanner

# في دالة scan():
findings.extend(MyVulnerabilityScanner().scan(url))
```

---

## 📊 مخرجات الفحص

كل فاحص يُرجع قائمة من `Finding` objects:

```python
Finding(
    title="SQL Injection Detected",
    severity="HIGH",
    description="Time-based blind SQL injection confirmed",
    location="/products.php?id=1",
    recommendation="Use parameterized queries",
    cwe_reference="CWE-89",
    confidence="High"
)
```

---

## ⚙️ الإعدادات

يمكن تخصيص الفحص من خلال `config.py`:

```python
# Timeout للطلبات
REQUEST_TIMEOUT = 10

# عدد المحاولات
MAX_RETRIES = 3

# البورتات المراد فحصها
COMMON_PORTS = [21, 22, 80, 443, 3306, 8080]
```

---

## 🔍 Logging & Debugging

لتفعيل logging مفصل:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

سيعرض معلومات مثل:
```
[RECON] Resolving IP for example.com...
[RECON] IP found: 93.184.216.34
[PORT_SCAN] Scanning port 80... OPEN
[SQLi] Testing Boolean-based injection...
[SQLi] Vulnerability detected!
```

---

## 📚 للمزيد

- **هيكل المشروع الكامل:** [../ARCHITECTURE.md](../ARCHITECTURE.md)
- **دليل التطوير:** [../DEVELOPMENT_GUIDE.md](../DEVELOPMENT_GUIDE.md)
- **README الرئيسي:** [../README.md](../README.md)

---

**📝 ملاحظة:** جميع الفاحصات تتبع معايير **OWASP** و **CWE** للثغرات الأمنية.
