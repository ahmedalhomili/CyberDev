# 🏗️ هيكل المشروع - CyberDev Security Scanner

## 📋 نظرة عامة

هذا مشروع ماسح ضوئي أمني شامل (Web Vulnerability Scanner) مكتوب بلغة Python، يقوم بفحص المواقع والتطبيقات الإلكترونية للكشف عن الثغرات الأمنية الشائعة.

## 📁 البنية الشجرية للمشروع

```
CyberDev/
├── 📄 main.py                    # نقطة الدخول الرئيسية للتطبيق
├── 📄 cli.py                     # واجهة سطر الأوامر (CLI Interface)
├── 📄 config.py                  # الإعدادات والثوابت العامة
├── 📄 models.py                  # نماذج البيانات (Data Models)
├── 📄 requirements.txt           # المكتبات المطلوبة
│
├── 📂 scanner/                   # 🔍 المحرك الأساسي للفحص
│   ├── __init__.py
│   │
│   ├── 📂 core/                  # النواة الأساسية
│   │   ├── scanner_orchestrator.py  # منسق عملية الفحص الكاملة
│   │   ├── http_handler.py          # معالج طلبات HTTP
│   │   └── requester.py              # إرسال الطلبات مع retry logic
│   │
│   ├── 📂 recon/                 # 🕵️ جمع المعلومات الاستخباراتية
│   │   ├── recon_analyzer.py        # محلل الاستطلاع الشامل
│   │   ├── link_crawler.py          # زاحف الروابط
│   │   ├── content_analyzer.py      # تحليل المحتوى
│   │   ├── headers_analyzer.py      # تحليل HTTP Headers
│   │   ├── cors_analyzer.py         # فحص CORS
│   │   ├── https_check.py           # فحص HTTPS/SSL
│   │   ├── robots_check.py          # تحليل robots.txt
│   │   └── explore_fuzzer.py        # اكتشاف الملفات والمجلدات
│   │
│   └── 📂 vulnerabilities/       # 🐛 فاحصات الثغرات الأمنية
│       ├── vuln_sqli.py              # SQL Injection
│       ├── vuln_xss.py               # Cross-Site Scripting
│       ├── vuln_lfi.py               # Local File Inclusion
│       ├── vuln_rce.py               # Remote Code Execution
│       ├── vuln_ssrf.py              # Server-Side Request Forgery
│       ├── vuln_ssti.py              # Server-Side Template Injection
│       ├── vuln_xxe.py               # XML External Entity
│       ├── vuln_jwt.py               # JWT Security
│       ├── vuln_redirect.py          # Open Redirect
│       ├── vuln_deserialization.py   # Insecure Deserialization
│       ├── vuln_upload_checks.py     # File Upload Security
│       ├── vuln_rate_limit.py        # Rate Limiting
│       ├── vuln_cache_poisoning.py   # Cache Poisoning
│       ├── vuln_host_header.py       # Host Header Injection
│       ├── vuln_auth_workflow.py     # Authentication Flaws
│       ├── vuln_api_security.py      # API Security
│       ├── vuln_graphql.py           # GraphQL Security
│       └── vuln_websocket.py         # WebSocket Security
│
├── 📂 report/                    # 📊 نظام التقارير
│   ├── report_formatter.py          # تنسيق التقارير (CLI, JSON, HTML, MD, CSV)
│   └── __init__.py
│
├── 📂 sessions/                  # 💾 حفظ الجلسات
│   ├── session_logger.py            # تسجيل الجلسات
│   └── scan_sessions/               # ملفات JSON للجلسات المحفوظة
│
├── 📂 ui/                        # 🎨 واجهة المستخدم
│   ├── colors.py                    # ألوان ANSI للـ CLI
│   ├── logo.py                      # شعار التطبيق
│   ├── menus.py                     # قوائم التفاعل
│   └── progress.py                  # شريط التقدم
│
└── 📂 utils/                     # 🛠️ أدوات مساعدة
    ├── helpers.py                   # دوال مساعدة عامة
    ├── network.py                   # أدوات الشبكة
    ├── severity.py                  # إدارة مستويات الخطورة
    └── allMenus.py                  # قوائم إضافية
```

---

## 🔄 سير العمل (Workflow)

### 1️⃣ **البداية** (`main.py`)
- تحميل الإعدادات من `config.py`
- عرض الشعار من `ui/logo.py`
- استدعاء واجهة CLI من `cli.py`

### 2️⃣ **إدخال الهدف** (`cli.py`)
- المستخدم يدخل URL الهدف
- التحقق من صحة الإدخال
- إنشاء Session ID فريد

### 3️⃣ **بدء الفحص** (`scanner/core/scanner_orchestrator.py`)
المنسق الرئيسي ينفذ المراحل التالية بالترتيب:

#### **المرحلة الأولى: الاستطلاع (Reconnaissance)** 🕵️
```
scanner/recon/recon_analyzer.py
├─► جمع معلومات Whois
├─► تحليل DNS و SPF/DMARC
├─► فحص البورتات المفتوحة
├─► الكشف عن التقنيات المستخدمة
├─► تحديد الموقع الجغرافي (Geolocation)
├─► اكتشاف مزود الاستضافة (Hosting Provider)
├─► الكشف عن CDN و WAF
└─► فحص شهادة SSL/TLS
```

#### **المرحلة الثانية: استكشاف الهيكل** 🗺️
```
scanner/recon/link_crawler.py  ⭐ المكون الأساسي
├─► زحف الروابط (Web Crawling)
├─► استخراج URLs من <a> و <form>
├─► فلترة URLs مع parameters فقط
│   مثال:
│   ✅ /page.php?id=1        → يُضاف للفحص
│   ✅ /search.php?q=test    → يُضاف للفحص
│   ❌ /about.html           → يُتجاهل (بدون parameters)
└─► إرجاع قائمة testable URLs

مثال عملي:
  المدخل: https://example.com
           ↓
  Crawler يكتشف:
  1. https://example.com/products.php?id=1
  2. https://example.com/search.php?q=test
  3. https://example.com/page.php?category=5
           ↓
  يُمرَّر للمرحلة الثالثة ←

scanner/recon/explore_fuzzer.py
├─► البحث عن ملفات حساسة
├─► اكتشاف مجلدات إدارية
└─► فحص backup files
```

#### **المرحلة الثالثة: فحص الثغرات** 🐛
```
لكل URL اكتشفه Crawler:

scanner/vulnerabilities/
تنفيذ كل فاحص بشكل متسلسل:
```
scanner/vulnerabilities/
├─► SQL Injection (vuln_sqli.py)
├─► XSS (vuln_xss.py)
├─► LFI (vuln_lfi.py)
├─► RCE (vuln_rce.py)
├─► SSRF (vuln_ssrf.py)
├─► XXE (vuln_xxe.py)
├─► JWT (vuln_jwt.py)
└─► ... (17 فاحص ثغرات)
```

### 4️⃣ **جمع النتائج** (`models.py`)
- تخزين البيانات في `ScanResult` dataclass
- كل ثغرة تُحفظ كـ `Finding` object
- Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO

### 5️⃣ **إنشاء التقرير** (`report/report_formatter.py`)
```
ReportFormatter
├─► CLI Output (عرض على الشاشة)
├─► JSON Export
├─► HTML Report
├─► Markdown Report
└─► CSV Export
```

### 6️⃣ **حفظ الجلسة** (`sessions/session_logger.py`)
- حفظ النتائج في `sessions/scan_sessions/`
- تنسيق: `SWVC-{timestamp}-{domain}-{hash}.json`

---

## 🧩 المكونات الرئيسية بالتفصيل

### 1. **Scanner Orchestrator** (المنسق)
**الملف:** `scanner/core/scanner_orchestrator.py`

**الوظيفة:** تنسيق كل مراحل الفحص

**الدوال الرئيسية:**
- `scan(url)` - نقطة الدخول الرئيسية
- `_run_recon()` - تنفيذ الاستطلاع
- `_run_vulnerability_checks()` - تنفيذ فحوصات الثغرات
- `_aggregate_results()` - جمع النتائج

---

### 2. **Link Crawler** (زاحف الروابط) 🕷️
**الملف:** `scanner/recon/link_crawler.py`

**الوظيفة:** اكتشاف URLs مع parameters تلقائياً للفحص

**لماذا نحتاجه؟**
معظم الثغرات (SQLi, XSS, LFI) تحتاج parameters:
```
✅ /page.php?id=1        # قابل للفحص
❌ /about.html           # لا يوجد parameters
```

**كيف يعمل؟**
```python
1. يزحف الموقع من الصفحة الرئيسية
2. يستخرج روابط من:
   - <a href="...">
   - <form action="...">
3. يفلتر الروابط التي فيها parameters (?param=value)
4. يزحف حتى عمق 2 مستويات
5. يرجع قائمة URLs للفحص
```

**الدوال الرئيسية:**
- `crawl(url)` - يبدأ الزحف من URL
- `get_testable_urls()` - يرجع URLs مع parameters فقط
- `_extract_links()` - يستخرج روابط من HTML
- `_is_same_domain()` - يتأكد أن الرابط من نفس الموقع

**مثال عملي:**
```python
crawler = LinkCrawler(max_depth=2, max_urls=30)
crawled = crawler.crawl("https://example.com")

# النتيجة:
[
    {'url': '/page.php?id=1', 'params': ['id'], 'depth': 1},
    {'url': '/search.php?q=test', 'params': ['q'], 'depth': 1},
    {'url': '/products.php?cat=5', 'params': ['cat'], 'depth': 2}
]

# استخدام في Orchestrator:
testable_urls = crawler.get_testable_urls(limit=15)
for url in testable_urls:
    sqli_scanner.scan(url)  # يفحص كل URL
```

**الإعدادات:**
```python
LinkCrawler(
    max_depth=2,     # كم مستوى يزحف (default: 2)
    max_urls=30      # كم صفحة يزور (default: 30)
)
```

**ماذا لو لم يجد URLs؟**
```python
if not testable_urls:
    testable_urls = [base_url]  # يستخدم الـ URL الأساسي
    # لكن معظم الفاحصات لن تجد شيء
```

---

### 3. **HTTP Handler** (معالج الطلبات)
**الملف:** `scanner/core/http_handler.py`

**الوظيفة:** إرسال واستقبال طلبات HTTP بأمان

**المميزات:**
- User-Agent عشوائي
- معالجة الأخطاء
- Timeout management
- SSL verification

---

### 4. **Vulnerability Scanners** (فاحصات الثغرات)
**المجلد:** `scanner/vulnerabilities/`

**الهيكل الموحد لكل فاحص:**
```python
class VulnScanner:
    def scan(self, url, headers=None):
        """
        الدالة الرئيسية للفحص
        Returns: List[Finding]
        """
        findings = []
        
        # 1. اختبار Payloads
        # 2. تحليل الاستجابات
        # 3. إنشاء Finding objects
        
        return findings
```

---

### 4. **Recon Analyzer** (محلل الاستطلاع)
**الملف:** `scanner/recon/recon_analyzer.py`

**الوظائف الرئيسية:**
- `analyze(url)` - تنفيذ كل فحوصات الاستطلاع
- `_resolve_ip()` - الحصول على IP
- `_scan_ports()` - فحص البورتات
- `_get_geolocation()` - تحديد الموقع الجغرافي
- `_detect_hosting_provider()` - اكتشاف مزود الاستضافة
- `_get_ssl_info()` - فحص SSL certificate

---

### 5. **Report Formatter** (منسق التقارير)
**الملف:** `report/report_formatter.py`

**الصيغ المدعومة:**
```python
ReportFormatter(scan_result)
├─► format_cli_output()    # عرض على الشاشة
├─► format_json()          # JSON export
├─► format_html()          # HTML report
├─► format_markdown()      # Markdown
└─► format_csv()           # CSV للتحليل
```

---

## 🎯 نماذج البيانات (Data Models)

### **Finding** (ثغرة واحدة)
```python
@dataclass
class Finding:
    title: str              # اسم الثغرة
    severity: str           # CRITICAL|HIGH|MEDIUM|LOW|INFO
    description: str        # شرح الثغرة
    location: str           # مكان الثغرة
    recommendation: str     # كيفية الإصلاح
    cwe_reference: str      # CWE ID
    confidence: str         # High|Medium|Low
```

### **ReconData** (معلومات الاستطلاع)
```python
@dataclass
class ReconData:
    ip_address: str
    domain_info: Dict       # Whois data
    server_os: str
    technologies: List[str]
    open_ports: List[int]
    dns_security: Dict      # SPF/DMARC
    subdomains: List[str]
    # Dynamic fields:
    geolocation: Dict       # Location, ISP, ASN
    hosting_provider: Dict  # AWS, Azure, etc.
    cdn_waf: Dict          # Cloudflare, Akamai
    ssl_info: Dict         # Certificate details
```

### **ScanResult** (نتيجة الفحص الكاملة)
```python
@dataclass
class ScanResult:
    session_id: str
    target_url: str
    timestamp: datetime
    findings: List[Finding]
    https_enabled: bool
    redirect_chain: List[str]
    recon: ReconData
```

---

## ⚙️ الإعدادات والثوابت

### **config.py**
```python
# Security Headers
SECURITY_HEADERS = {...}

# Severity Levels
SEVERITY_LEVELS = {
    'CRITICAL': {'symbol': '🔴', 'priority': 0},
    'HIGH': {'symbol': '🔴', 'priority': 1},
    'MEDIUM': {'symbol': '🟠', 'priority': 2},
    'LOW': {'symbol': '🟢', 'priority': 3},
    'INFO': {'symbol': '🔵', 'priority': 4}
}

# Logging
LOG_DIR = './sessions/scan_sessions'
REQUEST_TIMEOUT = 10  # seconds
```

---

## 🔐 الأمان والأخلاقيات

⚠️ **هذا الماسح مصمم للاستخدام الأخلاقي فقط:**

1. ✅ **يُسمح:**
   - فحص المواقع التي تملكها
   - فحص المواقع بإذن كتابي
   - الاختبار على بيئات تجريبية (testphp.vulnweb.com)

2. ❌ **ممنوع:**
   - فحص مواقع دون إذن
   - استخدامه لأغراض غير قانونية
   - الهجمات الحقيقية

---

## 📚 المكتبات المستخدمة

```txt
requests          # HTTP requests
beautifulsoup4    # HTML parsing
python-whois      # Whois lookups
dnspython         # DNS queries
fake-useragent    # Random User-Agents
certifi          # SSL certificates
```

---

## 🚀 كيفية إضافة ميزة جديدة

### إضافة فاحص ثغرة جديد:

1. **إنشاء ملف جديد** في `scanner/vulnerabilities/`:
   ```bash
   vuln_new_vulnerability.py
   ```

2. **استخدام Template التالي:**
   ```python
   """
   Scanner for [Vulnerability Name]
   
   Description: [What this scanner detects]
   Severity: [Typical severity level]
   """
   from models import Finding
   import logging
   
   logger = logging.getLogger(__name__)
   
   class NewVulnerabilityScanner:
       def scan(self, url, headers=None):
           """Scan for [vulnerability name]."""
           findings = []
           logger.info(f"[NEW_VULN] Scanning {url}...")
           
           # Your scanning logic here
           
           return findings
   ```

3. **إضافته للـ Orchestrator** في `scanner_orchestrator.py`:
   ```python
   from scanner.vulnerabilities.vuln_new_vulnerability import NewVulnerabilityScanner
   
   # In scan() method:
   findings.extend(NewVulnerabilityScanner().scan(url))
   ```

---

## 📊 مخطط تدفق البيانات

```
User Input (URL: https://example.com)
      ↓
   CLI Interface
      ↓
Scanner Orchestrator
      ↓
      ├─────────────────────────┐
      │                         │
  Reconnaissance          🕷️ Link Crawler
      Module                (NEW!)
      │                         │
      ├─ Whois                 ↓
      ├─ DNS               Crawls website
      ├─ Port Scan              ↓
      ├─ SSL Info          Discovers:
      ├─ Geolocation       • /page.php?id=1
      └─ Hosting           • /search.php?q=test
      │                    • /products.php?cat=5
      │                         │
      └─────────┬───────────────┘
                ↓
        testable_urls = [
            "/page.php?id=1",
            "/search.php?q=test",
            "/products.php?cat=5"
        ]
                ↓
        Vulnerability Scanners
        (Loop through each URL)
                ↓
        ┌───────┼───────┐
        │       │       │
      SQLi    XSS    LFI
        │       │       │
    Test each URL with:
    - /page.php?id=1' OR '1'='1
    - /search.php?q=<script>alert(1)</script>
    - /products.php?cat=../../etc/passwd
                ↓
      Aggregate Results
                ↓
       ScanResult Object
       (findings: List[Finding])
                ↓
      Report Formatter
                ↓
       ┌────────┴────────┐
       │                 │
   CLI Output      Export Files
   (Colored)      (JSON/HTML/MD/CSV)
```

### 🔍 مثال تفصيلي: مسار فحص SQLi

```
1. User: python main.py
2. Input: https://testphp.vulnweb.com
         ↓
3. Link Crawler يزحف:
   - صفحة رئيسية: https://testphp.vulnweb.com/
   - يجد: <a href="/artists.php?artist=1">
   - يجد: <a href="/listproducts.php?cat=1">
         ↓
4. testable_urls = [
       "/artists.php?artist=1",
       "/listproducts.php?cat=1"
   ]
         ↓
5. SQLi Scanner يفحص:
   
   URL 1: /artists.php?artist=1
   • Payload 1: artist=1' OR '1'='1
     Response: 200 OK (طول 5000 bytes)
   • Payload 2: artist=1' OR '1'='2
     Response: 200 OK (طول 2000 bytes)
   ✓ أطوال مختلفة → Boolean-based SQLi detected!
   
   • Payload 3: artist=1' AND SLEEP(5)--
     Response: 200 OK (بعد 5.2 ثانية)
   ✓ تأخير → Time-based SQLi confirmed!
         ↓
6. Finding created:
   {
     title: "SQL Injection (Boolean-based)",
     severity: "HIGH",
     location: "/artists.php?artist=1",
     ...
   }
         ↓
7. Report Formatter:
   [HIGH] SQL Injection Detected
   Location: /artists.php?artist=1
   Description: Boolean-based blind SQLi
```

---

## 🎓 للدراسة والفهم

### **ترتيب القراءة المقترح:**

1. **ابدأ بـ:** `main.py` → `cli.py` - فهم نقطة الدخول
2. **ثم:** `models.py` - فهم نماذج البيانات
3. **ثم:** `scanner/core/scanner_orchestrator.py` - فهم سير العمل
4. **ثم:** اختر أحد الـ vulnerability scanners - فهم كيفية الفحص
5. **أخيراً:** `report/report_formatter.py` - فهم كيفية عرض النتائج

### **للتطوير:**
- اقرأ `DEVELOPMENT_GUIDE.md` للتفاصيل الكاملة
- راجع README في كل مجلد

---

## 📞 للمزيد

- **README الرئيسي:** `README.md`
- **دليل التطوير:** `DEVELOPMENT_GUIDE.md`
- **توثيق المجلدات:** انظر `README.md` داخل كل مجلد

---

**تم إنشاؤه بواسطة:** فريق CyberDev  
**التاريخ:** فبراير 2026  
**الإصدار:** 1.0
