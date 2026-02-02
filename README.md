# 🛡️ CyberDev - Safe Web Vulnerability Scanner

<div align="center">

![Version](https://img.shields.io/badge/version-1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-Educational-orange.svg)

**أداة شاملة لفحص الثغرات الأمنية في تطبيقات الويب**  
A Comprehensive Web Application Security Scanner

</div>

---

## 📋 نظرة عامة | Overview

**CyberDev** هو ماسح ضوئي أمني متقدم مصمم لاكتشاف الثغرات الأمنية في تطبيقات الويب. يجمع بين تقنيات الاستطلاع السلبي (Passive Reconnaissance) والفحص النشط (Active Scanning) للكشف عن أكثر من **18 نوع من الثغرات الأمنية الشائعة**.

**CyberDev** is an advanced security scanner designed to detect vulnerabilities in web applications. It combines passive reconnaissance and active scanning techniques to identify over **18 types of common security vulnerabilities**.

### ⚠️ تنويه أخلاقي | Ethical Notice

```
⚖️  هذا المشروع مخصص للأغراض التعليمية والاختبارات الأخلاقية فقط
    This project is intended for educational purposes and ethical testing only

❌  لا تستخدمه لفحص مواقع دون إذن صريح
    Do not use it to scan websites without explicit permission

✅  استخدمه فقط على المواقع التي تملكها أو بإذن كتابي
    Use it only on websites you own or with written permission
```

---

## ✨ المميزات الرئيسية | Key Features

### 🕵️ **استطلاع شامل (Comprehensive Reconnaissance)**
- ✅ جمع معلومات Whois
- ✅ تحليل DNS و SPF/DMARC
- ✅ فحص البورتات المفتوحة
- ✅ اكتشاف التقنيات المستخدمة
- ✅ تحديد الموقع الجغرافي (Geolocation)
- ✅ الكشف عن مزود الاستضافة (AWS, Azure, GCP, etc.)
- ✅ اكتشاف CDN و WAF
- ✅ فحص شهادات SSL/TLS

### 🐛 **فحص الثغرات الأمنية (Vulnerability Scanning)**

#### تطبيقات الويب:
- 🔴 **SQL Injection** - حقن قواعد البيانات
- 🔴 **Cross-Site Scripting (XSS)** - هجمات JavaScript
- 🔴 **Remote Code Execution (RCE)** - تنفيذ أوامر عن بعد
- 🟠 **Local File Inclusion (LFI)** - قراءة ملفات النظام
- 🟠 **Server-Side Request Forgery (SSRF)** - تزوير طلبات الخادم
- 🟠 **XML External Entity (XXE)** - هجمات XML
- 🟠 **Server-Side Template Injection (SSTI)** - حقن القوالب

#### APIs & Authentication:
- 🔴 **JWT Security** - فحص JSON Web Tokens
- 🟠 **API Security** - BOLA, Mass Assignment, Data Exposure
- 🟠 **Authentication Flaws** - ثغرات المصادقة
- 🟠 **GraphQL Security** - فحص GraphQL APIs

#### البنية التحتية:
- 🟠 **Open Redirect** - إعادة توجيه غير آمنة
- 🟠 **Host Header Injection** - حقن رأس المضيف
- 🟠 **Cache Poisoning** - تسميم الذاكرة المؤقتة
- 🟢 **Rate Limiting** - فحص حدود المعدل
- 🟢 **File Upload Security** - أمان رفع الملفات
- 🔵 **WebSocket Security** - أمان WebSocket
- 🔵 **Insecure Deserialization** - فك تسلسل غير آمن

### 📊 **نظام تقارير متطور (Advanced Reporting)**
- 🖥️ **CLI Output** - عرض تفاعلي ملون على الشاشة
- 📄 **JSON Export** - للتكامل مع أدوات أخرى
- 🌐 **HTML Reports** - تقارير HTML جميلة وقابلة للطباعة
- 📝 **Markdown** - للتوثيق
- 📊 **CSV** - للتحليل في Excel

---

## 🚀 التثبيت والإعداد | Installation

### المتطلبات | Prerequisites
```bash
- Python 3.8 أو أحدث
- pip (مدير حزم Python)
```

### 1. تنزيل المشروع | Clone Repository
```bash
git clone https://github.com/ahmedalhomili/CyberDev.git
cd CyberDev
```

### 2. تثبيت المكتبات | Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. التحقق من التثبيت | Verify Installation
```bash
python main.py --help
```

---

## 📖 الاستخدام | Usage

### 🎯 الوضع التفاعلي | Interactive Mode
```bash
python main.py```

سيظهر لك قائمة تفاعلية:
```
╔════════════════════════════════════════════╗
║  SAFE WEB VULNERABILITY CHECKER           ║
╚════════════════════════════════════════════╝

[1] Start New Scan
[2] View Scan History
[0] Exit

Option >>
```

### ⚡ الوضع السريع | Quick Mode
```bash
# فحص سريع لموقع
python main.py

# إدخال URL عند الطلب
Enter target URL: https://example.com
```

### 📋 أمثلة عملية | Examples

#### مثال 1: فحص موقع تجريبي
```bash
python main.py
# ثم أدخل: http://testphp.vulnweb.com
```

#### مثال 2: عرض التقرير بعد الفحص
```bash
# بعد انتهاء الفحص، اختر:
[1] View Full Report (On Screen)
[2] Export Report (JSON, HTML, MD, CSV)
```

#### مثال 3: تصدير تقارير متعددة
```bash
# اختر الصيغ المطلوبة:
Formats (e.g. 1,3) >> 1,2,3,4
# سيحفظ: JSON, Markdown, HTML, CSV
```

---

## 📁 هيكل المشروع | Project Structure

```
CyberDev/
├── 📄 main.py                 # نقطة الدخول الرئيسية
├── 📄 cli.py                  # واجهة CLI
├── 📄 config.py               # الإعدادات
├── 📄 models.py               # نماذج البيانات
├── 📄 requirements.txt        # المكتبات المطلوبة
├── 📄 ARCHITECTURE.md         # ⭐ شرح مفصل للهيكل
├── 📄 DEVELOPMENT_GUIDE.md    # دليل المطورين
│
├── 📂 scanner/               # محرك الفحص
│   ├── core/                 # النواة الأساسية
│   ├── recon/                # الاستطلاع
│   └── vulnerabilities/      # فاحصات الثغرات
│
├── 📂 report/                # نظام التقارير
├── 📂 sessions/              # حفظ الجلسات
├── 📂 ui/                    # واجهة المستخدم
└── 📂 utils/                 # أدوات مساعدة
```

> 📖 **لفهم الهيكل بالتفصيل:** اقرأ ملف [ARCHITECTURE.md](ARCHITECTURE.md)

---

## 🎯 مثال على مخرجات الفحص | Sample Output

### 📊 ملخص النتائج | Results Summary
```
═══════════════════════════════════════════════
[ 📊 SUMMARY OF FINDINGS ]
──────────────────────────────
  🔴 CRITICAL: 0
  🔴 HIGH    : 2
  🟠 MEDIUM  : 3
  🔵 LOW     : 5
  ⚪ INFO    : 2
  ------------
  📊 TOTAL   : 12
═══════════════════════════════════════════════
```

### 🕵️ معلومات الاستطلاع | Reconnaissance Info
```
➤ Target Info:
   • IP Address    : 162.241.24.14
   • Server OS     : Likely Linux (Apache)
   • Registrar     : Yemen Net

➤ Geolocation:
   • Location      : Phoenix, Arizona, USA
   • ISP           : Oracle Corporation
   • Hosting Type  : Data Center / Cloud

➤ SSL/TLS Certificate:
   • Status        : ✓ Enabled
   • Protocol      : TLSv1.3
   • Issuer        : Let's Encrypt
```

### 🐛 أمثلة على الثغرات | Vulnerability Examples
```
[HIGH] SQL Injection Detected
───────────────────────────────
Location    : /products.php?id=1
Description : Time-based blind SQL injection confirmed
Fix         : Use parameterized queries
Reference   : CWE-89

[MEDIUM] Missing Security Headers
───────────────────────────────────
Location    : HTTP Response Headers
Description : Content-Security-Policy header not found
Fix         : Add CSP header
Reference   : CWE-79
```

---

## 🔧 التطوير والمساهمة | Development

### للمطورين | For Developers

#### 1. إضافة فاحص ثغرة جديد
```bash
# أنشئ ملف في scanner/vulnerabilities/
touch scanner/vulnerabilities/vuln_new_check.py
```

```python
# استخدم Template التالي:
from models import Finding
import logging

logger = logging.getLogger(__name__)

class NewVulnerabilityScanner:
    def scan(self, url, headers=None):
        """Scan for new vulnerability."""
        findings = []
        logger.info(f"[NEW_VULN] Scanning {url}...")
        
        # Your scanning logic here
        
        return findings
```

#### 2. أضفه للـ Orchestrator
```python
# في scanner/core/scanner_orchestrator.py
from scanner.vulnerabilities.vuln_new_check import NewVulnerabilityScanner

# في دالة scan():
findings.extend(NewVulnerabilityScanner().scan(url))
```

> 📖 **للمزيد:** اقرأ ملف [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md)

### قواعد المساهمة | Contribution Guidelines
1. ✅ **Code Style**: اتبع PEP 8
2. ✅ **Documentation**: أضف docstrings لكل دالة
3. ✅ **Testing**: اختبر على testphp.vulnweb.com
4. ✅ **Ethics**: لا تضيف exploits خطيرة

---

## 📚 الموارد التعليمية | Educational Resources

### للتعلم | Learning Materials
- 📖 [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- 📖 [CWE Top 25](https://cwe.mitre.org/top25/)
- 📖 [PortSwigger Web Security Academy](https://portswigger.net/web-security)

### مواقع تجريبية | Practice Sites
```bash
# مواقع آمنة للممارسة:
- http://testphp.vulnweb.com
- http://demo.testfire.net
- https://juice-shop.herokuapp.com
```

---

## ⚙️ الإعدادات المتقدمة | Advanced Configuration

### تخصيص الفحص | Customize Scanning
عدّل `config.py` لتغيير:
```python
# Timeout للطلبات
REQUEST_TIMEOUT = 10  # seconds

# عدد المحاولات
MAX_RETRIES = 3

# مستويات الخطورة
SEVERITY_LEVELS = {...}
```

### تفعيل Logging مفصل
```python
# في main.py:
logging.basicConfig(
    level=logging.DEBUG,  # بدلاً من INFO
    format='%(levelname)s: %(message)s'
)
```

---

## 🐛 الأخطاء الشائعة وحلولها | Troubleshooting

### مشكلة: "Module not found"
```bash
# الحل:
pip install -r requirements.txt --upgrade
```

### مشكلة: "Connection timeout"
```bash
# الحل: زيادة timeout في config.py
REQUEST_TIMEOUT = 20  # بدلاً من 10
```

### مشكلة: "Too many open ports detected"
```bash
# هذا تحذير - يعني أن فحص البورتات وجد نتائج غير واقعية
# الماسح سيعرض فقط البورتات الحرجة (80, 443, 22)
```

---

## 📊 الإحصائيات | Statistics

- ✅ **18+ Vulnerability Scanners**
- ✅ **8+ Reconnaissance Techniques**
- ✅ **5 Report Formats**
- ✅ **100+ Test Payloads**
- ✅ **OWASP Compliant**

---

## 📞 الدعم والتواصل | Support

### للأسئلة والاستفسارات:
- 📧 Email: ahmed.alhomili@example.com
- 🐛 Issues: [GitHub Issues](https://github.com/ahmedalhomili/CyberDev/issues)
- 📖 Documentation: [ARCHITECTURE.md](ARCHITECTURE.md) & [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md)

---

## 📜 الترخيص | License

```
⚖️  هذا المشروع للأغراض التعليمية فقط
    This project is for educational purposes only

📚  يُسمح باستخدامه في:
    - البحث الأكاديمي
    - التدريب الأمني
    - الاختبار الأخلاقي (بإذن)

❌  ممنوع استخدامه:
    - للهجمات الحقيقية
    - بدون إذن صريح
    - لأغراض غير قانونية
```

---

## 🙏 شكر وتقدير | Acknowledgments

- OWASP Community
- PortSwigger Academy
- Python Security Community
- جميع المساهمين في المشروع

---

## 🚀 الإصدارات المستقبلية | Future Releases

- [ ] إضافة فحص APIs بشكل أعمق
- [ ] دعم فحص تطبيقات Mobile APIs
- [ ] تكامل مع CI/CD pipelines
- [ ] واجهة Web UI
- [ ] تقارير PDF

---

<div align="center">

**صُنع بـ ❤️ من قبل فريق CyberDev**  
Made with ❤️ by CyberDev Team

**للمزيد من التفاصيل، اقرأ [ARCHITECTURE.md](ARCHITECTURE.md)**

</div>
````

#### Verbose Output
See more details during execution:
```bash
python main.py scan https://example.com -v
```

#### View History
List recent scan sessions:
```bash
python main.py history --limit 5
```

#### Show Specific Session
View details of a past scan using its Session ID:
```bash
python main.py show SWVC-20240118-123045-example-a1b2c3d4
```

---

## 📂 Project Structure

*   **`main.py`**: Entry point for both CLI and interactive modes.
*   **`cli.py`**: Handles command-line argument parsing.
*   **`config.py`**: Configuration constants (Severity levels, Header rules).
*   **`models.py`**: Data structures (`Finding`, `ScanResult`).
*   **`scanner/`**:
    *   `scanner_orchestrator.py`: Coordinates the scanning process.
    *   `http_handler.py`: Handles network requests and HTTPS checks.
    *   `headers_analyzer.py`: Validates security headers.
    *   `cors_analyzer.py`: Checks CORS policies.
*   **`sessions/`**:
    *   `session_logger.py`: Manages saving/loading scan history (JSON).
*   **`report/`**:
    *   `report_formatter.py`: Generates CLI, HTML, JSON, CSV, and Markdown reports.
*   **`utils/`**:
    *   `allMenus.py`: Interactive menu interface.
    *   `progress.py`: Visual progress bar for scans.
    *   `color.py`: ANSI color codes for terminal output.
    *   `util.py`: General utility functions.

---

## ⚠️ Disclaimer & Ethical Use

**This tool is for EDUCATIONAL PURPOSES ONLY.**

*   **No Exploitation:** This tool **does not** perform SQL Injection, XSS, Brute-force, or any active attacks.
*   **Passive Only:** It only reads headers and public configurations sent voluntarily by the server.
*   **Responsibility:** The authors are not responsible for any misuse of this tool. Always ensure you have permission to analyze the target.

---

## 👥 Contributors

| # | Name | GitHub | Role |
|---|---|---|---|
| 1 | Ahmed Alhomili | @ahmedalhomili | Project Lead |
| 2 | Bazil Adel | @bazilb402-dot | HTTP & Network |
| 3 | Othman | @othmancoc | Security Headers |
| 4 | Wazeer Abdulqawi | @wazeercs | CORS & Reporting |
