# 🛡️ CyberDev Security Scanner

<div align="center">

![Version](https://img.shields.io/badge/version-1.2-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-Educational-orange.svg)

**أداة فحص الثغرات الأمنية للويب - للأغراض التعليمية فقط**

</div>

---

## ⚠️ إشعار مهم

```
⚖️  لأغراض تعليمية فقط - لا تستخدمها على مواقع دون إذن
✅  استخدمها فقط على المواقع التي تملكها
```

---

## 📦 التثبيت السريع

```bash
# 1. تنزيل المشروع
git clone https://github.com/ahmedalhomili/CyberDev.git
cd CyberDev

# 2. إنشاء وتفعيل بيئة افتراضية (venv)
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

# 3. تثبيت المكتبات
pip install -r requirements.txt

# 4. تشغيل الفحص
python main.py
```

---

## 🎯 الاستخدام

### 🖥️ الوضع التفاعلي (موصى به)
```bash
python main.py
```
سيعرض قائمة تفاعلية مع شريط تقدم ملون لمتابعة الفحص.

### ⚡ الوضع السريع (CLI)
```bash
# فحص بسيط
python main.py scan https://example.com

# فحص مع تفاصيل
python main.py scan https://example.com -v

# تصدير نتائج
python main.py scan https://example.com --json report.json
python main.py scan https://example.com --html report.html

# عرض السجلات
python main.py history
python main.py show <session_id>
```

---

## 📚 الأوامر المتاحة

| الأمر | الوصف | مثال |
|------|-------|------|
| `scan` | فحص موقع | `python main.py scan https://example.com` |
| `history` | عرض الفحوصات السابقة | `python main.py history --limit 10` |
| `show` | عرض تفاصيل فحص معين | `python main.py show <session_id>` |
| `help` | عرض مساعدة سريعة | `python main.py help` |
| `man` | عرض دليل شامل | `python main.py man` |

### خيارات أمر `scan`

| الخيار | الوصف | مثال |
|--------|-------|------|
| `-v, --verbose` | عرض تفاصيل الفحص | `--verbose` |
| `-j, --json FILE` | تصدير JSON | `--json report.json` |
| `-m, --markdown FILE` | تصدير Markdown | `--markdown report.md` |
| `--html FILE` | تصدير HTML | `--html report.html` |
| `--csv FILE` | تصدير CSV | `--csv report.csv` |

---

## 🐛 الثغرات المدعومة (18+)

### تطبيقات الويب
- 🔴 **SQL Injection** - حقن قواعد البيانات
- 🔴 **Cross-Site Scripting (XSS)** - هجمات JavaScript
- 🔴 **Remote Code Execution (RCE)** - تنفيذ أوامر عن بعد
- 🟠 **Local File Inclusion (LFI)** - قراءة ملفات النظام
- 🟠 **Server-Side Request Forgery (SSRF)** - تزوير طلبات الخادم
- 🟠 **XML External Entity (XXE)** - هجمات XML
- 🟠 **Server-Side Template Injection (SSTI)** - حقن القوالب

### APIs والمصادقة
- 🔴 **JWT Security** - فحص JSON Web Tokens
- 🟠 **API Security** - BOLA, Mass Assignment
- 🟠 **Authentication Flaws** - ثغرات المصادقة
- 🟠 **GraphQL Security** - فحص GraphQL

### البنية التحتية
- 🟠 **Open Redirect** - إعادة توجيه غير آمنة
- 🟠 **Host Header Injection** - حقن رأس المضيف
- 🟠 **Cache Poisoning** - تسميم الذاكرة المؤقتة
- 🟢 **File Upload Security** - أمان رفع الملفات
- 🔵 **WebSocket Security** - أمان WebSocket
- 🔵 **Insecure Deserialization** - فك تسلسل غير آمن

---

## 📊 التقارير

### صيغ التصدير
- **CLI Output** - عرض ملون تفاعلي على الشاشة
- **JSON** - للتكامل مع أدوات أخرى
- **HTML** - تقارير احترافية قابلة للطباعة
- **Markdown** - للتوثيق
- **CSV** - للتحليل في Excel

### حفظ تلقائي
يتم حفظ جميع الفحوصات تلقائياً في:
```
sessions/scan_sessions/SWVC-YYYYMMDD-HHMMSS-domain-hash.json
```

---

## 🔍 كيف يعمل الفحص؟

### 1️⃣ الاستطلاع (Reconnaissance)
- جمع معلومات Whois
- تحليل DNS و SPF/DMARC
- فحص البورتات المفتوحة
- اكتشاف التقنيات المستخدمة
- تحديد الموقع الجغرافي
- الكشف عن CDN/WAF
- فحص شهادات SSL/TLS

### 2️⃣ الزحف واكتشاف URLs
- زحف تلقائي للموقع (عمق: 2 مستويات)
- اكتشاف URLs مع Parameters
- تحليل Forms ومدخلات المستخدم
- فحص robots.txt
- Directory Fuzzing

### 3️⃣ فحص الثغرات (21 خطوة)
يتم اختبار **18+ نوع ثغرة** على URLs المكتشفة:
- SQL Injection (Error-based, Time-based, Boolean-based)
- XSS (Reflected, Stored)
- RCE, LFI, SSTI, SSRF, XXE
- Open Redirect, Host Header Injection
- JWT, GraphQL, Deserialization
- Authentication & Session Management
- File Upload, API Security, WebSocket

### 4️⃣ التقرير
- تصنيف حسب الخطورة: CRITICAL, HIGH, MEDIUM, LOW, INFO
- توليد Session ID فريد
- حفظ تلقائي في مجلد sessions
- تصدير بصيغ متعددة

---

## 📁 هيكل المشروع

```
CyberDev/
├── main.py                    # نقطة الدخول الرئيسية
├── cli.py                     # معالج سطر الأوامر
├── config.py                  # الإعدادات المركزية
├── models.py                  # نماذج البيانات (Finding, ScanResult)
├── requirements.txt           # المكتبات المطلوبة
│
├── scanner/                   # محرك الفحص
│   ├── core/
│   │   ├── scanner_orchestrator.py  # منسق الفحص الرئيسي
│   │   ├── http_handler.py          # معالج طلبات HTTP
│   │   └── requester.py             # إدارة الطلبات
│   │
│   ├── recon/                 # الاستطلاع
│   │   ├── recon_analyzer.py        # جمع معلومات Whois/DNS/GeoIP
│   │   ├── headers_analyzer.py      # فحص Security Headers
│   │   ├── cors_analyzer.py         # فحص CORS
│   │   ├── content_analyzer.py      # فحص المحتوى (Secrets)
│   │   ├── robots_check.py          # فحص robots.txt
│   │   ├── link_crawler.py          # الزحف واكتشاف URLs
│   │   └── explore_fuzzer.py        # Directory Fuzzing
│   │
│   └── vulnerabilities/       # فاحصات الثغرات (18 فاحص)
│       ├── vuln_sqli.py             # SQL Injection
│       ├── vuln_xss.py              # Cross-Site Scripting
│       ├── vuln_rce.py              # Remote Code Execution
│       ├── vuln_lfi.py              # Local File Inclusion
│       ├── vuln_ssrf.py             # Server-Side Request Forgery
│       ├── vuln_ssti.py             # Template Injection
│       ├── vuln_xxe.py              # XML External Entity
│       ├── vuln_jwt.py              # JWT Security
│       ├── vuln_graphql.py          # GraphQL Security
│       ├── vuln_redirect.py         # Open Redirect
│       ├── vuln_host_header.py      # Host Header Injection
│       ├── vuln_cache_poisoning.py  # Cache Poisoning
│       ├── vuln_auth_workflow.py    # Authentication
│       ├── vuln_upload_checks.py    # File Upload
│       ├── vuln_api_security.py     # API Security
│       ├── vuln_websocket.py        # WebSocket Security
│       └── vuln_deserialization.py  # Deserialization
│
├── report/                    # نظام التقارير
│   └── report_formatter.py   # توليد تقارير بصيغ متعددة
│
├── sessions/                  # حفظ الجلسات
│   ├── session_logger.py      # إدارة الجلسات
│   └── scan_sessions/         # ملفات JSON للفحوصات
│
├── ui/                        # واجهة المستخدم
│   ├── menus.py               # القوائم التفاعلية
│   ├── scan_progress.py       # شريط التقدم الملون
│   ├── colors.py              # ألوان ANSI
│   ├── logo.py                # شعار الأداة
│   └── progress.py            # Progress Bar
│
└── utils/                     # أدوات مساعدة
    ├── helpers.py             # دوال عامة
    ├── network.py             # أدوات الشبكة
    └── severity.py            # تصنيف الخطورة
```

---

## 🔗 ملفات التوثيق

| الملف | الوصف |
|-------|--------|
| [README.md](README.md) | دليل الاستخدام الأساسي (هذا الملف) |
| [CLI_GUIDE.md](CLI_GUIDE.md) | مرجع سريع لجميع الأوامر والخيارات |
| [ARCHITECTURE.md](ARCHITECTURE.md) | شرح مفصل لهيكل المشروع (للمطورين) |
| [CHANGELOG.md](CHANGELOG.md) | سجل التغييرات والإصدارات |

---

## 💡 نصائح

### للحصول على أفضل النتائج:
1. استخدم الوضع التفاعلي (`python main.py`) للحصول على تجربة أفضل
2. جرب على مواقع تجريبية آمنة مثل:
   - http://testphp.vulnweb.com
   - http://demo.testfire.net
3. استخدم `--verbose` لمعرفة تفاصيل كل خطوة
4. احفظ التقارير بصيغ متعددة للمراجعة

---

## 📧 التواصل

- **GitHub**: [@ahmedalhomili](https://github.com/ahmedalhomili)
- **Project**: [CyberDev Security Scanner](https://github.com/ahmedalhomili/CyberDev)

---

<div align="center">

**⚡ Made with Python | Educational Use Only ⚡**

</div>
| 3 | Othman | @othmancoc | Security Headers |
| 4 | Wazeer Abdulqawi | @wazeercs | CORS & Reporting |
