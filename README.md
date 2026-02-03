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
python main.py scan https://example.com
```

---

## 🎯 الاستخدام الأساسي

### فحص موقع
```bash
python main.py scan https://example.com
```

### فحص مع خيارات
```bash
python main.py scan https://example.com --level 3 --verbose
python main.py scan https://example.com --timeout 15
python main.py scan https://example.com -o report
```

### عرض الفحوصات السابقة
```bash
python main.py history
python main.py show <session_id>
```

### مساعدة
```bash
python main.py --help
python main.py scan --help
```

---

## 🐛 الثغرات المدعومة (18+)

| الفئة | الثغرات |
|------|---------|
| **Web Apps** | SQL Injection, XSS, RCE, LFI, SSRF, XXE, SSTI |
| **APIs** | JWT Security, API Security, Auth Flaws, GraphQL |
| **Infrastructure** | Open Redirect, Host Header Injection, Cache Poisoning |
| **Others** | Rate Limiting, File Upload, WebSocket, Deserialization |

---

## 📊 التقارير المدعومة

- **CLI** - عرض ملون على الشاشة
- **JSON** - للتكامل مع أدوات أخرى
- **HTML** - تقارير احترافية
- **Markdown** - للتوثيق
- **CSV** - للتحليل

---

## 🔍 كيف يعمل الفحص؟

### المراحل الأربعة:

**1. الاستطلاع (Reconnaissance)**
```
• جمع معلومات Whois
• تحليل DNS
• فحص البورتات
• اكتشاف التقنيات
```

**2. اكتشاف URLs**
```
• الزحف التلقائي للموقع
• اكتشاف الروابط والـ Parameters
• تحليل Forms
```

**3. فحص الثغرات**
```
• اختبار 18+ نوع ثغرة
• استخدام Payloads متقدمة
• تحليل الاستجابات
```

**4. التقارير**
```
• تصنيف الثغرات حسب الخطورة
• تصدير بعدة صيغ
• حفظ الجلسات
```

---

## 📚 جميع الأوامر

| الأمر | الوصف | مثال |
|------|-------|------|
| `scan` | فحص موقع | `python main.py scan https://example.com` |
| `history` | عرض الفحوصات السابقة | `python main.py history --limit 10` |
| `show` | عرض تفاصيل فحص | `python main.py show <session_id>` |
| `help` | مساعدة سريعة | `python main.py help` |
| `man` | دليل شامل | `python main.py man` |

### خيارات الفحص المتقدمة

```bash
--level {1,2,3,4}          # مستوى الفحص (افتراضي: 4)
--verbose                  # عرض تفاصيل أكثر
--timeout SECONDS          # وقت انتظار الطلب
--user-agent "TEXT"        # User-Agent مخصص
--proxy http://proxy:port  # استخدام بروكسي
--no-ssl-verify            # تجاوز تحقق SSL
--xml report.xml           # تصدير XML
-o prefix                  # بادئة اسم الملفات
```

---

## 📁 هيكل المشروع

```
CyberDev/
├── main.py                # نقطة الدخول
├── cli.py                 # واجهة CLI
├── config.py              # الإعدادات
├── models.py              # نماذج البيانات
│
├── scanner/
│   ├── core/              # المحرك الأساسي
│   ├── recon/             # الاستطلاع
│   └── vulnerabilities/   # فاحصات الثغرات
│
├── report/                # نظام التقارير
├── sessions/              # حفظ الجلسات
└── ui/                    # واجهة المستخدم

```

---

## 🎯 الوضع التفاعلي

```bash
python main.py```

سيعرض قائمة تفاعلية بسيطة لبدء الفحص أو عرض السجلات.

---

## 🔗 المصادر

- [CLI_GUIDE.md](CLI_GUIDE.md) - دليل الأوامر التفصيلي
- [ARCHITECTURE.md](ARCHITECTURE.md) - شرح هيكل المشروع
- [CHANGELOG.md](CHANGELOG.md) - سجل التغييرات

---

## 📧 التواصل

لأي استفسارات أو مساعدة:
- GitHub: [@ahmedalhomili](https://github.com/ahmedalhomili)

---

<div align="center">

**⚡ Made with Python | Educational Use Only ⚡**

</div>
| 3 | Othman | @othmancoc | Security Headers |
| 4 | Wazeer Abdulqawi | @wazeercs | CORS & Reporting |
