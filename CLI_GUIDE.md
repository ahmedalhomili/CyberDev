# 📋 دليل الأوامر السريع

## 🎯 جميع الأوامر

| الأمر | الوصف | مثال |
|------|-------|------|
| **scan** | فحص موقع | `python main.py scan https://example.com` |
| **history** | عرض السجلات | `python main.py history` |
| **show** | عرض فحص معين | `python main.py show <id>` |
| **export** | تصدير تقرير | `python main.py export <id> --json` |
| **delete** | حذف جلسة | `python main.py delete <id>` |
| **compare** | مقارنة فحصين | `python main.py compare <id1> <id2>` |
| **version** | معلومات النسخة | `python main.py version` |
| **help** | مساعدة سريعة | `python main.py help` |
| **man** | دليل شامل | `python main.py man` |

---

## 🔧 خيارات أمر SCAN

### الخيارات الأساسية
```bash
--level {1,2,3,4}     # مستوى الفحص (افتراضي: 4)
--verbose, -v         # عرض تفاصيل أكثر
```

### خيارات الشبكة
```bash
--timeout SECONDS     # وقت انتظار الطلب (افتراضي: 10)
--user-agent "TEXT"   # User-Agent مخصص
--proxy URL           # استخدام بروكسي
--no-ssl-verify       # تجاوز تحقق SSL
```

### خيارات التصدير
```bash
--xml FILE            # تصدير XML
-o, --output PREFIX   # بادئة اسم الملفات
```

---

## 📚 خيارات أمر HISTORY

```bash
--limit N             # عرض N فحص فقط
--sort newest|oldest|findings  # ترتيب النتائج
--filter PATTERN      # تصفية بنص معين
--show-all            # عرض كل التفاصيل
```

---

## 📤 خيارات أمر EXPORT

```bash
--json                # تصدير JSON
--markdown            # تصدير Markdown
--html                # تصدير HTML
--csv                 # تصدير CSV
--xml                 # تصدير XML
-a, --all             # تصدير جميع الصيغ
```

---

## 🗑️ خيارات أمر DELETE

```bash
--all                 # حذف جميع الجلسات
--older-than DAYS     # حذف أقدم من X يوم
-f, --force           # بدون تأكيد
```

---

## 🔍 خيارات أمر COMPARE

```bash
--format cli|json|html  # صيغة المقارنة
-o, --output FILE       # حفظ في ملف
```

---

## 💡 أمثلة عملية

### فحص بسيط
```bash
python main.py scan https://example.com
```

### فحص متقدم
```bash
python main.py scan https://example.com --level 3 --timeout 15 --verbose
```

### فحص عبر بروكسي
```bash
python main.py scan https://example.com --proxy http://127.0.0.1:8080
```

### عرض آخر 5 فحوصات
```bash
python main.py history --limit 5 --sort newest
```

### تصدير تقرير بجميع الصيغ
```bash
python main.py export <session_id> -a
```

### مقارنة فحصين
```bash
python main.py compare <id1> <id2> --format html -o comparison.html
```

### حذف جلسات قديمة
```bash
python main.py delete --older-than 30 --force
```

---

## 📖 للمزيد

- **README.md** - دليل الاستخدام الأساسي
- **ARCHITECTURE.md** - شرح هيكل المشروع للمطورين
- **CHANGELOG.md** - سجل التغييرات
