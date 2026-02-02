# 🔍 كيف يعمل اكتشاف الـ Parameters؟

دليل سريع لفهم آلية Link Crawler في CyberDev Scanner.

---

## ❓ السؤال الشائع

**"إذا أدخلت رابط بسيط مثل `https://example.com`، كيف يعرف الماسح الـ parameters (`?id=1`) لفحص الثغرات؟"**

---

## ✅ الجواب: Link Crawler 🕷️

### المشكلة:
معظم الثغرات تحتاج parameters:
```
✅ /page.php?id=1        → قابل لفحص SQLi, XSS, LFI
✅ /search.php?q=test    → قابل لفحص XSS, SSTI
❌ /about.html           → بدون parameters، لا يمكن الفحص
```

### الحل:
**Link Crawler** يزحف الموقع تلقائياً ويكتشف URLs مع parameters!

---

## 🔄 كيف يعمل؟ (5 خطوات)

### 1️⃣ أنت تدخل URL بسيط
```
Input: https://example.com
```

### 2️⃣ Crawler يفتح الصفحة الرئيسية
```html
<!DOCTYPE html>
<html>
<body>
  <a href="/page.php?id=1">Page 1</a>
  <a href="/search.php?q=test">Search</a>
  <a href="/about.html">About</a>
  <form action="/login.php?redirect=home">...</form>
</body>
</html>
```

### 3️⃣ يستخرج جميع الروابط
```python
discovered_links = [
    "https://example.com/page.php?id=1",
    "https://example.com/search.php?q=test",
    "https://example.com/about.html",
    "https://example.com/login.php?redirect=home"
]
```

### 4️⃣ يفلتر الروابط التي فيها parameters
```python
from urllib.parse import urlparse, parse_qs

for link in discovered_links:
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    
    if params:  # إذا فيه ?param=value
        testable_urls.append(link)

# النتيجة:
testable_urls = [
    "https://example.com/page.php?id=1",        # ✓ فيه ?id=
    "https://example.com/search.php?q=test",    # ✓ فيه ?q=
    "https://example.com/login.php?redirect=home" # ✓ فيه ?redirect=
    # about.html تم تجاهله (بدون parameters)
]
```

### 5️⃣ الفاحصات تختبر كل URL
```python
# في scanner_orchestrator.py:
for url in testable_urls:
    # فحص SQLi
    sqli_scanner.scan(url)
    # يجرب:
    # - page.php?id=1' OR '1'='1
    # - page.php?id=1' AND SLEEP(5)--
    
    # فحص XSS
    xss_scanner.scan(url)
    # يجرب:
    # - search.php?q=<script>alert(1)</script>
    # - search.php?q=<img src=x onerror=alert(1)>
    
    # فحص LFI
    lfi_scanner.scan(url)
    # يجرب:
    # - page.php?id=../../etc/passwd
    # - page.php?id=..\\..\\windows\\win.ini
```

---

## 💻 الكود الفعلي

### في `link_crawler.py`:
```python
class LinkCrawler:
    def __init__(self, max_depth=2, max_urls=30):
        self.max_depth = max_depth    # كم مستوى يزحف
        self.max_urls = max_urls      # كم صفحة يزور
    
    def crawl(self, base_url):
        """يزحف الموقع ويكتشف URLs."""
        self._crawl_recursive(base_url, depth=0)
        return self.discovered_urls
    
    def _crawl_recursive(self, url, depth):
        """يزحف بشكل متكرر."""
        if depth > self.max_depth:
            return
        
        # 1. افتح الصفحة
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 2. استخرج الروابط
        for tag in soup.find_all('a', href=True):
            link = urljoin(url, tag['href'])
            
            # 3. فلتر: فقط الروابط مع parameters
            params = parse_qs(urlparse(link).query)
            if params:
                self.discovered_urls.append({
                    'url': link,
                    'params': list(params.keys()),
                    'depth': depth + 1
                })
            
            # 4. استمر بالزحف
            if depth < self.max_depth:
                self._crawl_recursive(link, depth + 1)
    
    def get_testable_urls(self, limit=15):
        """يرجع URLs القابلة للفحص."""
        return [item['url'] for item in self.discovered_urls[:limit]]
```

### في `scanner_orchestrator.py`:
```python
class SecurityScanner:
    def __init__(self):
        self.link_crawler = LinkCrawler(max_depth=2, max_urls=30)
        self.sqli_scanner = SQLiScanner()
        self.xss_scanner = XSSScanner()
        # ...
    
    def scan(self, url):
        # 1. Reconnaissance
        recon = self.recon_analyzer.analyze(url)
        
        # 2. Link Crawling ⭐
        logger.info("Starting link crawler...")
        crawled = self.link_crawler.crawl(url)
        testable_urls = self.link_crawler.get_testable_urls(limit=15)
        
        logger.info(f"Found {len(testable_urls)} testable URLs")
        
        # إذا ما لقى URLs، استخدم الـ URL الأساسي
        if not testable_urls:
            testable_urls = [url]
        
        # 3. Vulnerability Scanning
        findings = []
        for test_url in testable_urls:
            findings.extend(self.sqli_scanner.scan(test_url))
            findings.extend(self.xss_scanner.scan(test_url))
            findings.extend(self.lfi_scanner.scan(test_url))
            # ... باقي الفاحصات
        
        return ScanResult(findings=findings, ...)
```

---

## 📊 مثال عملي

### المدخل:
```bash
python main.py
Enter URL: https://testphp.vulnweb.com
```

### مخرجات الـ Logs:
```
[INFO] Starting link crawler...
[DEBUG] Crawling: https://testphp.vulnweb.com/
[DEBUG] Found link: /artists.php?artist=1
[DEBUG] Discovered testable URL: /artists.php?artist=1 ✓
[DEBUG] Found link: /listproducts.php?cat=1
[DEBUG] Discovered testable URL: /listproducts.php?cat=1 ✓
[DEBUG] Found link: /about.php
[DEBUG] Ignored (no parameters): /about.php

[INFO] Crawler found 25 URLs, 8 testable URLs

[INFO] [✓] Scanning for SQL Injection...
[INFO] [SQLi] Testing: /artists.php?artist=1
[INFO] [SQLi] Payload: artist=1' OR '1'='1
[WARNING] [SQLi] ⚠️ SQL Injection detected!

[INFO] [✓] Scanning for XSS...
[INFO] [XSS] Testing: /artists.php?artist=1
[INFO] [XSS] Payload: artist=<script>alert(1)</script>
```

### النتيجة:
```
═══════════════════════════════════════════════
[ 📊 SUMMARY OF FINDINGS ]
──────────────────────────────
  🔴 HIGH    : 2
  🟠 MEDIUM  : 1
  🔵 LOW     : 3
  📊 TOTAL   : 6
═══════════════════════════════════════════════

[HIGH] SQL Injection Detected
───────────────────────────────
Location: /artists.php?artist=1
Description: Boolean-based blind SQLi
Fix: Use parameterized queries
```

---

## ⚙️ الإعدادات

### تخصيص Crawler:
```python
# في scanner_orchestrator.py (السطر 53):
self.link_crawler = LinkCrawler(
    max_depth=3,     # زيادة العمق (1, 2, 3, ...)
    max_urls=50      # زيادة عدد الصفحات
)

# في السطر 190:
testable_urls = crawler.get_testable_urls(limit=20)  # زيادة الحد
```

### متى تزيد الإعدادات؟
- ✅ موقع كبير ومعقد → `max_depth=3, max_urls=100`
- ✅ موقع صغير بسيط → `max_depth=1, max_urls=20`

---

## 🎯 ماذا لو لم يجد URLs؟

```python
if not testable_urls:
    logger.warning("No URLs with parameters found")
    testable_urls = [url]  # يستخدم الـ URL الأساسي فقط

# النتيجة:
# معظم الفاحصات لن تجد شيء لأنه بدون parameters
```

**الحل:**
- تأكد أن الموقع فيه روابط مع parameters
- جرب موقع تجريبي: `http://testphp.vulnweb.com`
- زود `max_depth` و `max_urls`

---

## 🔍 Debugging

### شاهد ماذا يكتشف Crawler:
```python
# أضف في scanner_orchestrator.py:
logger.setLevel(logging.DEBUG)

# سيظهر:
[DEBUG] Crawling: https://example.com/page1.php
[DEBUG] Found link: /page2.php?id=10
[DEBUG] Discovered testable URL: /page2.php?id=10
[DEBUG] Found link: /page3.html
[DEBUG] Ignored: /page3.html (no parameters)
```

---

## 📚 الملفات ذات العلاقة

| الملف | الوظيفة |
|-------|---------|
| `scanner/recon/link_crawler.py` | زحف وفلترة URLs |
| `scanner/core/scanner_orchestrator.py` | استدعاء Crawler وتمرير URLs للفاحصات |
| `scanner/vulnerabilities/vuln_*.py` | فحص كل URL |

---

## 💡 ملخص سريع

```
🎯 المشكلة: معظم الثغرات تحتاج parameters
✅ الحل: Link Crawler يكتشفها تلقائياً
🔄 الآلية:
   1. زحف الموقع
   2. استخراج الروابط
   3. فلترة URLs مع parameters
   4. الفاحصات تختبر كل URL
📊 النتيجة: كشف شامل للثغرات بدون إدخال يدوي!
```

---

**🎉 الآن فهمت كيف يكتشف CyberDev الـ parameters تلقائياً!**
