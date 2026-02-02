# 🕵️ Recon Module - الاستطلاع والاستخبارات

هذا المجلد مسؤول عن **جمع المعلومات** عن الهدف قبل بدء الفحص العميق للثغرات.

---

## 📋 الملفات الرئيسية

### 1. ⭐ **recon_analyzer.py** - المحلل الرئيسي
**الوظيفة:** تنسيق جميع عمليات الاستطلاع

**ماذا يفعل؟**
```python
- جمع معلومات Whois (المسجل، تاريخ الإنشاء)
- تحليل DNS (SPF, DMARC)
- فحص البورتات المفتوحة
- اكتشاف التقنيات المستخدمة
- تحديد الموقع الجغرافي (IP-API)
- الكشف عن مزود الاستضافة (AWS, Azure, GCP, Cloudflare)
- اكتشاف CDN & WAF
- فحص شهادة SSL/TLS
```

**الاستخدام:**
```python
from scanner.recon.recon_analyzer import ReconAnalyzer

analyzer = ReconAnalyzer()
data = analyzer.analyze("https://example.com")

print(data.ip_address)        # "93.184.216.34"
print(data.open_ports)        # [80, 443]
print(data.technologies)      # ["Apache", "PHP"]
```

---

### 2. 🕷️ **link_crawler.py** - زاحف الروابط
**الوظيفة:** اكتشاف URLs مع parameters للفحص

**لماذا مهم؟**
معظم الثغرات تحتاج parameters:
```
✅ /page.php?id=1        # SQLi, XSS, LFI
✅ /search.php?q=test    # XSS, SSTI
❌ /about.html           # لا يوجد parameters
```

**كيف يعمل؟**
```
1. يزحف الموقع من الصفحة الرئيسية
2. يستخرج روابط من:
   - <a href="...">
   - <form action="...">
3. يفلتر الروابط التي فيها ?parameter=value
4. يزحف حتى عمق 2 مستويات (30 صفحة)
5. يرجع قائمة بـ URLs القابلة للفحص
```

**مثال:**
```python
from scanner.recon.link_crawler import LinkCrawler

crawler = LinkCrawler(max_depth=2, max_urls=30)
crawled = crawler.crawl("https://testphp.vulnweb.com")

# النتيجة:
[
    {
        'url': 'https://testphp.vulnweb.com/artists.php?artist=1',
        'params': ['artist'],
        'depth': 1
    },
    {
        'url': 'https://testphp.vulnweb.com/listproducts.php?cat=1',
        'params': ['cat'],
        'depth': 1
    }
]

# استخدام في Orchestrator:
testable_urls = crawler.get_testable_urls(limit=15)
for url in testable_urls:
    sqli_scanner.scan(url)  # يفحص SQLi على كل URL
    xss_scanner.scan(url)   # يفحص XSS على كل URL
```

**الإعدادات:**
```python
LinkCrawler(
    max_depth=2,     # كم مستوى يزحف (1, 2, 3, ...)
    max_urls=30      # كم صفحة يزور كحد أقصى
)
```

**الدوال:**
- `crawl(url)` - يبدأ الزحف
- `get_testable_urls(limit)` - يرجع URLs مع parameters
- `_extract_links(soup)` - يستخرج روابط من HTML
- `_is_same_domain(url)` - يتأكد من نفس الموقع

---

### 3. **headers_analyzer.py** - تحليل HTTP Headers
**الوظيفة:** فحص Security Headers

**يفحص:**
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy

---

### 4. **cors_analyzer.py** - فحص CORS
**الوظيفة:** اكتشاف سياسات CORS الخطيرة

**يبحث عن:**
- `Access-Control-Allow-Origin: *` مع credentials
- Reflected origin headers
- Null origin bypass

---

### 5. **https_check.py** - فحص HTTPS
**الوظيفة:** التحقق من HTTPS و SSL

**يفحص:**
- هل HTTPS مفعّل؟
- شهادة SSL صالحة؟
- إعادة التوجيه من HTTP → HTTPS

---

### 6. **robots_check.py** - تحليل robots.txt
**الوظيفة:** قراءة robots.txt

**يستخرج:**
- Sitemap URLs
- Disallowed paths (قد تكون حساسة)
- User-agent directives

---

### 7. **explore_fuzzer.py** - اكتشاف المجلدات
**الوظيفة:** البحث عن ملفات ومجلدات مخفية

**يبحث عن:**
```
/admin/
/backup/
/config.php
/.git/
/.env
/phpinfo.php
```

---

### 8. **content_analyzer.py** - تحليل المحتوى
**الوظيفة:** تحليل محتوى الصفحة

**يبحث عن:**
- Email addresses (تسريب بيانات)
- Comments في HTML (قد تحتوي معلومات حساسة)
- Keywords (passwords, api_key, etc.)

---

## 🔄 سير العمل

```
Scanner Orchestrator
        ↓
1. ReconAnalyzer.analyze(url)
        ↓
   ├─► Whois lookup
   ├─► DNS analysis
   ├─► Port scanning
   ├─► SSL check
   ├─► Geolocation
   └─► Tech detection
        ↓
2. LinkCrawler.crawl(url)  ⭐
        ↓
   ├─► Crawls website
   ├─► Extracts links
   └─► Filters URLs with parameters
        ↓
   Returns: testable_urls = [
       "/page.php?id=1",
       "/search.php?q=test"
   ]
        ↓
3. Vulnerability Scanners
   Loop: for url in testable_urls:
       sqli_scanner.scan(url)
       xss_scanner.scan(url)
       lfi_scanner.scan(url)
```

---

## 💡 مثال كامل

### السيناريو: فحص testphp.vulnweb.com

```python
# 1. Reconnaissance
analyzer = ReconAnalyzer()
recon = analyzer.analyze("http://testphp.vulnweb.com")

print(recon.ip_address)      # "44.228.249.3"
print(recon.server_os)       # "Linux (nginx)"
print(recon.open_ports)      # [80, 443]

# 2. Link Crawling
crawler = LinkCrawler(max_depth=2, max_urls=30)
crawled = crawler.crawl("http://testphp.vulnweb.com")

print(f"Crawled {len(crawled)} URLs")
# Output: Crawled 25 URLs

testable = crawler.get_testable_urls(limit=10)
print(testable)
# Output:
# [
#   "http://testphp.vulnweb.com/artists.php?artist=1",
#   "http://testphp.vulnweb.com/listproducts.php?cat=1",
#   "http://testphp.vulnweb.com/guestbook.php",
#   ...
# ]

# 3. Vulnerability Scanning (في Orchestrator)
from scanner.vulnerabilities.vuln_sqli import SQLiScanner

sqli = SQLiScanner()
for url in testable:
    findings = sqli.scan(url)
    if findings:
        print(f"[!] SQLi found in {url}")
        
# Output:
# [!] SQLi found in http://testphp.vulnweb.com/artists.php?artist=1
# [!] SQLi found in http://testphp.vulnweb.com/listproducts.php?cat=1
```

---

## 📊 مخرجات ReconData

```python
@dataclass
class ReconData:
    ip_address: str                    # "93.184.216.34"
    domain_info: Dict                  # Whois data
    server_os: str                     # "Ubuntu Linux"
    technologies: List[str]            # ["Apache", "PHP"]
    open_ports: List[int]              # [80, 443, 22]
    dns_security: Dict                 # SPF, DMARC
    subdomains: List[str]              # ["www", "api", "admin"]
    
    # Dynamic fields (added via __dict__):
    geolocation: Dict                  # City, Country, ISP
    hosting_provider: Dict             # AWS, Azure, etc.
    cdn_waf: Dict                      # Cloudflare, Akamai
    ssl_info: Dict                     # Certificate details
```

---

## 🛠️ للمطورين: إضافة تقنية استطلاع جديدة

### مثال: إضافة "Subdomain Enumeration"

```python
# في recon_analyzer.py:

def _enumerate_subdomains(self, domain: str) -> List[str]:
    """Enumerate subdomains using various techniques."""
    subdomains = []
    
    try:
        # 1. crt.sh API
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=10)
        data = resp.json()
        
        for entry in data:
            name = entry['name_value']
            if name not in subdomains:
                subdomains.append(name)
        
        # 2. DNS bruteforce (optional)
        common_subs = ['www', 'api', 'admin', 'mail', 'ftp']
        for sub in common_subs:
            try:
                full = f"{sub}.{domain}"
                socket.gethostbyname(full)
                subdomains.append(full)
            except:
                pass
    
    except Exception as e:
        logger.debug(f"Subdomain enumeration error: {e}")
    
    return subdomains
```

---

## 🎯 Best Practices

### ✅ افعل:
- استخدم timeout قصير (5-10 ثانية)
- أضف try-except لكل عملية
- log الأخطاء بـ `logger.debug()`
- تأكد من نفس الـ domain (في Crawler)

### ❌ لا تفعل:
- لا تزحف خارج الموقع المستهدف
- لا ترسل آلاف الطلبات
- لا تستخدم threads بدون rate limiting

---

## 📚 مراجع

- **Whois:** `python-whois` library
- **DNS:** `dnspython` library
- **Geolocation:** [ip-api.com](https://ip-api.com)
- **SSL:** `ssl` & `certifi` libraries
- **Web Crawling:** `BeautifulSoup4`

---

## 📞 للمزيد

- **هيكل المشروع:** [../ARCHITECTURE.md](../ARCHITECTURE.md)
- **دليل التطوير:** [../DEVELOPMENT_GUIDE.md](../DEVELOPMENT_GUIDE.md)
- **Scanner README:** [../README.md](../README.md)
