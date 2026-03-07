# dnstt DNS Tester

ابزار دو مرحله‌ای برای پیدا کردن DNS Resolverهایی که با تونل [dnstt](https://www.bamsoftware.com/software/dnstt/) کار می‌کنند.

## اسکریپت‌ها

| اسکریپت | کاربرد |
| ----- | ---- |
| `dnstt-dns-liveness.py` | مرحله ۱: پیدا کردن Resolverهایی که پاسخ DNS معتبر می‌دهند (با چک‌های پیشرفته اختیاری) |
| `dnstt-dns-tester.py` | مرحله ۲: اجرای `dnstt-client` برای هر Resolver و تست اتصال واقعی از طریق SOCKS |
| `subtract_ips.py` | ابزار کمکی: تفاضل دو لیست IP به صورت `A - B` |

## پیش‌نیازها

- Python 3.7 یا بالاتر
- باینری `dnstt-client` برای سیستم‌عامل شما
- پکیج‌های `requests`، `PySocks` و وابستگی‌های داخل `requirements.txt`
- `--pubkey` و `--domain` سرور dnstt برای مرحله ۲

## نصب وابستگی‌ها

حالت آنلاین:

```bash
python3 -m pip install -r requirements.txt
```

حالت آفلاین (با wheelهای داخل `vendor/`):

```bash
# Linux/macOS
bash install_deps.sh

# Windows (cmd.exe)
install_deps.bat
```

## مرحله ۱: بررسی زنده بودن DNS

اجرای پایه:

```bash
python3 dnstt-dns-liveness.py \
  --dns-list all_dns.txt \
  --output alive_dns.txt
```

نمونه اجرای چک‌های پیشرفته:

```bash
python3 dnstt-dns-liveness.py \
  --dns-list all_dns.txt \
  --output alive_dns.txt \
  --check-nxdomain \
  --check-edns \
  --check-censorship \
  --censorship-domain facebook.com \
  --censorship-prefix 10.10.
```

گزینه‌های مرحله ۱:

| گزینه | مقدار پیش‌فرض | توضیح |
| ---- | ------- | ----------- |
| `--dns-list` | `dns-servers.txt` | فایل ورودی IPها (هر خط یک IP) |
| `--dns-port` | `53` | پورت DNS |
| `--concurrent` | `50` | حداکثر همزمانی |
| `--timeout` | `5.0` | زمان انتظار هر کوئری |
| `--attempts` | `2` | تعداد تلاش مجدد برای هر Resolver |
| `--output` | `alive_dns_servers.txt` | خروجی Resolverهای زنده |
| `--output-json` | none | خروجی کامل JSON (در چک‌های پیشرفته خودکار فعال می‌شود) |
| `--check-nxdomain` | off | تشخیص NXDOMAIN Hijack |
| `--check-edns` | off | تست پشتیبانی EDNS (512/900/1232) |
| `--check-delegation` | off | تست recursion/delegation برای دامنه تونل |
| `--domain` | none | دامنه موردنیاز برای `--check-delegation` |
| `--filter-delegation` | off | نگه داشتن فقط Resolverهای موفق در delegation |
| `--check-censorship` | off | تشخیص پاسخ‌های سانسورشده (prefix مسدود) |
| `--censorship-domain` | `facebook.com` | دامنه تست سانسور |
| `--censorship-prefix` | `10.10.` | پیشوند IP نشانه سانسور |
| `--filter-censorship` | off | نگه داشتن فقط Resolverهای غیرسانسورشده |
| `--show-failed` | off | نمایش ردیف‌های ناموفق |
| `--no-color` | off | غیرفعال کردن رنگ خروجی |

فایل‌های دسته‌بندی‌شده‌ای که همیشه کنار `--output` ساخته می‌شوند:

- `*_alive_only.txt`
- `*_clean.txt`
- `*_nx_ok.txt`
- `*_ns_ok.txt`

## مرحله ۲: تست اتصال dnstt

```bash
python3 dnstt-dns-tester.py \
  --dnstt ./dnstt-client-linux-amd64 \
  --dns-list alive_dns.txt \
  --pubkey YOUR_PUBLIC_KEY \
  --domain your.dnstt.domain \
  --protocol udp \
  --max-concurrent 3
```

گزینه‌های مرحله ۲:

| گزینه | مقدار پیش‌فرض | توضیح |
| ---- | ------- | ----------- |
| `--dnstt` | `./dnstt-client-linux-amd64` | مسیر باینری `dnstt-client` |
| `--dns-list` | `dns-servers.txt` | فایل ورودی IPها |
| `--pubkey` | required | کلید عمومی سرور dnstt |
| `--domain` | required | دامنه سرور dnstt |
| `--dns-port` | `53` | پورت DNS Resolver |
| `--protocol` | `udp` | یکی از `udp`، `dot`، `doh` |
| `--startup-wait` | `2.0` | زمان انتظار برای بالا آمدن `dnstt-client` |
| `--http-timeout` | `15.0` | زمان انتظار درخواست HTTP |
| `--max-concurrent` | `3` | تعداد تست همزمان |
| `--test-timeout` | `90.0` | timeout کلی هر Resolver |
| `--attempts` | `2` | تعداد تلاش HTTP برای هر Resolver |
| `--test-url` | `https://www.gstatic.com/generate_204` | URL تست اتصال |
| `--output` | `dns_test_results.json` | خروجی کامل JSON |
| `--output-working` | `working_dns_servers.txt` | خروجی IPهای سالم |
| `--show-failed` | off | نمایش موارد ناموفق |
| `--no-color` | off | غیرفعال کردن رنگ خروجی |

## ابزار کمکی: تفاضل لیست IP

```bash
python3 subtract_ips.py <file_A> <file_B> <output_file>
```

این ابزار هر دو فایل را به صورت set می‌خواند و خروجی مرتب‌شده `A - B` را در فایل خروجی می‌نویسد.

## روند پیشنهادی

```bash
# 1) پیدا کردن DNSهای زنده (با فیلتر اختیاری)
python3 dnstt-dns-liveness.py --dns-list all_dns.txt --output alive_dns.txt

# 2) تست عملکرد واقعی dnstt
python3 dnstt-dns-tester.py \
  --dns-list alive_dns.txt \
  --dnstt ./dnstt-client-linux-amd64 \
  --pubkey <pubkey> \
  --domain <domain> \
  --output-working working_dns_servers.txt

# 3) تفاضل دو لیست (اختیاری)
python3 subtract_ips.py alive_dns.txt working_dns_servers.txt remaining.txt
```

## نکته‌ها

- در Linux/macOS هر دو مرحله در صورت امکان سقف file descriptor را افزایش می‌دهند.
- در نسخه فعلی، `dnstt-dns-tester.py` بعد از parse شدن آرگومان‌ها دو خط debug چاپ می‌کند.

## مجوز

MIT
