#!/usr/bin/env python3
# OmniBuster v7 - By Emerick-19
# Framework offensif modulaire tout-en-un
#
# Dépendances : aiohttp tqdm colorama
#   pip install aiohttp tqdm colorama
# Optionnel : nuclei, dalfox, sqlmap

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
# IMPORT DU CŒUR v6 (repris intégralement, on ne réaffiche que les sections
# NOUVELLES ou MODIFIÉES pour la v7)
# ===========================================================================

# --- Encodeurs, PayloadFactory, signatures : identiques v6 ---
# Pour la concision, je ne réaffiche pas ces blocs. Reprends-les tels quels
# depuis OmniBuster v6.

# ... [ENCODEURS v6] ...
# ... [PayloadFactory v6] ...
# ... [SIGNATURES v6] ...

# ===========================================================================
# NOUVEAU v7 - SECTION A : CONFIG ÉTENDUE
# ===========================================================================

@dataclass
class ScanConfig:
    # --- v6 fields ---
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
    fuzz_position: str = "URL"
    custom_payload_file: Optional[str] = None
    use_sqlmap: bool = False
    resume_file: Optional[str] = None
    batch_size: int = 500

    # --- NOUVEAU v7 ---
    targets_file: Optional[str] = None
    http2: bool = False
    use_nuclei: bool = False
    nuclei_templates: Optional[str] = None
    use_dalfox: bool = False
    dalfox_args: Optional[str] = None
    checkpoint_interval: int = 50
    json_body: Optional[str] = None      # Pour fuzz JSON
    json_fuzz_key: Optional[str] = None  # Clé JSON à fuzzer

# ===========================================================================
# NOUVEAU v7 - SECTION B : CHECKPOINT / RESUME
# ===========================================================================

class Checkpoint:
    """Sauvegarde la progression sur disque pour reprendre un scan interrompu."""

    def __init__(self, path: str):
        self.path = path
        self.data = self._load()
        self._dirty = False

    def _load(self) -> dict:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def is_done(self, key: str) -> bool:
        return key in self.data.get("done", [])

    def mark_done(self, key: str):
        self.data.setdefault("done", []).append(key)
        self._dirty = True
        if len(self.data["done"]) % 50 == 0:
            self.flush()

    def add_finding(self, finding: dict):
        self.data.setdefault("findings", []).append(finding)
        self._dirty = True

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
# NOUVEAU v7 - SECTION C : HTTP CLIENT v7 (HTTP/2 + rotation proxy améliorée)
# ===========================================================================

class HTTPClient:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.sem = asyncio.Semaphore(config.concurrency)
        self.session: Optional[aiohttp.ClientSession] = None
        self._last_request = 0.0
        self._ua_index = 0
        self.proxy_pool = ProxyPool(config.proxy, config.proxy_file)
        self._session_lock = asyncio.Lock()

    async def __aenter__(self):
        await self._build_session()
        return self

    async def _build_session(self):
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
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=self.config.concurrency * 2,
            force_close=not self.config.http2,
        )
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector, timeout=timeout,
            cookies=self.config.cookies or None,
            headers=headers,
        )
        self._default_headers = headers

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
                                "http_version": resp.version,
                            } if read_body else {
                                "headers": dict(resp.headers),
                                "http_version": resp.version,
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
# NOUVEAU v7 - SECTION D : CACHE POISONING / WEB CACHE DECEPTION
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

CACHE_UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
    "X-Host", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Prefix",
    "X-HTTP-Method-Override", "X-Forwarded-For",
]

async def scan_cache_poisoning(client, config, reporter):
    """Détecte si des headers non-keyed (unkeyed) sont reflétés et cachés."""
    print(f"\n{C_BOLD}=== Cache Poisoning / Web Cache Deception ==={C_END}")
    target = config.target
    marker = "omni_" + "".join(random.choices(string.ascii_lowercase, k=8))

    # 1) Test basique : reflète-t-il un header non-keyed ?
    for header, value in CACHE_POISON_HEADERS:
        poisoned = value + "." + marker + ".com"
        res = await client.request("GET", target, headers={header: poisoned},
                                   read_body=True, allow_redirects=False)
        if not res: continue
        body = res.extra.get("body", "")
        headers = res.extra.get("headers", {})
        if marker in body or marker in str(headers):
            reporter.report_finding("Cache-Poison-Reflect",
                f"Header {header}: {poisoned} reflété", "high", target)

    # 2) Test cache deception : ajouter extension statique à URL dynamique
    parsed = urlparse(target)
    if not parsed.path.endswith(("/", ".css", ".js", ".jpg", ".png")):
        deception_url = target + "/nonexistent" + marker + ".css"
        res = await client.request("GET", deception_url, read_body=True)
        if res and res.status == 200:
            # Vérifier si la réponse ressemble à du contenu dynamique
            ct = res.extra.get("headers", {}).get("Content-Type", "")
            if "css" not in ct.lower():
                reporter.report_finding("Cache-Deception",
                    f"{deception_url} retourne 200 sans Content-Type CSS", "medium", deception_url)

    # 3) Test de cache header
    res = await client.request("GET", target, headers={"Cache-Control": "no-cache"},
                               read_body=False, allow_redirects=False)
    if res:
        h = res.extra.get("headers", {})
        age = h.get("Age", "0")
        xcache = h.get("X-Cache", h.get("X-Cache-Status", ""))
        cf = h.get("CF-Cache-Status", "")
        if xcache or cf or (age and age != "0"):
            reporter.report_finding("Cache-Header",
                f"Cache détecté: X-Cache={xcache}, CF-Cache={cf}, Age={age}", "info", target)

# ===========================================================================
# NOUVEAU v7 - SECTION E : JSON BODY FUZZING
# ===========================================================================

async def scan_json_fuzz(client, config, reporter, json_template, fuzz_key):
    """
    Fuzz une clé JSON en envoyant POST application/json.
    json_template : dict ou str JSON avec les paramètres.
    fuzz_key : clé à remplacer par les payloads.
    """
    print(f"\n{C_BOLD}=== JSON Body Fuzzing (key={fuzz_key}) ==={C_END}")
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
        ("XSS-JSON", PayloadFactory.xss(count=count, obfuscate=obfuscate), None),
        ("SSTI-JSON", PayloadFactory.ssti(), PayloadFactory.SSTI_SIGNATURES),
        ("CMDi-JSON", PayloadFactory.cmdi(), PayloadFactory.CMDI_SIGNATURES),
    ]

    for cat_name, payloads, sigs in categories:
        for payload in payloads:
            data = dict(template)
            data[fuzz_key] = payload
            res = await client.request("POST", base_url, json_data=data,
                                       read_body=True, allow_redirects=False,
                                       headers={"Content-Type": "application/json"})
            if not res: continue
            body = res.extra.get("body", "")

            if sigs:
                for sig in sigs:
                    if re.search(sig, body, re.IGNORECASE):
                        reporter.report_finding(cat_name,
                            f"key={fuzz_key} payload={payload!r}", "high", base_url)
                        break
            else:
                # XSS reflection check
                marker = "".join(random.choices(string.ascii_letters, k=6))
                test_data = dict(template); test_data[fuzz_key] = marker + payload
                r2 = await client.request("POST", base_url, json_data=test_data,
                                          read_body=True, allow_redirects=False)
                if r2 and payload in r2.extra.get("body", "") and marker in r2.extra.get("body", ""):
                    reporter.report_finding("XSS-JSON",
                        f"key={fuzz_key} payload={payload!r}", "medium", base_url)
                    break

# ===========================================================================
# NOUVEAU v7 - SECTION F : MULTI-TARGET
# ===========================================================================

async def process_target(target: str, args, base_config: ScanConfig) -> Tuple[str, Optional[Reporter]]:
    """Exécute le scan complet sur une cible (utilisé en mode multi-target)."""
    # Copie la config en changeant la cible
    cfg = ScanConfig(**{**asdict(base_config), "target": target})

    # Checkpoint dédié par cible
    ckpt = None
    if cfg.resume_file:
        safe = re.sub(r'[^A-Za-z0-9_-]', '_', target)
        ckpt_path = f"{cfg.resume_file}.{safe}.json"
        ckpt = Checkpoint(ckpt_path)
        if ckpt.data.get("completed"):
            print(f"{C_YELLOW}[SKIP] {target} (déjà complété){C_END}")
            return target, None

    reporter = Reporter(cfg)

    try:
        async with HTTPClient(cfg) as client:
            # WAF detection
            wafs = await detect_waf(client, cfg.target)
            if wafs:
                print(f"{C_RED}[{target}] WAF: {', '.join(wafs)}{C_END}")

            mode = args.mode

            if mode == "all" or mode == "auto":
                await scan_security_headers(client, cfg, reporter)
                await scan_cookies(client, cfg, reporter)
                await scan_cors(client, cfg, reporter)
                await scan_verbs(client, cfg, reporter)
                await scan_graphql(client, cfg, reporter)
                await scan_cache_poisoning(client, cfg, reporter)
                await scan_sensitive_files(client, cfg, reporter)

                get_params, post_params = await extract_params(client, cfg)
                if get_params:
                    await scan_vulns(client, cfg, reporter, get_params)
                if post_params:
                    await scan_post_vulns(client, cfg, reporter, post_params)
            else:
                # Réutilise run_scan_legacy en changeant juste le mode
                await run_single_mode(client, cfg, reporter, args)

        if ckpt:
            ckpt.data["completed"] = True
            ckpt.flush()

        return target, reporter
    except Exception as e:
        print(f"{C_RED}[{target}] Erreur: {e}{C_END}")
        return target, reporter


async def run_multi_target(args, base_config: ScanConfig):
    targets = load_wordlist(base_config.targets_file)
    if not targets:
        print(f"{C_RED}[-] Aucune cible dans {base_config.targets_file}{C_END}")
        sys.exit(1)

    print(f"{C_CYAN}[*] {len(targets)} cible(s) à scanner{C_END}")

    sem = asyncio.Semaphore(5)  # 5 targets en parallèle

    async def bounded(t):
        async with sem:
            return await process_target(t, args, base_config)

    results = await asyncio.gather(*[bounded(t) for t in targets])

    # Rapport consolidé
    print(f"\n{C_MAGENTA}{C_BOLD}=== RAPPORT CONSOLIDÉ ==={C_END}")
    all_findings = []
    for target, reporter in results:
        if reporter:
            all_findings.extend(reporter.findings)
            print(f"  {target}: {len(reporter.findings)} findings")
        else:
            print(f"  {target}: (skipped)")

    # Génère un rapport HTML global si demandé
    if base_config.html_report:
        write_global_html_report(base_config.html_report, all_findings, targets)
        print(f"\n{C_GREEN}[+] Rapport global: {base_config.html_report}{C_END}")


def write_global_html_report(path, findings, targets):
    sev_colors = {"critical": "#8b0000", "high": "#d9534f",
                  "medium": "#f0ad4e", "low": "#5bc0de", "info": "#5cb85c"}
    rows = ""
    for f in sorted(findings, key=lambda x: ["info", "low", "medium", "high", "critical"].index(x["severity"]), reverse=True):
        rows += f"""<tr style="background:{sev_colors.get(f['severity'], '#fff')};color:#fff">
            <td>{f['severity'].upper()}</td><td>{html.escape(f['category'])}</td>
            <td>{html.escape(f.get('url',''))}</td><td>{html.escape(f['detail'])}</td></tr>"""
    content = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>OmniBuster v7 - Rapport global</title>
<style>body{{font-family:Arial;margin:20px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px}}th{{background:#333;color:#fff}}</style></head><body>
<h1>OmniBuster v7 — Rapport global</h1>
<p><b>Cibles :</b> {len(targets)} | <b>Findings :</b> {len(findings)}</p>
<table><tr><th>Sévérité</th><th>Catégorie</th><th>URL</th><th>Détail</th></tr>
{rows}</table></body></html>"""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    except OSError:
        pass

# ===========================================================================
# NOUVEAU v7 - SECTION G : INTÉGRATION NUCLEI
# ===========================================================================

def run_nuclei(target: str, templates: Optional[str] = None, extra_args: Optional[str] = None):
    if not shutil.which("nuclei"):
        print(f"{C_YELLOW}[*] nuclei introuvable, skip.{C_END}")
        return []
    outfile = tempfile.mktemp(suffix=".jsonl", prefix="nuclei_")
    cmd = ["nuclei", "-u", target, "-jsonl", "-o", outfile, "-silent",
           "-no-color", "-stats", "-timeout", "10", "-retries", "2"]
    if templates:
        cmd += ["-t", templates]
    if extra_args:
        cmd += extra_args.split()
    print(f"{C_CYAN}[nuclei] {' '.join(cmd)}{C_END}")
    try:
        subprocess.run(cmd, timeout=1800, check=False)
    except subprocess.TimeoutExpired:
        print(f"{C_RED}[nuclei] Timeout{C_END}")

    findings = []
    if os.path.exists(outfile):
        try:
            with open(outfile) as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        findings.append({
                            "template": data.get("template-id"),
                            "name": data.get("info", {}).get("name"),
                            "severity": data.get("info", {}).get("severity", "info"),
                            "matched": data.get("matched-at"),
                            "type": "nuclei",
                        })
                    except json.JSONDecodeError:
                        continue
        finally:
            try: os.remove(outfile)
            except OSError: pass
    return findings

# ===========================================================================
# NOUVEAU v7 - SECTION H : INTÉGRATION DALFOX
# ===========================================================================

def run_dalfox(url: str, extra_args: Optional[str] = None):
    if not shutil.which("dalfox"):
        print(f"{C_YELLOW}[*] dalfox introuvable, skip.{C_END}")
        return []
    outfile = tempfile.mktemp(suffix=".json", prefix="dalfox_")
    cmd = ["dalfox", "url", url, "--format", "json", "--output", outfile,
           "--no-color", "--silence", "--worker", "10"]
    if extra_args:
        cmd += extra_args.split()
    print(f"{C_CYAN}[dalfox] {' '.join(cmd)}{C_END}")
    try:
        subprocess.run(cmd, timeout=900, check=False)
    except subprocess.TimeoutExpired:
        print(f"{C_RED}[dalfox] Timeout{C_END}")

    findings = []
    if os.path.exists(outfile):
        try:
            with open(outfile) as f:
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            findings.append({
                                "type": "dalfox",
                                "url": item.get("url"),
                                "payload": item.get("payload"),
                                "type_vuln": item.get("type"),
                            })
                except json.JSONDecodeError:
                    pass
        finally:
            try: os.remove(outfile)
            except OSError: pass
    return findings

# ===========================================================================
# NOUVEAU v7 - SECTION I : DISPATCHER UNIFIÉ (run_single_mode)
# ===========================================================================

async def run_single_mode(client, config, reporter, args):
    """Dispatch vers le bon scanner en fonction du mode."""
    mode = args.mode
    if mode == "dir":
        if not args.wordlist: return
        wl = load_wordlist(args.wordlist)
        wildcard = await detect_wildcard(client, config.target)
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
        pp = args.post_params or []
        if args.auto_params:
            _, gp = await extract_params(client, config)
            pp = sorted(set(pp + gp))
        if pp:
            await scan_post_vulns(client, config, reporter, pp)
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
        paths = args.params or ["admin", "backup", "uploads", "files"]
        await scan_dir_listing(client, config, reporter, paths)
    elif mode == "jwt":
        if args.jwt_token:
            await scan_jwt(client, config, reporter, [args.jwt_token])
    elif mode == "graphql":
        await scan_graphql(client, config, reporter)
    elif mode == "cache":
        await scan_cache_poisoning(client, config, reporter)
    elif mode == "json":
        if args.json_body and args.json_fuzz_key:
            await scan_json_fuzz(client, config, reporter, args.json_body, args.json_fuzz_key)

    # Intégrations externes optionnelles
    if config.use_nuclei:
        print(f"\n{C_CYAN}[*] Lancement de Nuclei...{C_END}")
        nuclei_findings = run_nuclei(config.target, config.nuclei_templates)
        for f in nuclei_findings:
            reporter.report_finding("Nuclei",
                f"[{f.get('severity','info')}] {f.get('name')} -> {f.get('matched')}",
                f.get("severity", "info"), config.target)

    if config.use_dalfox:
        print(f"\n{C_CYAN}[*] Lancement de Dalfox...{C_END}")
        dalfox_findings = run_dalfox(config.target, config.dalfox_args)
        for f in dalfox_findings:
            reporter.report_finding("Dalfox",
                f"XSS {f.get('type_vuln')} payload={f.get('payload')}",
                "medium", config.target)

# ===========================================================================
# NOUVEAU v7 - SECTION J : RUN_SCAN (point d'entrée)
# ===========================================================================

async def run_scan_v7(args):
    config = build_config(args)
    reporter = Reporter(config)

    # Multi-target
    if config.targets_file:
        await run_multi_target(args, config)
        return

    # Single-target
    async with HTTPClient(config) as client:
        print(f"{C_YELLOW}[*] Détection WAF...{C_END}")
        wafs = await detect_waf(client, config.target)
        if wafs:
            print(f"{C_RED}[!] WAF: {', '.join(wafs)}{C_END}")
        else:
            print(f"{C_GREEN}[+] Aucun WAF évident.{C_END}")

        await run_single_mode(client, config, reporter, args)

    reporter.summary()

# ===========================================================================
# NOUVEAU v7 - SECTION K : CLI ÉTENDUE
# ===========================================================================

def build_parser_v7():
    parser = argparse.ArgumentParser(
        description="OmniBuster v7 - Framework offensif tout-en-un",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Modes : dir, sub, vhost, head, vuln, post, files, sec, cookies,
  cors, verbs, listing, jwt, graphql, cache, json, all, auto

Exemples :
  # Multi-target depuis un fichier
  python omnibuster.py auto --targets-file targets.txt --use-nuclei -o results.json

  # Cache poisoning
  python omnibuster.py cache -u http://cible

  # JSON body fuzz
  python omnibuster.py json -u http://api/cible \\
      --json-body '{"user":"x","pass":"y"}' --json-fuzz-key pass

  # HTTP/2 + reprenable
  python omnibuster.py vuln -u https://cible/page?id=1 --params id \\
      --http2 --resume scan.state -o out.txt
""")
    parser.add_argument("mode", choices=[
        "dir", "sub", "vhost", "head", "vuln", "post", "files", "sec",
        "cookies", "cors", "verbs", "listing", "jwt", "graphql",
        "cache", "json", "all", "auto"
    ])
    parser.add_argument("-u", "--url")
    parser.add_argument("--targets-file", help="Fichier de cibles (une par ligne)")
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
    parser.add_argument("--jwt-token")
    # --- NOUVEAU v7 ---
    parser.add_argument("--http2", action="store_true", help="Activer HTTP/2")
    parser.add_argument("--use-nuclei", action="store_true")
    parser.add_argument("--nuclei-templates", help="Dossier ou template nuclei")
    parser.add_argument("--use-dalfox", action="store_true")
    parser.add_argument("--dalfox-args", help="Arguments supplémentaires dalfox")
    parser.add_argument("--resume", dest="resume_file",
                        help="Fichier checkpoint pour reprise")
    parser.add_argument("--json-body", help="Template JSON pour fuzzing")
    parser.add_argument("--json-fuzz-key", help="Clé JSON à fuzzer")
    return parser


# ===========================================================================
# MAIN v7
# ===========================================================================

def main_v7():
    signal.signal(signal.SIGINT, sigint_handler)
    print(BANNER)
    parser = build_parser_v7()
    args = parser.parse_args()

    if not args.url and not args.targets_file:
        print(f"{C_RED}[-] Fournir -u URL ou --targets-file{C_END}")
        sys.exit(1)

    try:
        asyncio.run(run_scan_v7(args))
    except KeyboardInterrupt:
        print(f"\n{C_RED}[!] Interrompu{C_END}")
        sys.exit(0)


if __name__ == "__main__":
    main_v7()
