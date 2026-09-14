#!/usr/bin/env python3
"""
REKit - Reverse Engineering Toolkit
Outil léger d'analyse statique pour CTF et cybersécurité.
Auteur: usage libre
"""

import argparse
import hashlib
import math
import os
import re
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

# ---------- Couleurs ----------
class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    B = "\033[94m"; M = "\033[95m"; C = "\033[96m"
    W = "\033[97m"; BOLD = "\033[1m"; END = "\033[0m"

def banner():
    print(f"""{C.C}{C.BOLD}
    ██████╗ ███████╗██╗  ██╗██╗████████╗
    ██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝
    ██████╔╝█████╗  █████╔╝ ██║   ██║   
    ██╔══██╗██╔══╝  ██╔═██╗ ██║   ██║   
    ██║  ██║███████╗██║  ██╗██║   ██║   
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
        Reverse Engineering Toolkit v1.0
{C.END}""")

# ---------- Utilitaires ----------
def run_cmd(cmd):
    """Exécute une commande et retourne la sortie, ou None si indisponible."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.stdout + r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()

# ---------- 1. Informations fichier ----------
def file_info(path):
    print(f"\n{C.BOLD}{C.B}═══ [1] INFORMATIONS FICHIER ═══{C.END}")
    data = read_bytes(path)
    size = len(data)

    print(f"{C.Y}Chemin      :{C.END} {path}")
    print(f"{C.Y}Taille      :{C.END} {size} octets ({size/1024:.2f} Ko)")
    print(f"{C.Y}MD5         :{C.END} {hashlib.md5(data).hexdigest()}")
    print(f"{C.Y}SHA1        :{C.END} {hashlib.sha1(data).hexdigest()}")
    print(f"{C.Y}SHA256      :{C.END} {hashlib.sha256(data).hexdigest()}")

    # Détection de type par magic bytes
    magic = data[:16]
    ftype = detect_type(magic)
    print(f"{C.Y}Type        :{C.END} {C.G}{ftype}{C.END}")

    # Entropie (détection packing/chiffrement)
    ent = entropy(data)
    color = C.G if ent < 6 else (C.Y if ent < 7.2 else C.R)
    print(f"{C.Y}Entropie    :{C.END} {color}{ent:.4f}/8.0{C.END} "
          f"({'normal' if ent < 6 else 'suspect' if ent < 7.2 else 'PACKÉ/CHIFFRÉ possible'})")
    return data

def detect_type(magic):
    sigs = {
        b"\x7fELF": "ELF (Linux/Unix)",
        b"MZ": "PE (Windows)",
        b"\xca\xfe\xba\xbe": "Mach-O (macOS) / FAT",
        b"\xcf\xfa\xed\xfe": "Mach-O 64-bit (macOS)",
        b"PK\x03\x04": "ZIP / JAR / APK",
        b"\x89PNG": "PNG",
        b"\xff\xd8\xff": "JPEG",
        b"GIF8": "GIF",
        b"%PDF": "PDF",
        b"\x1f\x8b": "GZIP",
        b"BZh": "BZIP2",
        b"\xfd7zXZ": "XZ",
        b"ustar": "TAR",
        b"Rar!": "RAR",
        b"7z\xbc\xaf": "7-Zip",
        b"\x00asm": "WebAssembly",
        b"SQLite": "SQLite DB",
    }
    for sig, name in sigs.items():
        if magic.startswith(sig):
            return name
    return "Inconnu / brut"

def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

# ---------- 2. Extraction de chaînes ----------
def extract_strings(data, min_len=4):
    print(f"\n{C.BOLD}{C.B}═══ [2] CHAÎNES INTÉRESSANTES ═══{C.END}")
    # ASCII
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    # Unicode (UTF-16LE)
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)

    ascii_strs = [m.group().decode() for m in ascii_re.finditer(data)]
    wide_strs  = [m.group().decode("utf-16le", errors="ignore") for m in wide_re.finditer(data)]

    # Filtrage par mots-clés "intéressants"
    keywords = ["flag", "ctf", "key", "pass", "secret", "admin", "token",
                "http", "https", "cmd", "exec", "shell", "/bin/sh", "system",
                "socket", "connect", "debug", "error", "root", "user", "login"]

    print(f"{C.Y}Total ASCII :{C.END} {len(ascii_strs)}  |  "
          f"{C.Y}Total Wide :{C.END} {len(wide_strs)}")

    print(f"\n{C.M}▶ Chaînes suspectes (mots-clés) :{C.END}")
    found = False
    for s in ascii_strs + wide_strs:
        low = s.lower()
        if any(k in low for k in keywords):
            print(f"  {C.R}→{C.END} {s[:120]}")
            found = True
    if not found:
        print(f"  {C.W}(aucune){C.END}")

    # Flags potentielles (regex)
    print(f"\n{C.M}▶ Patterns type flag (flag{{...}}, CTF{{...}}) :{C.END}")
    flag_re = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}]{3,120}\}")
    for s in ascii_strs + wide_strs:
        for m in flag_re.finditer(s):
            print(f"  {C.G}{m.group()}{C.END}")

    # URLs / IPs
    print(f"\n{C.M}▶ URLs et IPs :{C.END}")
    url_re = re.compile(r"https?://[^\s\"'<>]{4,}")
    ip_re  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    urls, ips = set(), set()
    for s in ascii_strs:
        urls.update(url_re.findall(s))
        ips.update(ip_re.findall(s))
    for u in list(urls)[:20]:
        print(f"  {C.C}{u}{C.END}")
    for i in list(ips)[:20]:
        print(f"  {C.C}{i}{C.END}")

    return ascii_strs, wide_strs

# ---------- 3. Analyse ELF ----------
def analyze_elf(data):
    print(f"\n{C.BOLD}{C.B}═══ [3] ANALYSE ELF ═══{C.END}")
    if not data.startswith(b"\x7fELF"):
        print(f"{C.W}Pas un fichier ELF.{C.END}")
        return

    ei_class = data[4]  # 1=32, 2=64
    ei_data  = data[5]  # 1=LE, 2=BE
    arch = "64-bit" if ei_class == 2 else "32-bit"
    endian = "little" if ei_data == 1 else "big"
    print(f"{C.Y}Architecture :{C.END} {arch} {endian}")

    e_type = struct.unpack_from("<H", data, 16)[0] if ei_data == 1 else struct.unpack_from(">H", data, 16)[0]
    types = {0:"NONE",1:"REL",2:"EXEC",3:"DYN (PIE/Shared)",4:"CORE"}
    print(f"{C.Y}Type ELF     :{C.END} {types.get(e_type, e_type)}")

    # Utilise readelf si dispo pour plus de détails
    out = run_cmd(["readelf", "-h", "-l", "-S", path_global])
    if out:
        # Sections
        for line in out.splitlines():
            if "GNU_STACK" in line or "GNU_RELRO" in line:
                print(f"{C.Y}Protection   :{C.END} {line.strip()}")
        # Symboles
        sym_out = run_cmd(["readelf", "-s", path_global])
        if sym_out:
            suspicious = ["system", "execve", "popen", "strcpy", "gets",
                          "scanf", "printf", "malloc", "free", "memcpy"]
            print(f"\n{C.M}▶ Symboles dangereux importés :{C.END}")
            for sym in suspicious:
                if re.search(rf"\b{sym}@", sym_out):
                    print(f"  {C.R}⚠{C.END} {sym}")

# ---------- 4. Sécurité binaire ----------
def checksec(path):
    print(f"\n{C.BOLD}{C.B}═══ [4] PROTECTIONS (checksec-like) ═══{C.END}")
    out = run_cmd(["readelf", "-h", "-l", "-d", path])
    if out is None:
        print(f"{C.W}readelf indisponible.{C.END}")
        return
    print(f"{C.Y}PIE   :{C.END} " + ("Oui" if "DYN" in out.split("\n")[0] or "Type:                              DYN" in out else "Non"))
    print(f"{C.Y}NX    :{C.END} " + ("Non (stack exécutable ⚠)" if "RWE" in out else "Oui"))
    print(f"{C.Y}RELRO :{C.END} " + ("Full" if "BIND_NOW" in out else "Partial/None"))
    print(f"{C.Y}Canary:{C.END} " + ("Oui" if "__stack_chk_fail" in (run_cmd(["readelf","-s",path]) or "") else "Non"))
    print(f"{C.Y}Fortify:{C.END} " + ("Oui" if "_chk" in (run_cmd(["readelf","-s",path]) or "") else "Non"))

# ---------- 5. Désassemblage rapide (objdump) ----------
def disassemble(path):
    print(f"\n{C.BOLD}{C.B}═══ [5] DÉSASSEMBLAGE (extrait) ═══{C.END}")
    out = run_cmd(["objdump", "-d", "-M", "intel", path])
    if out is None:
        print(f"{C.W}objdump indisponible.{C.END}")
        return
    lines = out.splitlines()
    # On affiche les 80 premières instructions et on cherche les appels
    calls = [l for l in lines if "\tcall" in l]
    print(f"{C.Y}Instructions totales :{C.END} {len(lines)}")
    print(f"{C.Y}Appels détectés      :{C.END} {len(calls)}")
    print(f"\n{C.M}▶ 15 premiers appels :{C.END}")
    for c in calls[:15]:
        print(f"  {C.C}{c.strip()[:100]}{C.END}")

# ---------- 6. Extraction d'IOCs ----------
def extract_iocs(data):
    print(f"\n{C.BOLD}{C.B}═══ [6] IOCs (Indicateurs de Compromission) ═══{C.END}")
    txt = data.decode("latin-1", errors="ignore")
    patterns = {
        "Emails":     r"[\w.+-]+@[\w-]+\.[\w.-]+",
        "IPv4":       r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "URLs":       r"https?://[^\s\"'<>]+",
        "Domaines":   r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        "Registry":   r"HKEY_[A-Z_]+\\[^\s\"']+",
        "Chemins Win":r"[A-Z]:\\[^\s\"'<>]+",
    }
    for name, pat in patterns.items():
        found = set(re.findall(pat, txt))
        # Nettoyage basique
        found = {f for f in found if len(f) < 200 and not f.endswith(".dll")}
        if found:
            print(f"\n{C.M}▶ {name} ({len(found)}) :{C.END}")
            for f in list(found)[:10]:
                print(f"  {C.C}{f}{C.END}")

# ---------- 7. Recherche de patterns ----------
def search_patterns(data, patterns):
    print(f"\n{C.BOLD}{C.B}═══ [7] RECHERCHE DE PATTERNS ═══{C.END}")
    txt = data.decode("latin-1", errors="ignore")
    for p in patterns:
        try:
            matches = re.findall(p, txt)
        except re.error as e:
            print(f"{C.R}Regex invalide '{p}': {e}{C.END}")
            continue
        if matches:
            print(f"{C.G}✓ '{p}' → {len(matches)} match(s){C.END}")
            for m in matches[:5]:
                print(f"    {C.W}{m[:150]}{C.END}")
        else:
            print(f"{C.W}✗ '{p}' → aucun match{C.END}")

# ---------- 8. Recherche d'offsets ----------
def find_pattern_offset(data, pattern):
    print(f"\n{C.BOLD}{C.B}═══ [8] RECHERCHE D'OFFSETS pour '{pattern}' ═══{C.END}")
    needle = pattern.encode() if isinstance(pattern, str) else pattern
    offsets = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            break
        offsets.append(i)
        start = i + 1
    if offsets:
        for o in offsets:
            print(f"  {C.G}0x{o:08x}{C.END}  ({o})")
    else:
        print(f"{C.W}Aucun offset trouvé.{C.END}")

# ---------- 9. Hexdump ciblé ----------
def hexdump_region(data, offset, length=256):
    print(f"\n{C.BOLD}{C.B}═══ [9] HEXDUMP @ 0x{offset:x} ═══{C.END}")
    chunk = data[offset:offset+length]
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        hexs = " ".join(f"{b:02x}" for b in row)
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        print(f"  {C.Y}{offset+i:08x}{C.END}  {C.C}{hexs:<48}{C.END}  {C.W}{asci}{C.END}")

# ---------- MAIN ----------
path_global = ""

def main():
    global path_global
    banner()
    parser = argparse.ArgumentParser(
        description="REKit - Reverse Engineering Toolkit",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("fichier", help="Fichier à analyser")
    parser.add_argument("-a", "--all", action="store_true", help="Analyse complète")
    parser.add_argument("-i", "--info", action="store_true", help="Infos fichier")
    parser.add_argument("-s", "--strings", action="store_true", help="Chaînes intéressantes")
    parser.add_argument("-e", "--elf", action="store_true", help="Analyse ELF")
    parser.add_argument("-p", "--protections", action="store_true", help="checksec")
    parser.add_argument("-d", "--disasm", action="store_true", help="Désassemblage")
    parser.add_argument("-io", "--iocs", action="store_true", help="Extraction d'IOCs")
    parser.add_argument("-r", "--regex", nargs="+", help="Patterns regex à chercher")
    parser.add_argument("-o", "--offset", help="Chercher l'offset d'une chaîne")
    parser.add_argument("-x", "--hexdump", type=lambda x: int(x, 0),
                        help="Hexdump à un offset (ex: 0x100)")
    parser.add_argument("-l", "--len", type=int, default=256, help="Longueur hexdump")

    args = parser.parse_args()
    path_global = args.fichier

    if not os.path.isfile(path_global):
        print(f"{C.R}[!] Fichier introuvable : {path_global}{C.END}")
        sys.exit(1)

    data = read_bytes(path_global)

    # Si aucune option, on active --all
    if not any([args.info, args.strings, args.elf, args.protections,
                args.disasm, args.iocs, args.regex, args.offset, args.hexdump]):
        args.all = True

    if args.all or args.info:
        file_info(path_global)
    if args.all or args.strings:
        extract_strings(data)
    if args.all or args.elf:
        analyze_elf(data)
    if args.all or args.protections:
        checksec(path_global)
    if args.all or args.disasm:
        disassemble(path_global)
    if args.all or args.iocs:
        extract_iocs(data)
    if args.regex:
        search_patterns(data, args.regex)
    if args.offset:
        find_pattern_offset(data, args.offset)
    if args.hexdump is not None:
        hexdump_region(data, args.hexdump, args.len)

    print(f"\n{C.G}{C.BOLD}[✓] Analyse terminée.{C.END}\n")

if __name__ == "__main__":
    main()
