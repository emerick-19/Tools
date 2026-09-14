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
import shutil
# ---------- Détection des dépendances optionnelles ----------
HAS_CAPSTONE = False
HAS_R2PIPE   = False
HAS_ELFTOOLS = False
HAS_GHIDRA   = False

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    HAS_CAPSTONE = True
except ImportError:
    pass

try:
    import r2pipe
    HAS_R2PIPE = True
except ImportError:
    pass

try:
    from elftools.elf.elffile import ELFFile
    HAS_ELFTOOLS = True
except ImportError:
    pass

if shutil.which("analyzeHeadless"):
    HAS_GHIDRA = True
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
    parser.add_argument("-packer", "--packer", action="store_true",
                        help="Détection de packer (module 15)")
    parser.add_argument("-unpack", "--unpack", action="store_true",
                        help="Unpacking automatique (module 16)")
    parser.add_argument("-patch", "--patch-analysis", action="store_true",
                        help="Analyse des patchs possibles (module 17)")
    parser.add_argument("--patch-bytes", nargs=2, metavar=("OFFSET","HEX"),
                        help="Patch : offset et bytes en hex (ex: 0x1234 74)")
    parser.add_argument("--nop", nargs=2, metavar=("OFFSET","LEN"),
                        help="NOP-out : offset et longueur")
    parser.add_argument("--invert-jump", metavar="OFFSET",
                        help="Inverser un saut à un offset")
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
        # Nouveaux modules
    if args.packer or args.all:
        detect_packer(data, path_global)
    if args.unpack:
        auto_unpack(path_global)
    if args.patch_analysis or args.all:
        patch_analysis(data, path_global)

    # Patch applicatif
    if args.patch_bytes:
        offset = int(args.patch_bytes[0], 0)
        hex_bytes = bytes.fromhex(args.patch_bytes[1])
        apply_patch(path_global, [(offset, hex_bytes)])
    if args.nop:
        offset = int(args.nop[0], 0)
        length = int(args.nop[1])
        nop_out(path_global, offset, length)
    if args.invert_jump:
        offset = int(args.invert_jump, 0)
        invert_jump(path_global, offset)

    print(f"\n{C.G}{C.BOLD}[✓] Analyse terminée.{C.END}\n")
# ============================================================
# MODULE 15 - Détection de packer
# ============================================================
def detect_packer(data, path):
    print(f"\n{C.BOLD}{C.B}═══ [15] DÉTECTION PACKER ═══{C.END}")

    signatures = {
        b"UPX!":      "UPX",
        b"UPX0":      "UPX (section 0)",
        b"UPX1":      "UPX (section 1)",
        b"MPRESS1":   "MPRESS",
        b"MPRESS2":   "MPRESS",
        b".aspack":   "ASPack",
        b".adata":    "ASPack",
        b".pec":      "PECompact",
        b".petite":   "Petite",
        b"FSG!":      "FSG",
        b".Themida":  "Themida",
        b"VMProtect": "VMProtect",
        b".vmp0":     "VMProtect",
        b".vmp1":     "VMProtect",
        b".enigma1":  "Enigma",
        b".enigma2":  "Enigma",
    }

    detected = None
    for sig, name in signatures.items():
        if sig in data:
            print(f"  {C.G}✓ Signature : {name}{C.END}")
            detected = name

    # Entropie par section (ELF)
    if data.startswith(b"\x7fELF"):
        out = run_cmd(["readelf", "-S", "-W", path])
        if out:
            print(f"\n{C.M}▶ Entropie par section :{C.END}")
            for line in out.splitlines():
                m = re.search(r"\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
                if m:
                    name = m.group(1)
                    offset = int(m.group(2), 16)
                    size = int(m.group(3), 16)
                    if size > 100 and offset + size <= len(data):
                        sec_data = data[offset:offset+size]
                        ent = entropy(sec_data)
                        color = C.R if ent > 7.2 else (C.Y if ent > 6 else C.G)
                        print(f"  {C.C}{name:<20}{C.END} "
                              f"taille={size:<8} entropie={color}{ent:.3f}{C.END}")

    if not detected and entropy(data) > 7.2:
        print(f"\n  {C.Y}⚠ Entropie globale > 7.2 sans signature connue{C.END}")
        print(f"  {C.W}→ Packer custom ou chiffré possible{C.END}")

    return detected

# ============================================================
# MODULE 16 - Unpacking automatique
# ============================================================
def auto_unpack(path):
    print(f"\n{C.BOLD}{C.B}═══ [16] UNPACKING AUTOMATIQUE ═══{C.END}")

    data = read_bytes(path)
    original_size = len(data)
    unpacked_path = path + ".unpacked"

    # UPX
    if b"UPX!" in data:
        print(f"{C.Y}[1/3] UPX détecté{C.END}")
        if shutil.which("upx"):
            shutil.copy(path, unpacked_path)
            out = run_cmd(["upx", "-d", unpacked_path])
            if out and "Unpacked" in out:
                new_size = os.path.getsize(unpacked_path)
                print(f"  {C.G}✓ Unpacked : {original_size} → {new_size} octets{C.END}")
                print(f"  {C.Y}Fichier :{C.END} {unpacked_path}")
                return unpacked_path
            else:
                print(f"  {C.R}✗ Échec UPX{C.END}")
        else:
            print(f"  {C.W}upx non installé : sudo apt install upx-ucl{C.END}")
            return None

    # Autres signatures
    print(f"{C.Y}[2/3] Recherche d'autres packers...{C.END}")
    others = {
        b".aspack":   "ASPack (aspackdie)",
        b"MPRESS1":   "MPRESS (outil dédié)",
        b".Themida":  "Themida (manuel)",
        b"VMProtect": "VMProtect (manuel)",
    }
    for sig, tool in others.items():
        if sig in data:
            print(f"  {C.Y}⚠ {tool}{C.END}")

    # Suggestion dump runtime
    print(f"{C.Y}[3/3] Si aucun unpacker ne fonctionne :{C.END}")
    print(f"  {C.W}→ Dump mémoire avec GDB :{C.END}")
    print(f"    gdb {path}")
    print(f"    (gdb) info proc mappings")
    print(f"    (gdb) dump memory dump.bin <start> <end>")
    return None

# ============================================================
# MODULE 17 - Analyse de patch (avec Capstone si dispo)
# ============================================================
def patch_analysis(data, path):
    print(f"\n{C.BOLD}{C.B}═══ [17] ANALYSE DE PATCH ═══{C.END}")

    if not HAS_CAPSTONE:
        print(f"{C.W}Capstone non installé — analyse basique{C.END}")
        # Recherche brute de jne/je
        jne_count = data.count(b"\x75")
        je_count  = data.count(b"\x74")
        print(f"  {C.Y}jne (0x75) :{C.END} {jne_count} occurrences")
        print(f"  {C.Y}je  (0x74) :{C.END} {je_count} occurrences")
        print(f"{C.W}Installez Capstone : pip install capstone{C.END}")
        return

    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # Trouver la section .text (heuristique : après le header ELF)
    text_start = 0x1000
    text_size = min(0x10000, len(data) - text_start)

    print(f"\n{C.M}▶ Sauts conditionnels et comparaisons :{C.END}")
    interesting = []
    for insn in md.disasm(data[text_start:text_start+text_size], text_start):
        if insn.mnemonic in ("cmp", "test", "jne", "je", "jz", "jnz",
                             "jg", "jl", "jle", "jge", "call"):
            interesting.append((insn.address, insn.mnemonic,
                                insn.op_str, insn.bytes))

    for addr, mnem, ops, raw in interesting[:30]:
        bytes_str = " ".join(f"{b:02x}" for b in raw)
        print(f"  {C.C}0x{addr:08x}{C.END}  "
              f"{C.Y}{mnem:<6}{C.END} {ops:<25}  "
              f"{C.W}[{bytes_str}]{C.END}")

    print(f"\n{C.M}▶ Patchs suggérés :{C.END}")
    for addr, mnem, ops, raw in interesting:
        if mnem == "jne" and len(raw) >= 2:
            print(f"  0x{addr:08x} : jne → je  "
                  f"({raw[:2].hex()} → 74{raw[1:2].hex()})")
        elif mnem == "je" and len(raw) >= 2:
            print(f"  0x{addr:08x} : je → jne  "
                  f"({raw[:2].hex()} → 75{raw[1:2].hex()})")

# ============================================================
# MODULE 18 - Application de patch
# ============================================================
def apply_patch(path, patches):
    print(f"\n{C.BOLD}{C.B}═══ [18] APPLICATION DE PATCH ═══{C.END}")

    backup = path + ".bak"
    if not os.path.exists(backup):
        shutil.copy(path, backup)
        print(f"{C.Y}Backup :{C.END} {backup}")

    with open(path, "r+b") as f:
        for offset, new_bytes in patches:
            f.seek(offset)
            old = f.read(len(new_bytes))
            f.seek(offset)
            f.write(new_bytes)
            print(f"  {C.C}0x{offset:08x}{C.END}  "
                  f"{C.R}{old.hex()}{C.END} → {C.G}{new_bytes.hex()}{C.END}")

    print(f"\n{C.G}✓ {len(patches)} patch(s) appliqué(s){C.END}")

def nop_out(path, offset, length):
    print(f"\n{C.BOLD}{C.B}═══ [19] NOP-OUT ═══{C.END}")
    apply_patch(path, [(offset, b'\x90' * length)])

def invert_jump(path, offset):
    print(f"\n{C.BOLD}{C.B}═══ [20] INVERSION DE SAUT ═══{C.END}")

    with open(path, "rb") as f:
        f.seek(offset)
        opcode = f.read(1)[0]

    INVERSES = {
        0x74: 0x75, 0x75: 0x74,  # je ↔ jne
        0x7c: 0x7d, 0x7d: 0x7c,  # jl ↔ jge
        0x7e: 0x7f, 0x7f: 0x7e,  # jle ↔ jg
        0x72: 0x73, 0x73: 0x72,  # jb ↔ jae
        0x76: 0x77, 0x77: 0x76,  # jbe ↔ ja
    }
    NAMES = {0x74:"je",0x75:"jne",0x7c:"jl",0x7d:"jge",
             0x7e:"jle",0x7f:"jg",0x72:"jb",0x73:"jae",
             0x76:"jbe",0x77:"ja"}

    if opcode in INVERSES:
        new_op = INVERSES[opcode]
        print(f"  {C.Y}{NAMES[opcode]}{C.END} → {C.G}{NAMES[new_op]}{C.END}")
        apply_patch(path, [(offset, bytes([new_op]))])
    else:
        print(f"  {C.R}Opcode 0x{opcode:02x} non reconnu{C.END}")

if __name__ == "__main__":
    main()
