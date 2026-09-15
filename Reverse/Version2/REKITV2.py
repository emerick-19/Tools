#!/usr/bin/env python3
"""
REKit v2.0 - Reverse Engineering Toolkit
Outil d'analyse statique et dynamique pour CTF et cybersécurité.

Nouveautés v2.0 :
  [10] Constantes 32-bit intéressantes
  [11] Détection automatique d'algorithmes (FNV, RC4, MD5, SHA, AES...)
  [12] Désassemblage Capstone (propre, multi-arch)
  [13] Analyse radare2 (fonctions, CFG, xrefs)
  [14] Décompilation Ghidra headless (optionnel)
"""

import argparse
import hashlib
import math
import os
import re
import shutil
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

# ---------- Détection des dépendances optionnelles ----------
HAS_CAPSTONE = False
HAS_R2PIPE   = False
HAS_ELFTOOLS = False
HAS_GHIDRA   = False

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_MIPS
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

# Ghidra : on vérifie juste la présence du binaire
if shutil.which("analyzeHeadless"):
    HAS_GHIDRA = True

def banner():
    print(f"""{C.C}{C.BOLD}
    ██████╗ ███████╗██╗  ██╗██╗████████╗
    ██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝
    ██████╔╝█████╗  █████╔╝ ██║   ██║   
    ██╔══██╗██╔══╝  ██╔═██╗ ██║   ██║   
    ██║  ██║███████╗██║  ██╗██║   ██║   
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
       Reverse Engineering Toolkit v2.0
{C.END}""")
    # Afficher les modules disponibles
    mods = []
    if HAS_CAPSTONE: mods.append(f"{C.G}Capstone{C.END}")
    if HAS_R2PIPE:   mods.append(f"{C.G}radare2{C.END}")
    if HAS_ELFTOOLS: mods.append(f"{C.G}pyelftools{C.END}")
    if HAS_GHIDRA:   mods.append(f"{C.G}Ghidra{C.END}")
    if mods:
        print(f"{C.W}Modules actifs : {' | '.join(mods)}{C.END}\n")

# ---------- Utilitaires ----------
def run_cmd(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()

# ============================================================
# MODULE 1 - Informations fichier
# ============================================================
def file_info(path):
    print(f"\n{C.BOLD}{C.B}═══ [1] INFORMATIONS FICHIER ═══{C.END}")
    data = read_bytes(path)
    size = len(data)

    print(f"{C.Y}Chemin      :{C.END} {path}")
    print(f"{C.Y}Taille      :{C.END} {size} octets ({size/1024:.2f} Ko)")
    print(f"{C.Y}MD5         :{C.END} {hashlib.md5(data).hexdigest()}")
    print(f"{C.Y}SHA1        :{C.END} {hashlib.sha1(data).hexdigest()}")
    print(f"{C.Y}SHA256      :{C.END} {hashlib.sha256(data).hexdigest()}")

    ftype = detect_type(data[:16])
    print(f"{C.Y}Type        :{C.END} {C.G}{ftype}{C.END}")

    ent = entropy(data)
    color = C.G if ent < 6 else (C.Y if ent < 7.2 else C.R)
    status = "normal" if ent < 6 else ("suspect" if ent < 7.2 else "PACKÉ/CHIFFRÉ possible")
    print(f"{C.Y}Entropie    :{C.END} {color}{ent:.4f}/8.0{C.END} ({status})")
    return data

def detect_type(magic):
    sigs = {
        b"\x7fELF": "ELF (Linux/Unix)", b"MZ": "PE (Windows)",
        b"\xca\xfe\xba\xbe": "Mach-O (macOS)", b"\xcf\xfa\xed\xfe": "Mach-O 64-bit",
        b"PK\x03\x04": "ZIP/JAR/APK", b"\x89PNG": "PNG", b"\xff\xd8\xff": "JPEG",
        b"GIF8": "GIF", b"%PDF": "PDF", b"\x1f\x8b": "GZIP",
        b"BZh": "BZIP2", b"\xfd7zXZ": "XZ", b"ustar": "TAR",
        b"Rar!": "RAR", b"7z\xbc\xaf": "7-Zip",
        b"\x00asm": "WebAssembly", b"SQLite": "SQLite DB",
    }
    for sig, name in sigs.items():
        if magic.startswith(sig): return name
    return "Inconnu / brut"

def entropy(data):
    if not data: return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

# ============================================================
# MODULE 2 - Strings
# ============================================================
def extract_strings(data, min_len=4):
    print(f"\n{C.BOLD}{C.B}═══ [2] CHAÎNES INTÉRESSANTES ═══{C.END}")
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    wide_re  = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)

    ascii_strs = [m.group().decode() for m in ascii_re.finditer(data)]
    wide_strs  = [m.group().decode("utf-16le", errors="ignore") for m in wide_re.finditer(data)]

    keywords = ["flag", "ctf", "key", "pass", "secret", "admin", "token",
                "http", "https", "cmd", "exec", "shell", "/bin/sh", "system",
                "socket", "connect", "debug", "error", "root", "user", "login"]

    print(f"{C.Y}Total ASCII :{C.END} {len(ascii_strs)}  |  "
          f"{C.Y}Total Wide :{C.END} {len(wide_strs)}")

    print(f"\n{C.M}▶ Chaînes suspectes :{C.END}")
    found = False
    for s in ascii_strs + wide_strs:
        low = s.lower()
        if any(k in low for k in keywords):
            print(f"  {C.R}→{C.END} {s[:120]}")
            found = True
    if not found: print(f"  {C.W}(aucune){C.END}")

    print(f"\n{C.M}▶ Patterns type flag :{C.END}")
    flag_re = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}]{3,120}\}")
    any_flag = False
    for s in ascii_strs + wide_strs:
        for m in flag_re.finditer(s):
            print(f"  {C.G}{m.group()}{C.END}")
            any_flag = True
    if not any_flag: print(f"  {C.W}(aucun){C.END}")

    print(f"\n{C.M}▶ URLs / IPs :{C.END}")
    url_re = re.compile(r"https?://[^\s\"'<>]{4,}")
    ip_re  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    urls, ips = set(), set()
    for s in ascii_strs:
        urls.update(url_re.findall(s))
        ips.update(ip_re.findall(s))
    for u in list(urls)[:20]: print(f"  {C.C}{u}{C.END}")
    for i in list(ips)[:20]: print(f"  {C.C}{i}{C.END}")

    return ascii_strs, wide_strs

# ============================================================
# MODULE 3 - ELF
# ============================================================
def analyze_elf(data, path):
    print(f"\n{C.BOLD}{C.B}═══ [3] ANALYSE ELF ═══{C.END}")
    if not data.startswith(b"\x7fELF"):
        print(f"{C.W}Pas un fichier ELF.{C.END}")
        return

    ei_class = data[4]; ei_data = data[5]
    arch = "64-bit" if ei_class == 2 else "32-bit"
    endian = "little" if ei_data == 1 else "big"
    print(f"{C.Y}Architecture :{C.END} {arch} {endian}")

    e_type = struct.unpack_from("<H", data, 16)[0] if ei_data == 1 else struct.unpack_from(">H", data, 16)[0]
    types = {0:"NONE",1:"REL",2:"EXEC",3:"DYN (PIE/Shared)",4:"CORE"}
    print(f"{C.Y}Type ELF     :{C.END} {types.get(e_type, e_type)}")

    # pyelftools si dispo
    if HAS_ELFTOOLS:
        try:
            with open(path, "rb") as f:
                elf = ELFFile(f)
                print(f"{C.Y}Machine      :{C.END} {elf.get_machine_arch()}")
                print(f"{C.Y}Entry point  :{C.END} 0x{elf.header.e_entry:x}")
                print(f"{C.Y}Nb sections  :{C.END} {elf.num_sections()}")
                # Sections non standard
                custom = []
                for sec in elf.iter_sections():
                    name = sec.name
                    if name and name not in (".text",".data",".bss",".rodata",".comment",
                                              ".symtab",".strtab",".shstrtab",".dynamic",
                                              ".dynsym",".dynstr",".hash",".gnu.hash",
                                              ".gnu.version",".gnu.version_r",".rela.dyn",
                                              ".rela.plt",".plt",".plt.got",".init",".fini",
                                              ".init_array",".fini_array",".eh_frame",
                                              ".eh_frame_hdr",".got",".got.plt",".interp",
                                              ".note.gnu.build-id",".note.ABI-tag",
                                              ".note.gnu.property",".gnu.version_d"):
                        custom.append(name)
                if custom:
                    print(f"\n{C.M}▶ Sections non standard :{C.END}")
                    for name in custom:
                        print(f"  {C.Y}→{C.END} {name}")
        except Exception as e:
            print(f"{C.W}pyelftools erreur : {e}{C.END}")
    else:
        print(f"{C.W}pyelftools non installé (analyse limitée){C.END}")

    # Symboles dangereux
    sym_out = run_cmd(["readelf", "-s", path])
    if sym_out:
        suspicious = ["system", "execve", "popen", "strcpy", "gets",
                      "scanf", "printf", "malloc", "free", "memcpy",
                      "socket", "connect", "send", "recv"]
        print(f"\n{C.M}▶ Symboles dangereux importés :{C.END}")
        any_danger = False
        for sym in suspicious:
            if re.search(rf"\b{sym}@", sym_out):
                print(f"  {C.R}⚠{C.END} {sym}")
                any_danger = True
        if not any_danger:
            print(f"  {C.W}(aucun){C.END}")

# ============================================================
# MODULE 4 - Protections
# ============================================================
def checksec(path):
    print(f"\n{C.BOLD}{C.B}═══ [4] PROTECTIONS (checksec-like) ═══{C.END}")
    out = run_cmd(["readelf", "-h", "-l", "-d", path])
    if out is None:
        print(f"{C.W}readelf indisponible.{C.END}")
        return
    sym_out = run_cmd(["readelf", "-s", path]) or ""
    print(f"{C.Y}PIE    :{C.END} " + ("Oui" if "Type:                              DYN" in out else "Non"))
    print(f"{C.Y}NX     :{C.END} " + ("Non (stack exécutable ⚠)" if "RWE" in out else "Oui"))
    print(f"{C.Y}RELRO  :{C.END} " + ("Full" if "BIND_NOW" in out else "Partial/None"))
    print(f"{C.Y}Canary :{C.END} " + ("Oui" if "__stack_chk_fail" in sym_out else "Non"))
    print(f"{C.Y}Fortify:{C.END} " + ("Oui" if "_chk" in sym_out else "Non"))

# ============================================================
# MODULE 5 - Désassemblage objdump (fallback)
# ============================================================
def disassemble(path):
    print(f"\n{C.BOLD}{C.B}═══ [5] DÉSASSEMBLAGE (objdump) ═══{C.END}")
    out = run_cmd(["objdump", "-d", "-M", "intel", path])
    if out is None:
        print(f"{C.W}objdump indisponible.{C.END}")
        return
    lines = out.splitlines()
    calls = [l for l in lines if "\tcall" in l]
    print(f"{C.Y}Instructions totales :{C.END} {len(lines)}")
    print(f"{C.Y}Appels détectés      :{C.END} {len(calls)}")
    print(f"\n{C.M}▶ 15 premiers appels :{C.END}")
    for c in calls[:15]:
        print(f"  {C.C}{c.strip()[:100]}{C.END}")

# ============================================================
# MODULE 6 - IOCs
# ============================================================
def extract_iocs(data):
    print(f"\n{C.BOLD}{C.B}═══ [6] IOCs ═══{C.END}")
    txt = data.decode("latin-1", errors="ignore")
    patterns = {
        "Emails":     r"[\w.+-]+@[\w-]+\.[\w.-]+",
        "IPv4":       r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "URLs":       r"https?://[^\s\"'<>]+",
        "Registry":   r"HKEY_[A-Z_]+\\[^\s\"']+",
        "Chemins Win":r"[A-Z]:\\[^\s\"'<>]+",
    }
    for name, pat in patterns.items():
        found = set(re.findall(pat, txt))
        # Filtrer les faux positifs GLIBC
        found = {f for f in found if not f.endswith((".so",".so.6")) and
                 "@GLIBC" not in f and len(f) < 200}
        if found:
            print(f"\n{C.M}▶ {name} ({len(found)}) :{C.END}")
            for f in list(found)[:10]:
                print(f"  {C.C}{f}{C.END}")

# ============================================================
# MODULE 7 - Patterns regex
# ============================================================
def search_patterns(data, patterns):
    print(f"\n{C.BOLD}{C.B}═══ [7] RECHERCHE REGEX ═══{C.END}")
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

# ============================================================
# MODULE 8 - Offsets
# ============================================================
def find_pattern_offset(data, pattern):
    print(f"\n{C.BOLD}{C.B}═══ [8] OFFSETS de '{pattern}' ═══{C.END}")
    needle = pattern.encode() if isinstance(pattern, str) else pattern
    offsets, start = [], 0
    while True:
        i = data.find(needle, start)
        if i == -1: break
        offsets.append(i)
        start = i + 1
    if offsets:
        for o in offsets:
            print(f"  {C.G}0x{o:08x}{C.END}  ({o})")
    else:
        print(f"{C.W}Aucun offset trouvé.{C.END}")

# ============================================================
# MODULE 9 - Hexdump
# ============================================================
def hexdump_region(data, offset, length=256):
    print(f"\n{C.BOLD}{C.B}═══ [9] HEXDUMP @ 0x{offset:x} ═══{C.END}")
    chunk = data[offset:offset+length]
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        hexs = " ".join(f"{b:02x}" for b in row)
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        print(f"  {C.Y}{offset+i:08x}{C.END}  {C.C}{hexs:<48}{C.END}  {C.W}{asci}{C.END}")

# ============================================================
# MODULE 10 - Constantes 32-bit intéressantes
# ============================================================
def find_constants(data):
    print(f"\n{C.BOLD}{C.B}═══ [10] CONSTANTES 32-BIT ═══{C.END}")

    # Signatures connues
    KNOWN = {
        0x811c9dc5: "FNV-1a offset basis",
        0x01000193: "FNV-1a prime",
        0xedb88320: "CRC32 (IEEE) polynomial",
        0x67452301: "MD5 init A",
        0xefcdab89: "MD5 init B",
        0x98badcfe: "MD5 init C",
        0x10325476: "MD5 init D",
        0x5a827999: "SHA1 K0",
        0x6ed9eba1: "SHA1 K1",
        0x428a2f98: "SHA256 K0",
        0x71374491: "SHA256 K1",
        0xcafebabe: "Java class / magic",
        0xdeadbeef: "Magic marker",
        0x13371337: "Magic marker (leet)",
        0xbaadf00d: "Magic marker",
        0xf00dbabe: "Magic marker",
        0x0d15ea5e: "Magic marker",
        0xdeadc0de: "Magic marker",
        0xabad1dea: "Magic marker",
    }

    print(f"\n{C.M}▶ Signatures connues :{C.END}")
    found_any = False
    for magic, name in KNOWN.items():
        needle = struct.pack("<I", magic)
        idx = 0
        offsets = []
        while True:
            i = data.find(needle, idx)
            if i == -1: break
            offsets.append(i)
            idx = i + 1
        if offsets:
            print(f"  {C.G}✓ 0x{magic:08x}{C.END} ({name})")
            for o in offsets[:3]:
                print(f"      offset: {C.C}0x{o:x}{C.END}")
            found_any = True
    if not found_any:
        print(f"  {C.W}(aucune signature connue){C.END}")

    # Constantes "suspectes" (entre 0x1000 et 0xffffffff, hors adresses)
    print(f"\n{C.M}▶ Autres constantes 32-bit (échantillon) :{C.END}")
    consts = []
    for i in range(0, len(data) - 4, 4):
        v = struct.unpack_from("<I", data, i)[0]
        # Filtrer : ni trop petit, ni adresse ELF, ni caractères ASCII
        if 0x1000 <= v <= 0xffffffff:
            if 0x400000 <= v <= 0x500000:  # adresses ELF typiques
                continue
            # Filtrer les valeurs qui sont 4 chars ASCII
            bs = struct.pack("<I", v)
            if all(32 <= b < 127 for b in bs):
                continue
            consts.append((i, v))

    # Dédupliquer
    seen = set()
    for off, v in consts[:30]:
        if v in seen: continue
        seen.add(v)
        print(f"  {C.Y}0x{off:08x}{C.END}  →  {C.C}0x{v:08x}{C.END}")

# ============================================================
# MODULE 11 - Détection d'algorithmes
# ============================================================
def detect_algorithms(data):
    print(f"\n{C.BOLD}{C.B}═══ [11] DÉTECTION D'ALGORITHMES ═══{C.END}")

    # Signatures par constantes
    sigs = {
        "FNV-1a 32-bit":   [0x811c9dc5, 0x01000193],
        "FNV-1 32-bit":    [0x811c9dc5, 0x01000193],
        "CRC32 IEEE":      [0xedb88320],
        "CRC32 Castagnoli":[0x82f63b78],
        "MD5":             [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
        "SHA1":            [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
        "SHA256":          [0x428a2f98, 0x71374491, 0xb5c0fbcf],
        "SHA512":          [0x428a2f98, 0xd728ae22],
        "AES S-box":       [0x7b777c63],  # début S-box
        "Base64 alphabet": [0x41424344],  # "ABCD"
        "Blowfish":        [0x243f6a88, 0x85a308d3],
        "Arcfour (RC4)":   [0xff],        # masque 0xff récurrent
    }

    found = []
    for name, consts in sigs.items():
        matches = 0
        for c in consts:
            # Chercher en little-endian
            needle = struct.pack("<I", c) if c > 0xff else bytes([c])
            if needle in data:
                matches += 1
        if matches >= len(consts) * 0.6:  # au moins 60% des constantes
            found.append((name, matches, len(consts)))

    if found:
        for name, m, total in found:
            print(f"  {C.G}✓ {name}{C.END} ({m}/{total} signatures)")
    else:
        print(f"  {C.W}(aucun algorithme connu détecté par constantes){C.END}")

    # Détection RC4 par boucle caractéristique
    print(f"\n{C.M}▶ Heuristiques :{C.END}")
    # RC4 : beaucoup de 0xff et 0x100 dans le code
    count_ff   = data.count(b"\xff\x00\x00\x00")
    count_100  = data.count(b"\x00\x01\x00\x00")
    if count_ff > 2 or count_100 > 0:
        print(f"  {C.Y}⚠{C.END} Masque 0xff fréquent → RC4/XOR loop probable")

    # XOR loop : recherche de 0x30/0x31/0x32 (xor opcodes)
    if b"\x30" in data[:0x10000] or b"\x31" in data[:0x10000]:
        pass  # trop commun, on skip

# ============================================================
# MODULE 12 - Capstone (désassemblage propre)
# ============================================================
def capstone_disasm(path, offset=None, length=2000, max_insns=60):
    if not HAS_CAPSTONE:
        print(f"\n{C.W}[12] Capstone non installé (pip install capstone){C.END}")
        return

    print(f"\n{C.BOLD}{C.B}═══ [12] CAPSTONE DÉSASSEMBLAGE ═══{C.END}")

    data = read_bytes(path)

    # Détecter l'architecture
    if data.startswith(b"\x7fELF"):
        ei_class = data[4]
        mode = CS_MODE_64 if ei_class == 2 else CS_MODE_32
        # Vérifier l'endianness
        if data[5] == 2:  # big endian
            mode |= 0x4000000  # CS_MODE_BIG_ENDIAN
        md = Cs(CS_ARCH_X86, mode)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64)

    # Trouver le point de départ : entry point ou offset donné
    if offset is None:
        if data.startswith(b"\x7fELF") and len(data) > 0x20:
            # Entry point dans le header ELF
            e_entry = struct.unpack_from("<Q", data, 0x18)[0]
            offset = 0x1000  # fallback : début du .text typique
            print(f"{C.Y}Entry point :{C.END} 0x{e_entry:x}")
            print(f"{C.Y}Désassemblage à partir de :{C.END} 0x{offset:x}\n")
        else:
            offset = 0
            print(f"{C.Y}Désassemblage à partir de :{C.END} 0x0\n")

    chunk = data[offset:offset+length]
    count = 0
    for insn in md.disasm(chunk, offset):
        # Colorer selon le type
        if insn.mnemonic == "call":
            color = C.G
        elif insn.mnemonic.startswith("j"):
            color = C.Y
        elif insn.mnemonic in ("ret", "leave"):
            color = C.R
        else:
            color = C.W

        print(f"  {C.C}0x{insn.address:08x}{C.END}  "
              f"{color}{insn.mnemonic:<8}{C.END} {insn.op_str}")
        count += 1
        if count >= max_insns:
            print(f"  {C.W}...{C.END}")
            break

# ============================================================
# MODULE 13 - radare2
# ============================================================
def r2_analyze(path):
    if not HAS_R2PIPE:
        print(f"\n{C.W}[13] radare2 non disponible (pip install r2pipe + apt install radare2){C.END}")
        return

    print(f"\n{C.BOLD}{C.B}═══ [13] ANALYSE RADARE2 ═══{C.END}")

    try:
        r2 = r2pipe.open(path)
        r2.cmd("aaa")  # analyse complète

        # Fonctions
        print(f"\n{C.M}▶ Fonctions détectées :{C.END}")
        funcs = r2.cmdj("aflj") or []
        for f in funcs[:25]:
            name = f.get("name", "?")
            addr = f.get("offset", 0)
            size = f.get("size", 0)
            color = C.G if name not in ("entry0", "main") else C.Y
            print(f"  {C.C}0x{addr:08x}{C.END}  {color}{name}{C.END}  "
                  f"({size} octets)")

        # Xrefs vers puts/printf (chercher où le flag est affiché)
        print(f"\n{C.M}▶ Appels à printf/puts :{C.END}")
        xrefs = r2.cmd("axt @@ sym.imp.printf sym.imp.puts").splitlines()
        for x in xrefs[:15]:
            print(f"  {C.C}{x}{C.END}")

        # Strings avec offsets (mieux que regex)
        print(f"\n{C.M}▶ Strings (r2, filtrées) :{C.END}")
        strings = r2.cmdj("izj") or []
        interesting = [s for s in strings if any(
            k in s.get("string", "").lower()
            for k in ["flag", "rek", "ctf", "pass", "key", "rc4"]
        )]
        for s in interesting[:15]:
            print(f"  {C.C}0x{s.get('vaddr',0):x}{C.END}  "
                  f"{C.W}{s.get('string','')[:80]}{C.END}")

        # Désassemblage d'une fonction clé
        if funcs:
            # Chercher main ou une fonction contenant "rc4"
            target = None
            for f in funcs:
                if "rc4" in f.get("name", "").lower() or f.get("name") == "main":
                    target = f
                    break
            if target:
                print(f"\n{C.M}▶ Désassemblage de {target['name']} "
                      f"({target['size']} octets) :{C.END}")
                disasm = r2.cmd(f"pdf @ {target['offset']}")
                for line in disasm.splitlines()[:40]:
                    print(f"  {C.C}{line}{C.END}")

        r2.quit()
    except Exception as e:
        print(f"{C.R}Erreur radare2 : {e}{C.END}")

# ============================================================
# MODULE 14 - Ghidra headless (optionnel)
# ============================================================
def ghidra_decompile(path, output_file=None):
    if not HAS_GHIDRA:
        print(f"\n{C.W}[14] Ghidra non installé (analyzeHeadless introuvable){C.END}")
        print(f"{C.W}    Téléchargez Ghidra : https://ghidra-sre.org/{C.END}")
        print(f"{C.W}    Puis : export PATH=$PATH:/opt/ghidra/support{C.END}")
        return

    print(f"\n{C.BOLD}{C.B}═══ [14] GHIDRA HEADLESS ═══{C.END}")

    import tempfile
    proj_dir = tempfile.mkdtemp(prefix="rekit_ghidra_")
    proj_name = "rekit_proj"

    # Script Ghidra minimal pour décompiler toutes les fonctions
    ghidra_script = """
# @category REKit
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

decomp = DecompInterface()
decomp.openProgram(currentProgram)

fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if func.isThunk(): continue
    print("=== " + func.getName() + " @ " + str(func.getEntryPoint()) + " ===")
    res = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    print("")
"""
    script_path = os.path.join(proj_dir, "decompile.py")
    with open(script_path, "w") as f:
        f.write(ghidra_script)

    cmd = [
        "analyzeHeadless", proj_dir, proj_name,
        "-import", path,
        "-postScript", "decompile.py",
        "-scriptPath", proj_dir,
        "-deleteProject",
    ]
    print(f"{C.Y}Lancement de Ghidra (peut prendre 30s)...{C.END}")
    out = run_cmd(cmd, timeout=300)
    if out:
        # Extraire le pseudo-C
                if output_file is None:
            output_file = path + ".decompiled.c"

        lines = out.splitlines()
        c_lines = []
        capture = False
        for line in lines:
            if line.startswith("=== ") and line.endswith(" ==="):
                capture = True
                c_lines.append("\n/* " + line + " */")
            elif capture and not line.startswith(("INFO ", "WARN ", "ERROR ", "Using ")):
                c_lines.append(line)

        pseudo_c = "\n".join(c_lines)
        with open(output_file, "w") as f:
            f.write(pseudo_c)

        print(f"{C.G}✓ Décompilation terminée : {output_file}{C.END}")
        print(f"{C.Y}Extrait :{C.END}")
        for line in c_lines[:40]:
            print(f"  {C.C}{line}{C.END}")
          
if __name__ == "__main__":
    main()
