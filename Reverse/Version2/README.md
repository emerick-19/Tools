🚀 REKit v2.0 — Version augmentée avec r2, Capstone, détection d'algos
Voici la version complète et améliorée. Elle conserve toute la v1.0 et ajoute 5 modules puissants.

📁 Structure finale
text
rekit-v2/
├── rekit.py              # Outil principal (v2.0)
├── requirements.txt      # Dépendances optionnelles
├── install_extras.sh     # Installe Capstone, r2pipe, pyelftools
└── README.md

# REKit v2.0 — Reverse Engineering Toolkit

Outil d'analyse statique et dynamique pour **CTF** et **cybersécurité**.
Léger, modulaire, extensible. Écrit en Python pur.

---

## 🚀 Installation rapide

```bash
# 1. Cloner / créer le dossier
mkdir rekit-v2 && cd rekit-v2

# 2. Copier rekit.py dedans
# (le script principal)

# 3. Installer les extras optionnels
bash install_extras.sh

# 4. Tester
python3 rekit.py --help
📦 Dépendances
Obligatoires
Aucune. REKit fonctionne avec la bibliothèque standard Python uniquement.

Optionnelles (recommandées)
Dépendance	Poids	Apporte
capstone	~5 Mo	Désassemblage propre (x86, ARM, MIPS)
r2pipe + radare2	~10 Mo	Analyse de flux, fonctions, xrefs
pyelftools	~2 Mo	Parsing ELF avancé (sections custom)
Ghidra	~1 Go	Décompilation pseudo-C (headless)
REKit détecte automatiquement ce qui est installé et active les modules disponibles.

🛠️ Utilisation
Analyse complète (tous les modules)
bash
python3 rekit.py <binaire>
Options principales
bash
python3 rekit.py <binaire> -a          # Analyse complète
python3 rekit.py <binaire> -i          # Infos fichier (hashes, entropie)
python3 rekit.py <binaire> -s          # Strings + flags + IOCs
python3 rekit.py <binaire> -e          # Analyse ELF
python3 rekit.py <binaire> -p          # Protections (checksec)
python3 rekit.py <binaire> -d          # Désassemblage objdump
python3 rekit.py <binaire> -io         # Extraction d'IOCs
python3 rekit.py <binaire> -r <regex>  # Recherche regex
python3 rekit.py <binaire> -o <str>    # Chercher offset d'une chaîne
python3 rekit.py <binaire> -x <offset> # Hexdump à un offset
Nouveautés v2.0
bash
python3 rekit.py <binaire> -c          # Constantes 32-bit intéressantes
python3 rekit.py <binaire> -algo       # Détection d'algorithmes (FNV, RC4, MD5...)
python3 rekit.py <binaire> -cap        # Désassemblage Capstone
python3 rekit.py <binaire> -r2         # Analyse radare2
python3 rekit.py <binaire> -gh         # Décompilation Ghidra
Exemples concrets
bash
# Reco rapide d'un binaire inconnu
python3 rekit.py suspicious.bin

# Chercher un flag
python3 rekit.py challenge -s -r 'flag\{.*\}' 'CTF\{.*\}'

# Détecter un algorithme crypto custom
python3 rekit.py cryptobin -algo -c

# Trouver l'offset d'une chaîne (pour patching)
python3 rekit.py challenge -o "Correct!"

# Désassembler avec Capstone (plus propre qu'objdump)
python3 rekit.py challenge -cap

# Analyse complète avec radare2 (fonctions, xrefs)
python3 rekit.py challenge -r2

# Décompiler avec Ghidra (si installé)
python3 rekit.py challenge -gh
🧩 Architecture
text
rekit.py
├── [1]  file_info          → hashes, entropie, type
├── [2]  extract_strings    → ASCII/UTF-16, flags, URLs, IPs
├── [3]  analyze_elf        → architecture, sections, symboles
├── [4]  checksec           → PIE, NX, RELRO, Canary, Fortify
├── [5]  disassemble        → objdump (fallback)
├── [6]  extract_iocs       → emails, IPs, URLs, registry, chemins
├── [7]  search_patterns    → regex custom
├── [8]  find_pattern_offset→ localisation d'octets
├── [9]  hexdump_region     → vue hex + ASCII
├── [10] find_constants     → magic numbers, hashes
├── [11] detect_algorithms  → FNV, RC4, MD5, SHA, AES...
├── [12] capstone_disasm    → désassemblage propre
├── [13] r2_analyze         → fonctions, xrefs, CFG
└── [14] ghidra_decompile   → pseudo-C (optionnel)
Chaque module est indépendant : vous pouvez les appeler seuls ou combinés.

🎯 Ce que REKit détecte automatiquement
Protections binaires
PIE : adresses randomisées (ASLR)

NX : stack non exécutable

RELRO : protection GOT

Canary : détection de stack overflow

Fortify : fonctions libc durcies

Algorithmes cryptographiques
FNV-1a / FNV-1 (hash non cryptographique)

CRC32 (IEEE, Castagnoli)

MD5 (init constants)

SHA1 / SHA256 / SHA512

AES (S-box)

Blowfish (P-array)

RC4 (masque 0xff récurrent)

Types de fichiers
ELF, PE, Mach-O, ZIP, PNG, JPEG, GIF, PDF, GZIP, BZIP2, XZ, TAR, RAR, 7-Zip, WebAssembly, SQLite

🔬 Comparaison avec les outils existants
Fonction	REKit	Ghidra	radare2	objdump
Léger (< 5 Mo)	✅	❌	✅	✅
Sans GUI	✅	⚠️	✅	✅
Python scriptable	✅	⚠️	⚠️	❌
Détection d'algos	✅	❌	❌	❌
Désassemblage	✅	✅	✅	✅
Décompilation	⚠️ (via Ghidra)	✅	⚠️	❌
Analyse de flux	⚠️ (via r2)	✅	✅	❌
Extraction IOCs	✅	❌	❌	❌
Détection packer	✅	❌	⚠️	❌
REKit n'est pas un remplaçant de Ghidra — c'est un wrapper unifié qui vous fait gagner du temps sur les tâches répétitives (reco, strings, IOCs, protections), et qui délègue aux vrais outils (r2, Ghidra) quand il faut aller plus loin.

🎓 Cas d'usage
1. CTF — Reconnaissance rapide
bash
python3 rekit.py challenge
# En 5 secondes : type, entropie, strings, protections
# → décider quoi faire ensuite
2. Analyse de malware (échantillon)
bash
python3 rekit.py sample.exe -io -s -r 'http[s]?://' 'HKEY_' 
# → extraction d'IOCs, URLs, registre
3. Reverse de binaire obfusqué
bash
python3 rekit.py target -algo -c -r2
# → détecter la crypto, lister les fonctions, voir les xrefs
4. Patch de binaire
bash
python3 rekit.py challenge -o "Access Denied"
# → offset exact → patcher avec HxD / radare2 -w
⚠️ Avertissement légal
REKit est destiné à l'analyse de binaires dont vous avez la propriété ou l'autorisation explicite :

Challenges CTF

Binaires que vous avez écrits

Échantillons malware en sandbox isolée

Audits de sécurité autorisés

L'usage sur des systèmes tiers sans consentement est illégal.

🐛 Limitations connues
Pattern matching fragile sur les protections (parfois faux positifs)

Pas d'analyse dynamique native (pas d'exécution, pas d'émulation)

Détection d'algorithmes par constantes — peut rater les algos custom

Ghidra headless lent (~30s pour un petit binaire)

Pas de support Windows PE natif (via pefile à ajouter)

Pour les challenges Insane, REKit ne fait que 20 % du travail :
il donne les matériaux bruts (constantes, désassemblage, fonctions),
mais vous devez reconstruire la logique (Ghidra, GDB, Unicorn, Angr).

🔮 Roadmap v3.0
□ Support PE complet (Windows) via pefile
□ Émulation Unicorn pour tracer l'exécution
□ Interface TUI (Textual)
□ Export JSON/YAML des résultats
□ Base de signatures YARA intégrée
□ Détection de packers (UPX, MPRESS, Themida...)
□ Support ARM/MIPS pour firmware
□ Analyse de documents Office (oletools)
□ Détection de macros VBA
□ Intégration angr pour exécution symbolique
📚 Ressources
radare2 book

Ghidra docs

Capstone docs

Practical Malware Analysis (Ligh & Adair)

Malware Unicorn workshops

📝 Licence
Usage pédagogique et professionnel. Fourni tel quel, sans garantie.

Auteur : REKit v2.0 — généré pour l'apprentissage du reverse engineering.

text

---

## 🛠️ Bonus — `install_extras.sh`

Je vous livre aussi le script d'installation des extras :

```bash
#!/bin/bash
# ============================================================
#  REKit v2.0 - Installation des modules optionnels
# ============================================================

set -e

echo -e "\033[96m[*] Installation des extras REKit v2.0\033[0m"

# Détection de l'OS
if [ -f /etc/debian_version ]; then
    PKG="apt"
    SUDO="sudo apt install -y"
elif [ -f /etc/arch-release ]; then
    PKG="pacman"
    SUDO="sudo pacman -S --noconfirm"
elif [ -f /etc/fedora-release ]; then
    PKG="dnf"
    SUDO="sudo dnf install -y"
else
    PKG="unknown"
fi

# --- Pip : Capstone + r2pipe + pyelftools ---
echo -e "\n\033[93m[1/3] Modules Python\033[0m"
pip install --user capstone r2pipe pyelftools 2>/dev/null || \
    pip install --break-system-packages capstone r2pipe pyelftools

# --- Système : radare2 ---
echo -e "\n\033[93m[2/3] radare2\033[0m"
if command -v r2 >/dev/null 2>&1; then
    echo "  [✓] radare2 déjà installé"
else
    case $PKG in
        apt)    $SUDO radare2 ;;
        pacman) $SUDO radare2 ;;
        dnf)    $SUDO radare2 ;;
        *)      echo "  [!] Installez radare2 manuellement" ;;
    esac
fi

# --- Outils système utiles ---
echo -e "\n\033[93m[3/3] Outils système (binutils, file, upx)\033[0m"
case $PKG in
    apt)    $SUDO binutils file upx-ucl ;;
    pacman) $SUDO binutils file upx ;;
    dnf)    $SUDO binutils file upx ;;
esac

# --- Ghidra (optionnel) ---
echo -e "\n\033[93m[Ghidra] (optionnel, ~1 Go)\033[0m"
if command -v analyzeHeadless >/dev/null 2>&1; then
    echo "  [✓] Ghidra déjà installé"
else
    read -p "  Installer Ghidra ? (o/N) " yn
    case $yn in
        [oO]*)
            GHIDRA_VER="11.0.3"
            GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER}_build/ghidra_${GHIDRA_VER}_PUBLIC_20240410.zip"
            echo "  [*] Téléchargement..."
            curl -L -o /tmp/ghidra.zip "$GHIDRA_URL"
            echo "  [*] Extraction dans /opt/ghidra..."
            sudo unzip -q /tmp/ghidra.zip -d /opt/
            sudo mv /opt/ghidra_* /opt/ghidra
            echo ""
            echo "  [✓] Ghidra installé. Ajoutez à votre PATH :"
            echo "      export PATH=\$PATH:/opt/ghidra/support"
            rm /tmp/ghidra.zip
            ;;
        *) echo "  [i] Ghidra ignoré" ;;
    esac
fi

# --- Vérification finale ---
echo -e "\n\033[92m[✓] Installation terminée\033[0m"
echo ""
echo "Modules disponibles :"
python3 -c "import capstone; print('  [✓] capstone', capstone.__version__)" 2>/dev/null || echo "  [✗] capstone"
python3 -c "import r2pipe; print('  [✓] r2pipe')" 2>/dev/null || echo "  [✗] r2pipe"
python3 -c "import elftools; print('  [✓] pyelftools')" 2>/dev/null || echo "  [✗] pyelftools"
command -v r2 >/dev/null && echo "  [✓] radare2 $(r2 -v | head -1)" || echo "  [✗] radare2"
command -v analyzeHeadless >/dev/null && echo "  [✓] Ghidra" || echo "  [✗] Ghidra (optionnel)"

echo ""
echo -e "\033[96mTestez avec : python3 rekit.py --help\033[0m"
