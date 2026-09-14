📖 README.md (résumé)
markdown
# REKit

Outil de reverse engineering statique pour CTF et analyse réelle.

## Installation
chmod +x rekit.py

## Usage
./rekit.py binaire              # Analyse complète
./rekit.py binaire -s           # Chaînes uniquement
./rekit.py binaire -r 'flag{.*}' 'password'
./rekit.py binaire -o "secret"  # Offset d'une chaîne
./rekit.py binaire -x 0x1000    # Hexdump
🚀 Utilisation en CTF
bash
# Analyse complète d'un binaire suspect
python3 rekit.py ./challenge

# Chercher directement un flag
python3 rekit.py ./challenge -r 'flag\{.*\}' 'CTF\{.*\}'

# Trouver l'offset d'une chaîne pour patching
python3 rekit.py ./challenge -o "Correct!"

# Dumper une zone mémoire
python3 rekit.py ./challenge -x 0x4000 -l 512

# Analyse ciblée d'un ELF
python3 rekit.py ./challenge -e -p -s
🛡️ Utilisation en cybersécurité réelle
bash
# Analyse d'un malware (IOCs + strings + entropie)
python3 rekit.py suspicious.exe --all

# Extraction d'IOCs d'un dropper
python3 rekit.py dropper.bin -io

# Recherche de C2 dans un échantillon
python3 rekit.py sample -r 'https?://\d+\.\d+\.\d+\.\d+'
✨ Fonctionnalités
Module	Description
1. Info fichier	Hashes MD5/SHA1/SHA256, type, entropie
2. Strings	ASCII + UTF-16, mots-clés, flags, URLs, IPs
3. ELF	Architecture, type, symboles dangereux
4. Protections	PIE, NX, RELRO, Canary, Fortify
5. Désassemblage	Appels de fonctions via objdump
6. IOCs	Emails, IPs, URLs, domaines, registry
7. Regex	Recherche personnalisée
8. Offsets	Localisation de patterns
9. Hexdump	Vue hexadécimale ciblée
🔮 Améliorations futures possibles
Intégration Capstone pour un désassemblage complet multi-architecture

Support PE (Windows) via pefile ou lief

Intégration YARA pour la détection de malwares

Décompilation via Ghidra headless (pyghidra)

Wrapper Frida pour l'analyse dynamique

IA : envoyer les fonctions suspectes à un LLM pour résumé

Interface web (FastAPI + React) pour usage collaboratif

Support Wasm pour les challenges web
