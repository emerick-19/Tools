<p align="center">
  <img src="logo.svg" width="200" alt="OmniBuster">
</p>

<h1 align="center">OmniBuster v7</h1>

<p align="center">
  <b>Framework offensif tout-en-un</b><br>
  Fuzzer async · Scanner de vulnérabilités · Multi-target · Reprise sur interruption
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg">
  <img src="https://img.shields.io/badge/license-Educational-red.svg">
  <img src="https://img.shields.io/badge/version-7.0-green.svg">
  <img src="https://img.shields.io/badge/status-stable-brightgreen.svg">
</p>

---

**Sommaire**
- [Installation](#installation)
- [Utilisation rapide](#utilisation-rapide)
- [Documentation complète](OmniBuster_v7_Documentation.pdf)
- [Modes de scan](#modes)
- [Modules de vulnérabilités](#modules)
- [Avertissement légal](#legal)

## Installation

\`\`\`bash
pip install aiohttp tqdm colorama
git clone <repo> && cd omnibuster
chmod +x omnibuster.py
\`\`\`

## Utilisation rapide

\`\`\`bash
# Reconnaissance
omnibuster auto --targets-file targets.txt --html-report scan.html

# Vulnérabilités
omnibuster vuln -u "http://cible/page.php" --auto-params --obfuscation high

# Scan furtif
omnibuster vuln -u http://cible --auto-params --proxy-file proxies.txt --random-delay
\`\`\`

## <a name="legal"></a>Avertissement légal

Cet outil est destiné à un usage **éducatif et professionnel autorisé uniquement**.
L'utilisateur est seul responsable de l'usage qu'il en fait.
