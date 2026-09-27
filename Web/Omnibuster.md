---
title: "OmniBuster v7"
subtitle: "Manuel d'utilisation complet"
author: "Emerick-19"
date: "2026"
logo: "logo.svg"
---

# OmniBuster v7 — Manuel d'utilisation

**Version** : 7.0
**Auteur** : Emerick-19
**Langage** : Python 3.10+
**Catégorie** : Framework offensif tout-en-un
**Licence** : Éducatif & pentest autorisé

---

\newpage

## Avant-propos

OmniBuster est né d'une frustration simple : devoir jongler entre quinze outils différents pour mener un audit web complet. D'un côté `ffuf` pour le fuzzing, `dalfox` pour les XSS, `sqlmap` pour les injections, `nuclei` pour les CVE… De l'autre, tout un tas de scripts maison qu'on oublie à chaque nouveau projet.

J'ai voulu un **outil unique**, rapide, furtif, et qui reste **lisible**. Pas une usine à gaz avec 400 dépendances et une interface graphique qui plante. Juste un binaire Python qu'on lance en ligne de commande, qu'on peut scripter, et dont on comprend chaque sortie.

Ce document couvre **tout** : installation, architecture, chaque mode, chaque module de vulnérabilité, chaque option CLI. Il est pensé pour être lu une fois du début à la fin, puis utilisé comme référence au besoin.

Bonne lecture. Et n'oubliez pas la règle d'or : **on ne scanne que ce qu'on est autorisé à scanner.**

---

\newpage

## Table des matières

1. Présentation
2. Installation
3. Architecture
4. Le client HTTP
5. Modes de scan
6. Modules de vulnérabilités
7. Système de payloads
8. Détection WAF
9. Multi-target & reprise
10. Intégrations externes
11. Rapports
12. Cas pratiques
13. Sécurité légale
14. Dépannage

\newpage

## 1. Présentation

OmniBuster v7 regroupe en un seul exécutable :

- Un **fuzzer asynchrone** pour répertoires, sous-domaines, vhosts et headers
- Un **scanner de vulnérabilités** couvrant 9 familles d'attaques web
- Des **audits de configuration** (headers, cookies, CORS, verbes HTTP)
- Des **détections avancées** (cache poisoning, JWT, GraphQL)
- Des **intégrations** avec Nuclei, Dalfox et sqlmap
- Un **moteur multi-target** avec reprise sur interruption

### 1.1 Ce que fait OmniBuster

| Domaine | Ce qu'il couvre |
|---------|-----------------|
| Reconnaissance | Répertoires, fichiers, sous-domaines, vhosts, headers |
| Injection | SQLi, XSS, LFI, SSRF, SSTI, CMDi, CRLF, XXE |
| Configuration | Headers de sécurité, cookies, CORS, verbes |
| Logique | Open redirect, cache poisoning |
| Découverte | Fichiers sensibles, GraphQL, JWT |
| Exploitation | Intégration sqlmap |

### 1.2 Ce qu'il ne fait pas

- ❌ Il n'exécute pas de JavaScript (pas de DOM XSS natif)
- ❌ Il ne remplace pas un pentest manuel
- ❌ Il n'escalade pas les privilèges côté serveur
- ❌ Il n'authentifie pas automatiquement (sessions complexes)

### 1.3 Philosophie

Trois principes :

1. **Modulaire** — chaque fonctionnalité est indépendante
2. **Asynchrone** — `asyncio` + `aiohttp` pour rester rapide
3. **Lisible** — un fichier, pas mille, et des sorties claires

\newpage

## 2. Installation

### 2.1 Prérequis

- Python **3.10** minimum (testé jusqu'à 3.12)
- pip
- OS : Linux, macOS, WSL (Windows natif non testé)

### 2.2 Dépendances Python

```bash
pip install aiohttp tqdm colorama
```

### 2.3 Dépendances optionnelles

Pour profiter des intégrations externes :

| Outil | Rôle | Installation |
|-------|------|--------------|
| Nuclei | Scans CVE/exposure | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| Dalfox | XSS avancé | `go install github.com/hahwul/dalfox/v2@latest` |
| sqlmap | Exploitation SQLi | `apt install sqlmap` |

### 2.4 Installation du binaire

```bash
git clone <repo>
cd omnibuster
chmod +x omnibuster.py
sudo ln -s $PWD/omnibuster.py /usr/local/bin/omnibuster
```

Vérifiez :

```bash
omnibuster --help
```

### 2.5 Vérification de l'environnement

```bash
python3 --version        # doit être ≥ 3.10
pip show aiohttp tqdm colorama | grep Version
```

\newpage

## 3. Architecture

OmniBuster est structuré en couches :

```
CLI (argparse)
    ↓
ScanConfig (dataclass)
    ↓
HTTPClient (aiohttp + proxy + retry + UA rotation)
    ↓
Dispatcher (run_single_mode / run_multi_target)
    ↓
Scanners spécialisés (dir, vuln, post, ...)
    ↓
PayloadFactory (payloads + mutations)
    ↓
Reporter (console + TXT/JSON/CSV/HTML)
```

### 3.1 Les composants clés

**HTTPClient** — gère tout le réseau :
- limite la concurrence (`Semaphore`)
- fait tourner les User-Agents
- choisit un proxy si pool fourni
- applique un rate-limit
- retente en cas d'échec réseau
- spoofe Referer/Origin/X-Requested-With

**Reporter** — centralise la sortie :
- affichage console coloré
- écriture dans un fichier (TXT, JSON, CSV)
- génération d'un rapport HTML

**PayloadFactory** — génère les payloads :
- 9 familles de bases (SQLi, XSS, LFI…)
- mutations aléatoires à chaque run
- 3 niveaux d'obfuscation (low, medium, high)

**Checkpoint** — sauvegarde la progression :
- écrit un fichier JSON toutes les 50 actions
- permet de reprendre un scan interrompu

\newpage

## 4. Le client HTTP

Toute communication passe par `HTTPClient.request()` :

```python
async def request(self, method, url, headers=None, data=None,
                  params=None, allow_redirects=None, read_body=False):
    async with self.sem:          # limite concurrence
        await self._rate_limit()  # délai éventuel
        # construit les headers (UA aléatoire + spoof + custom)
        # choisit un proxy
        # boucle de retry
        # retourne un ScanResult
```

### 4.1 Rotation User-Agent

À chaque requête, l'UA change selon une liste prédéfinie :
- Chrome Windows 10
- Firefox Linux
- Safari macOS
- Safari iOS

### 4.2 Rotation proxy

Si `--proxy-file` est fourni, chaque requête prend le proxy suivant :

```
proxies.txt :
http://user:pass@ip1:port
socks5://ip2:port
http://ip3:port
```

### 4.3 Rate limiting

Deux modes :
- `--rate-limit 0.5` → délai fixe de 0.5s entre requêtes
- `--random-delay` → délai aléatoire 0.1–1.5s (furtif)

\newpage

## 5. Modes de scan

### 5.1 `dir` — Répertoires et fichiers

**Objectif** : découvrir des chemins cachés.

**Exemple** :

```bash
omnibuster dir -u https://cible.com -w dirs.txt -x php,html -r 2
```

**Fonctionnement** :
1. Détection automatique du wildcard
2. Pour chaque mot de la wordlist :
   - teste `word`
   - teste `word.ext1`, `word.ext2`…
3. Filtre selon les codes/taille/mots/lignes
4. Si récursion > 0 et chemin découvert est un dossier → relance

### 5.2 `sub` — Sous-domaines

```bash
omnibuster sub -u cible.com -w subs.txt
```

Détecte aussi les **subdomain takeovers** (GitHub Pages, S3, Fastly).

### 5.3 `vhost` — Virtual hosts

```bash
omnibuster vhost -u http://cible.com -w vhosts.txt
```

Envoie `Host: word.cible.com` et compare la taille à la baseline.

### 5.4 `head` — Fuzzing de headers

Teste 9 headers de confiance :
- X-Forwarded-For, X-Forwarded-Host, X-Real-IP
- X-Client-IP, X-Originating-IP, X-Remote-IP
- X-Remote-Addr, Client-IP, Forwarded

Utile pour détecter les **IP trust bypass**.

### 5.5 `vuln` — Scanner de vulnérabilités

Le mode le plus complet. Lance **8 scanners en parallèle** sur les paramètres :

```bash
omnibuster vuln -u "http://cible/page.php" --auto-params --obfuscation high
```

### 5.6 `post` — Fuzzing POST

```bash
omnibuster post -u http://cible/login.php \
    --post-params user pass --obfuscation high
```

### 5.7 `json` — Fuzzing JSON

```bash
omnibuster json -u http://api.cible.com/login \
    --json-body '{"user":"admin","pass":"x"}' --json-fuzz-key pass
```

### 5.8 `files` — Fichiers sensibles

Cherche 60+ chemins courants : `.env`, `.git/config`, backups, clés SSH, endpoints Spring Boot, etc.

### 5.9 `sec` — Audit des headers

Vérifie la présence de 10 headers de sécurité et détecte les fuites d'info (`Server`, `X-Powered-By`).

### 5.10 `cookies` — Flags de cookies

Analyse les flags `Secure`, `HttpOnly`, `SameSite` sur les cookies renvoyés.

### 5.11 `cors` — Mauvaise config CORS

Teste si l'Origin reflète une origine hostile, avec gestion du flag credentials.

### 5.12 `verbs` — HTTP Verb Tampering

Teste 13 méthodes HTTP et signale les dangereuses (PUT, DELETE, TRACE).

### 5.13 `listing` — Directory listing

Cherche les index ouverts sur des dossiers usuels.

### 5.14 `jwt` — Analyse JWT

```bash
omnibuster jwt -u http://cible --jwt-token "eyJhbG..."
```

Signale notamment `alg: none`.

### 5.15 `graphql` — Introspection GraphQL

Teste 4 chemins courants et vérifie si `__schema` est accessible.

### 5.16 `cache` — Cache Poisoning

Envoie 8 headers cache-unkeyed pour voir s'ils sont reflétés, teste la cache deception.

### 5.17 `all` / `auto` — Enchaînement automatique

Lance dans l'ordre : headers, cookies, CORS, verbes, GraphQL, cache, fichiers sensibles, extraction des paramètres, vuln scan GET, POST fuzzing.

\newpage

## 6. Modules de vulnérabilités

### 6.1 SQL Injection

Deux techniques :

**Error-based** — cherche des messages d'erreur SQL dans la réponse. 22 signatures couvrent MySQL, PostgreSQL, MSSQL, Oracle, SQLite.

**Time-based** — mesure le temps de réponse avec `SLEEP(5)`, `WAITFOR DELAY`, `pg_sleep(5)`.

### 6.2 XSS réfléchi

Injecte `marqueur + payload`, vérifie que **les deux** apparaissent dans la réponse. Permet d'éviter les faux positifs.

### 6.3 LFI

Couvre : traversée simple, traversée encodée, PHP wrappers (`php://filter`, `data://`, `expect://`), fichiers sensibles (`/etc/shadow`, `/root/.ssh/id_rsa`).

### 6.4 SSRF

Inclut les bypass 127.0.0.1 (octal, décimal, hex, `[::1]`), les métadonnées cloud (AWS, GCP, Alibaba) et les protocoles alternatifs (`gopher://`, `dict://`, `file://`).

### 6.5 SSTI

Couvre Jinja2, Twig, FreeMarker, ERB, Velocity, et inclut des payloads RCE pour Jinja2.

### 6.6 Command Injection

Payloads avec `;`, `|`, `&&`, backticks, `$()`, et time-based.

**⚠️ Ce module exécute réellement des commandes sur une cible vulnérable.**

### 6.7 CRLF Injection

Injecte `%0d%0a` pour tenter d'ajouter des headers dans la réponse.

### 6.8 Open Redirect

15 payloads de bypass : `//evil.com`, `https:evil.com`, `//google.com@evil.com`, etc.

### 6.9 XXE

3 payloads d'entity expansion pour lire des fichiers locaux ou déclencher des requêtes sortantes.

\newpage

## 7. Système de payloads

### 7.1 Base

Chaque famille contient 15–60 payloads bruts (voir PayloadFactory dans le code).

### 7.2 Mutations

4 transformations appliquées aléatoirement :
- Casse aléatoire (`SeLeCt`)
- Insertion de commentaires SQL (`/**/`)
- Encodage URL partiel
- Double URL-encoding

### 7.3 Niveaux

| Niveau | Payloads testés | Mutations |
|--------|:---------------:|:---------:|
| low | 15 | non |
| medium | 40 | oui (10) |
| high | 80 | oui (20) |

**Astuce** : deux scans `high` ne génèrent jamais exactement les mêmes payloads → casse les signatures WAF.

\newpage

## 8. Détection WAF

### 8.1 Fingerprinting passif

Analyse les en-têtes de réponse pour identifier :

- Cloudflare (`cf-ray`, `__cfduid`)
- AWS WAF (`x-amzn-requestid`)
- ModSecurity (`mod_security`, `NOYB`)
- Sucuri, Akamai, Imperva, F5, Barracuda, Fastly, Wordfence

### 8.2 Détection active

Envoie un payload évident (`<script>alert(1)</script>`) et observe la réponse : `403`, `406`, `419`, `501`, `503` → WAF probable.

### 8.3 Contournement

- `--obfuscation high` → payloads mutés
- `--random-delay` → évite le rate-limiting
- `--proxy-file` → rotation d'IP
- `--http2` → évite certains fingerprints HTTP/1.1

\newpage

## 9. Multi-target & reprise

### 9.1 Multi-target

```bash
omnibuster auto --targets-file targets.txt --html-report global.html
```

- 5 cibles scannées en parallèle
- Chaque cible a son propre Reporter
- Rapport HTML consolidé à la fin

### 9.2 Reprise sur interruption

```bash
omnibuster vuln -u http://cible --auto-params --resume scan.state
```

**Fonctionnement** :
- Sauvegarde JSON toutes les 50 actions
- Si relancé avec le même `--resume` → reprend où ça s'est arrêté
- Marque la cible comme `completed` à la fin

\newpage

## 10. Intégrations externes

### 10.1 Nuclei

```bash
omnibuster auto -u http://cible --use-nuclei \
    --nuclei-templates ~/nuclei-templates/
```

Les findings Nuclei sont remontés avec leur sévérité d'origine.

### 10.2 Dalfox

```bash
omnibuster vuln -u http://cible --auto-params --use-dalfox \
    --dalfox-args "--deep-domxss"
```

### 10.3 sqlmap

```bash
omnibuster vuln -u "http://cible?id=1" --params id --use-sqlmap
```

À utiliser **après** confirmation d'une SQLi pour exploiter proprement.

\newpage

## 11. Rapports

### 11.1 Console

```
[200] http://cible/admin (4521b/120w/45l) [0.23s]
[XSS-REFLECTED] param=q payload="<script>alert(1)</script>"
```

Couleurs :
- 🟢 Vert → info / 200
- 🟡 Jaune → low / 301
- 🟣 Magenta → medium
- 🔴 Rouge → high
- 🔴 Rouge gras → critical

### 11.2 Fichier TXT

```
200	http://cible/admin	4521	120	45
FINDING	SQLi-error	high	http://cible/?id=1	param=id payload="'"
```

### 11.3 Fichier JSON

Une ligne JSON par résultat (JSON Lines) — pratique pour `jq`.

### 11.4 Fichier CSV

Compatible tableur.

### 11.5 Rapport HTML

Généré avec `--html-report FILE.html`. Tableau trié par sévérité, couleur par niveau, URLs cliquables.

\newpage

## 12. Cas pratiques

### 12.1 Reconnaissance d'un site

```bash
omnibuster sub -u cible.com -w subs.txt -o subs.txt
omnibuster dir -u https://cible.com -w dirs.txt -x php,html -o dirs.txt
omnibuster sec -u https://cible.com --html-report sec.html
```

### 12.2 Bug bounty pipeline

```bash
# Reconnaissance
omnibuster sub -u target.com -w ~/wordlists/subs.txt -o subs.txt

# Auto scan + Nuclei sur tous les subs
omnibuster auto --targets-file subs.txt \
    --use-nuclei --nuclei-templates ~/nuclei-templates/cves/ \
    --html-report bounty.html --resume bounty.state

# Exploitation ciblée
omnibuster vuln -u "https://interesting.target.com" \
    --auto-params --use-dalfox --use-sqlmap
```

### 12.3 Audit API REST

```bash
# Cartographier les endpoints
omnibuster dir -u https://api.cible.com/v1 -w api_endpoints.txt \
    -mc 200,201,204,400,401,403,405

# Fuzzer le JSON
omnibuster json -u https://api.cible.com/v1/login \
    --json-body '{"email":"","password":"","role":"user"}' \
    --json-fuzz-key email --obfuscation high
```

### 12.4 Scan furtif

```bash
omnibuster vuln -u http://cible --auto-params \
    --obfuscation high \
    --random-delay \
    --rate-limit 2.0 \
    --proxy-file tor_pool.txt \
    -H "Accept-Language: fr-FR,fr;q=0.9" \
    --no-spoof-headers
```

\newpage

## 13. Sécurité légale

> ⚠️ **OmniBuster ne doit être utilisé que sur :**
>
> - Des systèmes vous appartenant
> - Des cibles avec autorisation écrite (contrat de pentest, scope de bug bounty)
> - Des environnements de lab / CTF

**En France**, l'utilisation non autorisée d'un outil de scan est un délit puni par l'**article 323-1 du Code pénal** : jusqu'à 3 ans d'emprisonnement et 100 000 € d'amende.

### Modules à surveiller

| Module | Risque |
|--------|--------|
| `cmdi` | Exécute **réellement** des commandes sur la cible |
| `cache` | Peut empoisonner un CDN → affecter d'autres utilisateurs |
| `--use-sqlmap` | Peut dumper des bases entières |

**En production** : préférez `--obfuscation low --rate-limit 1.0` et désactivez CMDi.

\newpage

## 14. Dépannage

### 14.1 Erreurs fréquentes

| Erreur | Solution |
|--------|----------|
| `ModuleNotFoundError: aiohttp` | `pip install aiohttp tqdm colorama` |
| `sqlmap introuvable` | `apt install sqlmap` |
| 403 partout après détection WAF | `--proxy`, `-t 5`, `--rate-limit 2.0` |
| Timeouts répétés | `--timeout 15 --retries 3` |
| Trop de faux positifs SQLi | `-fw <mots> -fl <lignes>` |
| Wildcard détecté → 0 résultat | Normal, le filtre wildcard agit |

### 14.2 Performance

**Trop lent** :
```bash
omnibuster dir -u URL -w wl.txt -t 200 --retries 0 --timeout 3
```

**Rate-limité par la cible** :
```bash
omnibuster ... -t 10 --rate-limit 0.5 --random-delay
```

### 14.3 Debug

Activer la sauvegarde JSON de toutes les réponses :

```bash
omnibuster dir -u http://cible -w wl.txt -o debug.json --format json
jq '.[] | select(.status == 200)' debug.json
```

\newpage

## Conclusion

OmniBuster v7 est un framework **complet, rapide et lisible**. Il couvre la plupart des besoins d'un audit web moderne, sans dépendre d'une douzaine d'outils externes.

**Trois commandes à retenir** :

```bash
# Reconnaissance large
omnibuster auto --targets-file targets.txt --html-report rapport.html

# Vulnérabilités sur une page
omnibuster vuln -u "http://cible/page.php" --auto-params --obfuscation high

# Scan furtif multi-proxy
omnibuster vuln -u http://cible --auto-params --proxy-file proxies.txt --random-delay
```

Bonne chasse.

— Emerick-19
