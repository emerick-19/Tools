import argparse
import concurrent.futures
import requests
import sys
import random
import signal

C_GREEN = "\033[92m"
C_BLUE = "\033[94m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_MAGENTA = "\033[95m"
C_CYAN = "\033[96m"
C_END = "\033[0m"
C_BOLD = "\033[1m"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
]

shutdown_flag = False

def sigint_handler(signum, frame):
    global shutdown_flag
    print(f"\n{C_RED}[!] Interruption (CTRL+C)... Arrêt propre...{C_END}")
    shutdown_flag = True
    sys.exit(0)

signal.signal(signal.SIGINT, sigint_handler)

# --- FONCTIONS DE SCAN CORE ---

def fuzz_directory(word, target, config):
    global shutdown_flag
    if shutdown_flag: return
    
    word_base = word.strip().lstrip('/')
    
    # On crée la liste des variantes à tester (le mot brut + les extensions)
    urls_to_test = [f"{target}/{word_base}"]
    if config['extensions'] and '.' not in word_base: # Évite de rajouter .html si le mot est déjà index.php
        for ext in config['extensions']:
            urls_to_test.append(f"{target}/{word_base}.{ext.strip().lstrip('.')}")

    for url in urls_to_test:
        if shutdown_flag: return
        try:
            res = requests.head(url, headers={"User-Agent": random.choice(USER_AGENTS)}, allow_redirects=False, timeout=4)
            
            if res.status_code == 429:
                return

            if res.status_code in config['excluded_codes']: return
            
            if res.status_code in [200, 204, 301, 302, 307, 403]:
                color = C_GREEN if res.status_code == 200 else C_YELLOW
                # Extrait juste la fin de l'URL pour l'affichage propre
                display_path = url.replace(target, "")
                print(f"{color}[{res.status_code}]{C_END} {C_CYAN}{display_path}{C_END}")
        except requests.RequestException: pass

def fuzz_subdomain(word, target, config):
    global shutdown_flag
    if shutdown_flag: return
    clean_target = target.replace("http://", "").replace("https://", "").split('/')[0]
    sub = word.strip()
    url = f"http://{sub}.{clean_target}"
    try:
        res = requests.head(url, headers={"User-Agent": random.choice(USER_AGENTS)}, allow_redirects=True, timeout=4)
        if res.status_code == 429: return 
        if res.status_code in config['excluded_codes']: return
        if res.status_code in [200, 204, 301, 302, 401, 403]:
            print(f"{C_GREEN}[Trouvé]{C_END} {C_CYAN}{sub}.{clean_target}{C_END} (Status: {res.status_code})")
    except requests.RequestException: pass

def fuzz_vhost(word, target, config):
    global shutdown_flag
    if shutdown_flag: return
    clean_target = target.replace("http://", "").replace("https://", "").split('/')[0]
    vhost = f"{word.strip()}.{clean_target}"
    headers = {"User-Agent": random.choice(USER_AGENTS), "Host": vhost}
    try:
        res = requests.get(target, headers=headers, timeout=4, allow_redirects=False)
        if res.status_code == 429: return
        length = len(res.content)
        if res.status_code in config['excluded_codes']: return
        if length != config['base_size'] and res.status_code != 404:
            print(f"{C_GREEN}[VHost]{C_END} {C_CYAN}{vhost}{C_END} -> Code: {C_YELLOW}{res.status_code}{C_END} | Taille: {C_BLUE}{length} bytes{C_END}")
    except requests.RequestException: pass

def fuzz_headers(word, target, config):
    global shutdown_flag
    if shutdown_flag: return
    headers = {"User-Agent": random.choice(USER_AGENTS), "X-Forwarded-For": word.strip()}
    try:
        res = requests.get(target, headers=headers, timeout=4)
        if res.status_code == 429: return
        length = len(res.content)
        if res.status_code in config['excluded_codes']: return
        if length != config['base_size']:
            print(f"{C_GREEN}[Header]{C_END} X-Forwarded-For: {C_CYAN}{word.strip()}{C_END} -> Taille: {C_BLUE}{length} bytes{C_END}")
    except requests.RequestException: pass

# --- LOGIQUE PRINCIPALE ---

def main():
    # Bannière corrigée, propre et lisible pour OMNIBUSTER
    banner = r"""
{C_MAGENTA}{C_BOLD} ______ __  __ _   _ _____ ____  _    _  _____ _______ ______ _____  
|  ____|  \/  | \ | |_   _|  _ \| |  | |/ ____|__   __|  ____|  __ \ 
| |__  | \  / |  \| | | | | |_) | |  | | (___    | |  | |__  | |__) |
|  __| | |\/| | . ` | | | |  _ <| |  | |\___ \   | |  |  __| |  _  / 
| |____| |  | | |\  |_| |_| |_) | |__| |____) |  | |  | |____| | \ \ 
|______|_|  |_|_| \_|_____|____/ \____/|_____/   |_|  |______|_|  \_\ 
                                         {C_CYAN}v3.2 - Stable By Emerick-19{C_END}
    """
    print(banner.format(C_MAGENTA=C_MAGENTA, C_BOLD=C_BOLD, C_CYAN=C_CYAN, C_END=C_END))

    parser = argparse.ArgumentParser(description="OmniBuster Premium v3.2")
    parser.add_argument("-t", "--target", required=True, help="URL cible")
    parser.add_argument("-w", "--wordlist", required=True, help="Chemin de la wordlist")
    parser.add_argument("-threads", type=int, default=10, help="Nombre de threads")
    parser.add_argument("-fc", "--filter-code", default="", help="Codes HTTP à masquer (ex: 301)")
    parser.add_argument("-x", "--extensions", default="", help="Extensions à tester séparées par des virgules (ex: html,txt,php)")
    
    args = parser.parse_args()
    target = args.target if args.target.startswith("http") else f"http://{args.target}"

    print(f"{C_BOLD}--- SÉLECTION DU MODE DE SCAN ---{C_END}")
    print(f"{C_BLUE}1.{C_END} Scan de Répertoires / Fichiers (Prend en compte les extensions)")
    print(f"{C_BLUE}2.{C_END} Scan de Sous-domaines")
    print(f"{C_BLUE}3.{C_END} Scan de Virtual Hosts (VHosts)")
    print(f"{C_BLUE}4.{C_END} Fuzzing d'En-têtes (Headers)")
    print(f"{C_BLUE}5.{C_END} Quitter")
    
    choix = input(f"\n{C_BOLD}Choisis ton mode (1-5) :{C_END} ")
    
    modes = {"1": fuzz_directory, "2": fuzz_subdomain, "3": fuzz_vhost, "4": fuzz_headers}
    if choix not in modes:
        print(f"{C_RED}[*] Sortie du programme.{C_END}")
        sys.exit(0)
        
    scan_function = modes[choix]

    # Traitement des extensions passées en argument (ex: "html,txt" -> ["html", "txt"])
    extensions_list = []
    if args.extensions:
        extensions_list = [e.strip() for e in args.extensions.split(",")]

    excluded_codes = []
    if args.filter_code:
        excluded_codes = [int(c.strip()) for c in args.filter_code.split(",")]

    try:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"{C_RED}[-] Erreur : Wordlist introuvable.{C_END}")
        sys.exit(1)

    config = {'excluded_codes': excluded_codes, 'base_size': None, 'extensions': extensions_list}
    
    if choix in ["3", "4"]:
        print(f"\n{C_YELLOW}[*] Calcul de la baseline...{C_END}")
        try:
            res_base = requests.get(target, headers={"User-Agent": USER_AGENTS[0]}, timeout=5, allow_redirects=False)
            config['base_size'] = len(res_base.content)
            print(f"{C_GREEN}[+] Baseline : {config['base_size']} bytes.{C_END}")
        except requests.RequestException:
            print(f"{C_RED}[-] Échec baseline.{C_END}")

    print(f"\n{C_GREEN}{C_BOLD}[*] Lancement du scan sur {target}...{C_END}\n")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(scan_function, w, target, config) for w in words]
            for future in concurrent.futures.as_completed(futures):
                if shutdown_flag: break
    except KeyboardInterrupt: pass

    print(f"\n{C_MAGENTA}{C_BOLD}[*] Scan terminé.{C_END}")

if __name__ == "__main__":
    main()
