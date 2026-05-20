---

## 📋 Prérequis

L'outil nécessite l'installation de la bibliothèque Python `requests`.

```bash
pip install requests

🚀 Utilisation

Pour lancer l'outil, exécutez la commande suivante depuis votre terminal :
Bash

python3 Emnibuster.py -t <URL_CIBLE> -w <CHEMIN_WORDLIST> [OPTIONS]

Options disponibles
Option	Description	Exemple
-t, --target	[Requis] URL ou domaine de la cible	-t https://exemple.com
-w, --wordlist	[Requis] Chemin complet vers le fichier d'un dictionnaire	-w /usr/share/wordlists/dirb/common.txt
-threads	Nombre de threads simultanés (Défaut : 10)	-threads 40
-fc	Filtrer/Masquer certains codes HTTP	-fc 301,403
-x	Extensions de fichiers à tester (Mode 1 uniquement)	-x html,txt,php
💡 Exemples de Commandes
1. Scan de répertoires avec recherche de fichiers spécifiques :
Bash

python3 Emnibuster.py -t [https://exemple.com](https://exemple.com) -w wordlist.txt -x html,txt,php -threads 30

2. Scan rapide de sous-domaines en masquant les redirections (301) :
Bash

python3 Emnibuster.py -t exemple.com -w sous_domaines.txt -fc 301 -threads 50

⚠️ Avertissement Légal (Disclaimer)

Cet outil a été développé uniquement dans un but éducatif et de recherche en sécurité. L'utilisation d'Emnibuster contre des cibles sans autorisation écrite préalable est totalement illégale. L'auteur décline toute responsabilité quant à l'usage malveillant ou aux dommages causés par cet outil.

Développé avec 💜 par Emerick-19
