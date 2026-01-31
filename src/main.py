# main.py

# Autres scripts
from others.utils import c, inputc, printc, printl, get_app_path, get_path
from setup import setup, load_config
from others.cache import cache_manager
from updater import auto_update

# librairies headers
import signal
import atexit

# librairies d'écriture de données
import orjson

# Librairies système
import sys
from pathlib import Path

# librairies sécurité
import getpass

# Exceptions cryptographiques
from cryptography.exceptions import InvalidTag

APP_ROOT = get_app_path()
CONFIG_PATH = get_path("data/config.json")
MAX_ATTEMPTS = 3

def cleanup_on_exit():
    """
    Fonction appelée lors de la fermeture
    Avertit si des fichiers sont déchiffrés
    """
    try:
        # Vérifier s'il y a des données à rechiffrer
        if cache_manager.data.get("mappings"):
            printc("\n" + "="*60, c['r'])
            printc("⚠️  ATTENTION : Des fichiers sont déchiffrés !", c['r'])
            printc("="*60, c['r'])
            printc("\n🔐 Vous devez relancer l'application et :", c['y'])
            printc("   1. Utiliser l'option 7 (Rechiffrer)", c['y'])
            printc("   2. Utiliser l'option 0 (Quitter proprement)", c['y'])
            printc("\n💡 Les fichiers déchiffrés sont visibles dans l'explorateur !", c['y'])
            printc("="*60 + "\n", c['r'])
    except Exception as e:
        printl(f"Erreur lors du cleanup : {e}", "4")


def signal_handler(signum, frame):
    """
    Gère les signaux d'interruption (Ctrl+C, etc.)
    """
    printc("\n\n⚠️  Interruption détectée !", c['y'])
    cleanup_on_exit()
    sys.exit(0)

def check_config():
    if CONFIG_PATH.exists():
        return True
    else:
        return False

version = "V1.0.1"

def main():
    # Vérification des mises à jour au démarrage
    auto_update()
    
    first_launch = check_config()
    printl(f"Chemin de recherche : {CONFIG_PATH}", "1")
    
    if first_launch:
        printl("Configuration trouvée.", "1")
        printc("=== cipher_manager ===", c['c'])
        
        # Tentatives de connexion
        attempts = 0
        while attempts < MAX_ATTEMPTS:
            try:
                master_pass = getpass.getpass("Entrer le mot de passe maître : ")
                
                if not master_pass:
                    printc("❌ Le mot de passe ne peut pas être vide.", c['r'])
                    attempts += 1
                    continue
                
                cfg = load_config(master_pass)
                printl("Déchiffrement réussi.", "2")
                
                # Lancer le menu
                from menu import menu
                menu(cfg, master_pass)
                break
                
            except InvalidTag:
                attempts += 1
                remaining = MAX_ATTEMPTS - attempts
                
                if remaining > 0:
                    printc(f"❌ Mot de passe incorrect. Il vous reste {remaining} tentative(s).", c['r'])
                    
                    # Proposer le mot de passe de secours après 2 échecs
                    if attempts == 2:
                        use_backup = inputc("Voulez-vous utiliser le mot de passe de secours ? (o/n) : ", c['y']).lower()
                        if use_backup == 'o':
                            try:
                                backup_pass = getpass.getpass("Entrer le mot de passe de secours : ")
                                cfg = load_config(backup_pass, use_backup=True)
                                printl("Déchiffrement avec mot de passe de secours réussi.", "2")
                                
                                # Lancer le menu
                                from menu import menu
                                menu(cfg, backup_pass)
                                return
                            except InvalidTag:
                                printc("❌ Mot de passe de secours incorrect.", c['r'])
                            except Exception as e:
                                printc(f"❌ Erreur : {e}", c['r'])
                else:
                    printc("❌ Trop de tentatives échouées. Fermeture de l'application.", c['r'])
                    printl("Accès refusé après 3 tentatives", "4")
                    sys.exit(1)
                    
            except FileNotFoundError as e:
                printc(f"❌ Fichier manquant : {e}", c['r'])
                printl(f"Erreur FileNotFoundError: {e}", "4")
                sys.exit(1)
                
            except Exception as e:
                printc(f"❌ Erreur inattendue : {e}", c['r'])
                printl(f"Erreur lors du chargement de la config: {e}", "4")
                sys.exit(1)
    else:
        printl("Aucune configuration trouvée. Lancement du setup", "1")
        setup()

# Enregistrer les handlers
atexit.register(cleanup_on_exit)
signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
signal.signal(signal.SIGTERM, signal_handler)  # Kill

if __name__ == "__main__":
    main()