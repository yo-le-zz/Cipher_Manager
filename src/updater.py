# updater.py
import subprocess
import sys
import os
from pathlib import Path
from others.utils import printl, printc, c
import tempfile
import json

# Essayer d'importer requests, sinon utiliser urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False

def get_latest_release():
    """
    Récupère la dernière version depuis GitHub API
    """
    try:
        url = "https://api.github.com/repos/yo-le-zz/Cipher_Manager/releases/latest"
        
        if HAS_REQUESTS:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        else:
            with urllib.request.urlopen(url, timeout=10) as response:
                return json.loads(response.read().decode('utf-8'))
                
    except Exception as e:
        raise Exception(f"Erreur lors de la récupération de la version: {e}")

def download_file(url, filepath):
    """
    Télécharge un fichier depuis une URL
    """
    try:
        if HAS_REQUESTS:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            with open(filepath, 'wb') as f:
                f.write(response.content)
        else:
            urllib.request.urlretrieve(url, filepath)
            
    except Exception as e:
        raise Exception(f"Erreur lors du téléchargement: {e}")

def check_for_updates():
    """
    Vérifie si une mise à jour est disponible
    """
    try:
        latest_release = get_latest_release()
        latest_version = latest_release["tag_name"]
        
        # Version actuelle
        from main import version
        current_version = version
        
        printl(f"Version actuelle : {current_version}", "1")
        printl(f"Dernière version disponible : {latest_version}", "1")
        
        if current_version == latest_version:
            printl("✅ Vous êtes à jour !", "2")
            return False
        else:
            printl("🔄 Une mise à jour est disponible !", "3")
            return True
            
    except Exception as e:
        printl(f"❌ Erreur lors de la vérification des mises à jour : {e}", "4")
        return False

def download_and_install_update():
    """
    Télécharge et installe la mise à jour
    """
    try:
        printl("📥 Téléchargement de l'outil de mise à jour...", "1")
        
        # Télécharger update.exe
        update_url = "https://github.com/yo-le-zz/GenericUpdater/releases/latest/download/update.exe"
        
        # Créer un fichier temporaire pour update.exe
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            update_exe_path = temp_file.name
        
        download_file(update_url, update_exe_path)
        
        printl(f"📁 Fichier de mise à jour téléchargé : {update_exe_path}", "1")
        
        # Obtenir le nom du script/exécutable actuel
        if getattr(sys, 'frozen', False):
            # Exécutable PyInstaller
            executable_name = os.path.basename(sys.executable)
        else:
            # Script Python
            executable_name = os.path.basename(__file__).replace('updater.py', 'main.py')
        
        printl(f"🔧 Lancement de la mise à jour pour : {executable_name}", "1")
        
        # Construire la commande de mise à jour
        command = [
            update_exe_path,
            "--update",
            executable_name,
            f"yo-le-zz/{executable_name}"
        ]
        
        printl("🚀 Lancement de la mise à jour automatique...", "2")
        printl("L'application va redémarrer après la mise à jour.", "1")
        
        # Lancer update.exe dans un nouveau processus pour ne pas bloquer l'application actuelle
        subprocess.Popen(command, shell=True)
        
        # Donner le temps au processus de démarrer
        import time
        time.sleep(2)
        
        # Quitter l'application actuelle
        printl("👋 Fermeture de l'application pour la mise à jour...", "3")
        sys.exit(0)
        
    except Exception as e:
        printl(f"❌ Erreur lors de l'installation : {e}", "4")
        return False

def auto_update():
    """
    Fonction principale de mise à jour automatique
    """
    printc("\n" + "="*50, c['c'])
    printc("🔍 Vérification des mises à jour...", c['c'])
    printc("="*50, c['c'])
    
    if check_for_updates():
        # Demander confirmation à l'utilisateur
        from others.utils import inputc
        choice = inputc("Voulez-vous installer la mise à jour maintenant ? (o/n) : ", c['y']).lower()
        
        if choice == 'o':
            download_and_install_update()
        else:
            printl("❌ Mise à jour annulée.", "4")
    else:
        printl("✅ Aucune mise à jour nécessaire.", "2")
