# export_import.py

"""
Système complet d'exportation et d'importation des données cipher_manager
- Exporte : config, clés de chiffrement, arborescence, contenu des fichiers
- Importe : restaure tout proprement avec recréation des dossiers
- Format : JSON chiffré avec le mot de passe maître
"""

import orjson
import base64
import os
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from others.utils import c, inputc, printc, printl, get_path
from others.registry import get_cipher, hash_password
from crypto.scrypt import derive_key_scrypt
from setup import CONFIG_PATH, KEYS_PATH, load_config, encrypt_key_with_master, chiffrer_config
from manager import create_file_dat, derive_element_key, decrypt_name
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.console import Console

console = Console()

# ====================================
# EXPORTATION
# ====================================

def export_all_data(master_password: str, config: dict) -> bool:
    """
    Exporte toutes les données dans un fichier JSON chiffré
    
    Args:
        master_password: Mot de passe maître
        config: Configuration déchiffrée
        
    Returns:
        bool: True si succès, False si erreur
    """
    try:
        printc("\n📦 Début de l'exportation...", c['c'])
        
        # 1. Collecter toutes les données
        export_data = {
            "metadata": {
                "version": "1.0.0",
                "exported_at": datetime.now().isoformat(),
                "cipher_manager_version": "V1.0.2"
            },
            "config": {},
            "keys": {},
            "files_content": {}
        }
        
        # 2. Exporter la configuration
        printl("Exportation de la configuration...", "1")
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            export_data["config"] = orjson.loads(f.read())
        
        # 3. Exporter les clés
        printl("Exportation des clés...", "1")
        with open(KEYS_PATH, "r", encoding="utf-8") as f:
            export_data["keys"] = orjson.loads(f.read())
        
        # 4. Exporter le contenu des fichiers ET des dossiers
        printl("Exportation du contenu des fichiers et dossiers...", "1")
        tree = config.get("tree", {})
        data_path = Path(config.get("data_path", "."))
        
        # Exporter les dossiers
        folders_to_export = [(eid, item) for eid, item in tree.items() if item.get("type") == "folder"]
        for element_id, item in folders_to_export:
            # Ajouter les dossiers à l'export (pas de contenu, juste les métadonnées)
            export_data["files_content"][element_id] = {
                "content": "",  # Les dossiers n'ont pas de contenu
                "name_encrypted": item["name_encrypted"],
                "file_type": "folder",
                "parent": item.get("parent"),
                "salt": item["salt"],
                "cipher_method": item.get("cipher_method", "aes-gcm")
            }
        
        # Exporter les fichiers
        files_to_export = [(eid, item) for eid, item in tree.items() if item.get("type") == "file"]
        
        if files_to_export:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task("Exportation des fichiers...", total=len(files_to_export))
                
                for element_id, item in files_to_export:
                    try:
                        # Déchiffrer le contenu du fichier
                        file_path = data_path / f"{element_id}.dat"
                        if not file_path.exists():
                            # Chercher avec le préfixe ID
                            for f in data_path.glob(f"{element_id[:8]}_*"):
                                if f.is_file():
                                    file_path = f
                                    break
                        
                        if file_path.exists():
                            with open(file_path, 'rb') as f:
                                encrypted_bytes = f.read()
                            
                            # Dériver la clé et déchiffrer
                            salt = bytes.fromhex(item["salt"])
                            element_key, _ = derive_element_key(master_password, element_id, salt=salt)
                            
                            cipher_method = item.get("cipher_method", "aes-gcm")
                            cipher = get_cipher(cipher_method)
                            decrypt_fn = cipher["decrypt"]
                            
                            decrypted_bytes = decrypt_fn(encrypted_bytes, element_key)
                            decrypted_content = decrypted_bytes.decode('utf-8')
                            
                            # Stocker le contenu chiffré (en base64 pour JSON)
                            import base64
                            encrypted_content_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
                            
                            export_data["files_content"][element_id] = {
                                "content": encrypted_content_b64,
                                "name_encrypted": item["name_encrypted"],
                                "file_type": item.get("file_type", "note"),
                                "parent": item.get("parent"),
                                "salt": item["salt"],
                                "cipher_method": item.get("cipher_method", "aes-gcm")
                            }
                        
                        progress.update(task, advance=1)
                        
                    except Exception as e:
                        printl(f"Erreur exportation fichier {element_id}: {e}", "4")
                        progress.update(task, advance=1)
        
        # 5. Sérialiser et chiffrer
        printl("Chiffrement de l'export...", "1")
        export_json = orjson.dumps(export_data)
        
        # Chiffrer avec le mot de passe maître - SEL FIXE pour compatibilité
        export_salt = b"cipher_manager_export_fixed_salt"
        export_key, _ = derive_key_scrypt(master_password, salt=export_salt, length=32)
        cipher = get_cipher("aes-gcm")
        encrypted_export = cipher["encrypt"](export_json, export_key)
        
        # 6. Sauvegarder le fichier d'export
        export_filename = f"cipher_manager_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.cexp"
        export_path = get_path(export_filename)
        
        with open(export_path, "wb") as f:
            f.write(encrypted_export)
        
        printc(f"\n✅ Exportation réussie !", c['g'])
        printc(f"📁 Fichier : {export_path}", c['c'])
        printc(f"🔏 Chiffré avec votre mot de passe maître", c['y'])
        printc(f"📊 {len(files_to_export)} fichiers et {len(folders_to_export)} dossiers exportés", c['c'])
        
        return True
        
    except Exception as e:
        printc(f"\n❌ Erreur lors de l'exportation : {e}", c['r'])
        printl(f"Erreur exportation: {e}", "4")
        return False

# ====================================
# IMPORTATION
# ====================================

def import_all_data(master_password: str) -> bool:
    """
    Importe toutes les données depuis un fichier JSON chiffré
    
    Args:
        master_password: Mot de passe maître pour déchiffrer l'import
        
    Returns:
        bool: True si succès, False si erreur
    """
    try:
        printc("\n📥 Début de l'importation...", c['c'])
        
        # 1. Sélectionner le fichier d'import
        export_path = select_import_file()
        if not export_path:
            printc("❌ Aucun fichier sélectionné.", c['r'])
            return False
        
        # 2. Lire et déchiffrer le fichier
        printl("Déchiffrement de l'import...", "1")
        with open(export_path, "rb") as f:
            encrypted_data = f.read()
        
        # Déchiffrer avec le mot de passe maître - MÊME SEL FIXE
        import_salt = b"cipher_manager_export_fixed_salt"
        import_key, _ = derive_key_scrypt(master_password, salt=import_salt, length=32)
        cipher = get_cipher("aes-gcm")
        
        try:
            decrypted_bytes = cipher["decrypt"](encrypted_data, import_key)
        except Exception as e:
            printc("❌ Mot de passe incorrect ou fichier corrompu.", c['r'])
            printl(f"Erreur déchiffrement import: {e}", "4")
            return False
        
        import_data = orjson.loads(decrypted_bytes)
        
        # 3. Valider les métadonnées
        metadata = import_data.get("metadata", {})
        printl(f"Import de version {metadata.get('version', 'inconnue')}", "1")
        printl(f"Exporté le : {metadata.get('exported_at', 'inconnu')}", "1")
        
        # 4. Sauvegarder l'ancienne configuration si elle existe
        backup_existing_data()
        
        # 5. Importer les clés
        printl("Importation des clés...", "1")
        KEYS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(KEYS_PATH, "w", encoding="utf-8") as f:
            f.write(orjson.dumps(import_data["keys"]).decode())
        
        # 6. Importer la configuration
        printl("Importation de la configuration...", "1")
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            f.write(orjson.dumps(import_data["config"]).decode())
        
        # 7. Créer le dossier de données s'il n'existe pas
        config = load_config(master_password)
        data_path = Path(config.get("data_path", "."))
        data_path.mkdir(parents=True, exist_ok=True)
        
        # 8. Importer le contenu des fichiers et dossiers
        files_content = import_data.get("files_content", {})
        if files_content:
            printl(f"Importation de {len(files_content)} éléments...", "1")
            
            # Séparer les dossiers et les fichiers
            folders_to_import = {eid: data for eid, data in files_content.items() if data.get("file_type") == "folder"}
            files_to_import = {eid: data for eid, data in files_content.items() if data.get("file_type") != "folder"}
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task("Importation des éléments...", total=len(files_content))
                
                # Importer les dossiers d'abord
                for element_id, file_data in folders_to_import.items():
                    try:
                        name_encrypted = file_data["name_encrypted"]
                        parent_id = file_data.get("parent")
                        
                        # Créer le dossier physique avec l'ID original
                        folder_path = data_path / element_id
                        folder_path.mkdir(parents=True, exist_ok=True)
                        
                        # Ajouter le dossier à la configuration avec l'ID original
                        if "tree" not in config:
                            config["tree"] = {}
                        
                        config["tree"][element_id] = {
                            "type": "folder",
                            "name_encrypted": name_encrypted,
                            "parent": parent_id,
                            "salt": file_data["salt"],
                            "cipher_method": file_data.get("cipher_method", "aes-gcm"),
                            "created_at": datetime.now().isoformat()
                        }
                        
                        # Mettre à jour le parent si nécessaire
                        if parent_id and parent_id in config["tree"]:
                            if "children" not in config["tree"][parent_id]:
                                config["tree"][parent_id]["children"] = []
                            if element_id not in config["tree"][parent_id]["children"]:
                                config["tree"][parent_id]["children"].append(element_id)
                        
                        progress.update(task, advance=1, description=f"📁 {element_id[:8]}...")
                        
                    except Exception as e:
                        printl(f"Erreur importation dossier {element_id}: {e}", "4")
                        progress.update(task, advance=1, description=f"❌ Erreur {element_id[:8]}...")
                
                # Importer les fichiers ensuite
                for element_id, file_data in files_to_import.items():
                    try:
                        name_encrypted = file_data["name_encrypted"]
                        content = file_data["content"]
                        file_type = file_data.get("file_type", "note")
                        parent_id = file_data.get("parent")
                        
                        # Décoder le contenu base64 en bytes
                        import base64
                        if isinstance(content, str):
                            content_bytes = base64.b64decode(content)
                        else:
                            content_bytes = content
                        
                        # Créer le fichier directement avec l'ID original et le contenu chiffré
                        file_path = data_path / f"{element_id}.dat"
                        
                        # Écrire le contenu chiffré directement
                        with open(file_path, 'wb') as f:
                            f.write(content_bytes)
                        
                        # Ajouter le fichier à la configuration avec l'ID original
                        if "tree" not in config:
                            config["tree"] = {}
                        
                        config["tree"][element_id] = {
                            "type": "file",
                            "name_encrypted": name_encrypted,
                            "parent": parent_id,
                            "salt": file_data["salt"],
                            "cipher_method": file_data.get("cipher_method", "aes-gcm"),
                            "file_type": file_type,
                            "created_at": datetime.now().isoformat()
                        }
                        
                        # Mettre à jour le parent si nécessaire
                        if parent_id and parent_id in config["tree"]:
                            if "children" not in config["tree"][parent_id]:
                                config["tree"][parent_id]["children"] = []
                            if element_id not in config["tree"][parent_id]["children"]:
                                config["tree"][parent_id]["children"].append(element_id)
                        
                        progress.update(task, advance=1, description=f"📝 {element_id[:8]}...")
                        
                    except Exception as e:
                        printl(f"Erreur importation fichier {element_id}: {e}", "4")
                        progress.update(task, advance=1, description=f"❌ Erreur {element_id[:8]}...")
        
        # Sauvegarder la configuration mise à jour
        from manager import save_tree_to_config
        save_tree_to_config(config.get("tree", {}), master_password, config)
        
        printc(f"\n✅ Importation réussie !", c['g'])
        printc(f"📁 Données restaurées dans : {data_path}", c['c'])
        printc(f"🔏 Configuration et clés importées", c['y'])
        printc(f"📊 {len(files_to_import)} fichiers et {len(folders_to_import)} dossiers importés", c['c'])
        
        return True
        
    except Exception as e:
        printc(f"\n❌ Erreur lors de l'importation : {e}", c['r'])
        printl(f"Erreur importation: {e}", "4")
        return False

# ====================================
# UTILITAIRES
# ====================================

def select_import_file() -> Path | None:
    """
    Sélectionne un fichier d'import via input utilisateur
    
    Returns:
        Path: Chemin du fichier sélectionné ou None
    """
    while True:
        file_path = inputc("📂 Chemin du fichier d'import (.cexp) : ", c['c']).strip()
        
        if not file_path:
            return None
        
        import_path = Path(file_path)
        
        if not import_path.exists():
            printc("❌ Le fichier n'existe pas.", c['r'])
            continue
        
        if not import_path.suffix == '.cexp':
            printc("❌ Le fichier doit avoir l'extension .cexp", c['r'])
            continue
        
        return import_path

def backup_existing_data():
    """
    Crée une sauvegarde des données existantes avant importation
    """
    try:
        if CONFIG_PATH.exists():
            backup_path = get_path(f"backup_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            shutil.copy2(CONFIG_PATH, backup_path)
            printl(f"Configuration sauvegardée : {backup_path}", "2")
        
        if KEYS_PATH.exists():
            backup_path = get_path(f"backup_keys_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            shutil.copy2(KEYS_PATH, backup_path)
            printl(f"Clés sauvegardées : {backup_path}", "2")
            
    except Exception as e:
        printl(f"Erreur lors de la sauvegarde : {e}", "3")

def export_interactive(master_password: str, config: dict):
    """
    Interface interactive pour l'exportation
    """
    printc("\n=== EXPORTATION DES DONNÉES ===", c['c'])
    printc("Ceci va exporter :", c['y'])
    printc("• Configuration complète", c['w'])
    printc("• Clés de chiffrement", c['w'])
    printc("• Arborescence des dossiers/fichiers", c['w'])
    printc("• Contenu de tous les fichiers", c['w'])
    printc("• Le fichier sera chiffré avec votre mot de passe maître", c['y'])
    
    confirm = inputc("\n⚠️  Voulez-vous continuer ? (o/n) : ", c['y']).lower()
    if confirm != 'o':
        printc("❌ Exportation annulée.", c['r'])
        return
    
    success = export_all_data(master_password, config)
    if success:
        printc("\n🎉 Exportation terminée avec succès !", c['g'])
    else:
        printc("\n💥 Exportation échouée.", c['r'])

def import_interactive(master_password: str) -> bool:
    """
    Interface interactive pour l'importation
    """
    printc("\n=== IMPORTATION DES DONNÉES ===", c['c'])
    printc("⚠️  ATTENTION : Ceci va remplacer toutes vos données actuelles !", c['r'])
    printc("Une sauvegarde sera automatiquement créée.", c['y'])
    
    confirm = inputc("\n⚠️  Voulez-vous continuer ? (o/n) : ", c['y']).lower()
    if confirm != 'o':
        printc("❌ Importation annulée.", c['r'])
        return False
    
    success = import_all_data(master_password)
    if success:
        printc("\n🎉 Importation terminée avec succès !", c['g'])
        printc("🔄 Veuillez redémarrer l'application.", c['y'])
        return True
    else:
        printc("\n💥 Importation échouée.", c['r'])
        return False
