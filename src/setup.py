# setup.py

import getpass
import sys
import os
from pathlib import Path
import orjson
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidTag

from others.utils import c, inputc, printc, printl, get_path
from others.registry import list_ciphers, hash_password, get_cipher
from crypto.scrypt import derive_key_scrypt

CONFIG_PATH = get_path("data/config.json")
KEYS_PATH = CONFIG_PATH.parent / "keys.json"

# --- Fonctions utilitaires ---

def decrypt_key_with_password(enc_info: dict, password: str) -> bytes:
    """
    Déchiffre une clé interne AESGCM stockée dans keys.json avec un mot de passe.
    Lève InvalidTag si le mot de passe est incorrect.
    """
    try:
        key_bytes = bytes.fromhex(enc_info["key"])
        salt = bytes.fromhex(enc_info["salt"])
        nonce = bytes.fromhex(enc_info["nonce"])
        derived_key, _ = derive_key_scrypt(password, salt=salt, length=32)
        aesgcm = AESGCM(derived_key)
        return aesgcm.decrypt(nonce, key_bytes, None)
    except InvalidTag:
        # Re-raise pour que l'appelant puisse gérer
        raise
    except Exception as e:
        printl(f"Erreur lors du déchiffrement de la clé : {e}", "4")
        raise ValueError(f"Impossible de déchiffrer la clé : {e}")


def load_config(password: str, use_backup: bool = False) -> dict:
    """
    Charge et déchiffre config.json avec keys.json.
    `use_backup` permet d'utiliser le mot de passe de secours.
    
    Raises:
        InvalidTag: Si le mot de passe est incorrect
        FileNotFoundError: Si config.json ou keys.json manquent
        ValueError: Si les données sont corrompues
    """
    try:
        # --- Vérifier l'existence des fichiers ---
        if not CONFIG_PATH.exists():
            raise FileNotFoundError(f"Fichier de configuration introuvable : {CONFIG_PATH}")
        if not KEYS_PATH.exists():
            raise FileNotFoundError(f"Fichier de clés introuvable : {KEYS_PATH}")
        
        # --- Lire les fichiers ---
        printl("Lecture des fichiers de configuration...", "1")
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config_json = json.load(f)
        with open(KEYS_PATH, "r", encoding="utf-8") as f:
            keys_json = json.load(f)

        # --- Vérifier la présence du mot de passe de secours si demandé ---
        if use_backup and "backup" not in keys_json.get("config", {}):
            raise ValueError("Aucun mot de passe de secours n'a été configuré.")

        # --- Choisir le mot de passe à utiliser pour la clé interne ---
        printl(f"Utilisation du mot de passe {'de secours' if use_backup else 'maître'}...", "1")
        group_key = keys_json["config"]["backup" if use_backup else "master"]
        internal_key = decrypt_key_with_password(group_key, password)
        printl("Clé interne déchiffrée avec succès.", "2")

        # --- Déchiffrement du payload ---
        cipher_method = config_json["secure"]["cipher_method"].lower()
        printl(f"Méthode de chiffrement détectée : {cipher_method}", "1")
        encrypted_payload_b64 = config_json["secure"]["config"]
        encrypted_bytes = base64.b64decode(encrypted_payload_b64)

        # Utiliser le bon cipher selon la méthode
        cipher = get_cipher(cipher_method)
        decrypt_fn = cipher["decrypt"]
        
        printl("Déchiffrement de la configuration...", "1")
        decrypted_bytes = decrypt_fn(encrypted_bytes, internal_key)
        printl("Configuration déchiffrée avec succès.", "2")

        # --- Convertir en dict ---
        decrypted_config = orjson.loads(decrypted_bytes)
        return decrypted_config
        
    except InvalidTag:
        # Mot de passe incorrect - on laisse remonter l'exception
        printl("Échec du déchiffrement : mot de passe incorrect", "4")
        raise
    except json.JSONDecodeError as e:
        printl(f"Erreur de format JSON : {e}", "4")
        raise ValueError(f"Fichier de configuration corrompu : {e}")
    except KeyError as e:
        printl(f"Clé manquante dans la configuration : {e}", "4")
        raise ValueError(f"Structure de configuration invalide : {e}")
    except Exception as e:
        printl(f"Erreur inattendue lors du chargement : {e}", "4")
        raise


def generate_internal_key() -> bytes:
    """Génère une clé symétrique aléatoire (32 bytes)."""
    return os.urandom(32)


def encrypt_key_with_master(internal_key: bytes, master_password: str) -> dict:
    """Chiffre une clé interne avec le mot de passe maître via AESGCM + dérivation Scrypt."""
    try:
        master_key, salt = derive_key_scrypt(master_password)
        aesgcm = AESGCM(master_key)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, internal_key, None)
        return {
            "key": encrypted.hex(),
            "salt": salt.hex(),
            "nonce": nonce.hex()
        }
    except Exception as e:
        printl(f"Erreur lors du chiffrement de la clé : {e}", "4")
        raise


def chiffrer_config(config_data: dict, internal_key: bytes) -> bytes:
    """
    Chiffre la configuration avec la clé interne.
    
    Raises:
        ValueError: Si les données sont invalides
    """
    try:
        # --- Hash des mots de passe ---
        auth = config_data.get("auth", {})
        password = auth.get("password")
        backup_password = auth.get("backup_password")
        hash_method = auth.get("hash_method")

        printl(f"Hachage des mots de passe avec {hash_method}...", "1")
        auth["password"] = (
            hash_password(password, method=hash_method).decode()
            if password else None
        )
        auth["backup_password"] = (
            hash_password(backup_password, method=hash_method).decode()
            if backup_password else None
        )

        # --- Chiffrement du payload ---
        secure = config_data.get("secure", {})
        cipher_method = secure.get("cipher_method").lower()
        cipher = get_cipher(cipher_method)

        payload_dict = secure.get("config", {})
        payload_bytes = orjson.dumps(payload_dict)

        printl(f"Chiffrement de la configuration avec {cipher_method}...", "1")
        encrypt_fn = cipher["encrypt"]
        encrypted_payload = encrypt_fn(payload_bytes, internal_key)

        secure["config"] = base64.b64encode(encrypted_payload).decode()

        return orjson.dumps(config_data, option=orjson.OPT_INDENT_2)
    
    except Exception as e:
        printl(f"Erreur lors du chiffrement de la configuration : {e}", "4")
        raise


def setup_keys_file(internal_key: bytes, password_master: str, password_backup: str | None = None):
    """
    Crée le fichier keys.json avec les clés chiffrées.
    
    Raises:
        IOError: Si l'écriture échoue
    """
    try:
        keys_data = {
            "config": {
                "master": encrypt_key_with_master(internal_key, password_master)
            }
        }

        if password_backup:
            keys_data["config"]["backup"] = encrypt_key_with_master(internal_key, password_backup)

        # user_data peut avoir sa propre clé
        user_key = generate_internal_key()
        keys_data["user_data"] = {
            "master": encrypt_key_with_master(user_key, password_master)
        }
        if password_backup:
            keys_data["user_data"]["backup"] = encrypt_key_with_master(user_key, password_backup)

        printl(f"Écriture du fichier de clés : {KEYS_PATH}", "1")
        with open(KEYS_PATH, "w", encoding="utf-8") as f:
            json.dump(keys_data, f, indent=2)
        printl("Fichier de clés créé avec succès.", "2")
        
    except Exception as e:
        printl(f"Erreur lors de la création du fichier de clés : {e}", "4")
        raise


# --- Setup principal ---

def setup():
    """
    Procédure de configuration initiale de cipher_manager.
    """
    try:
        printc("=== setup de cipher_manager ===", c['c'])

        # --- Infos utilisateur ---
        username = inputc("Entrer un nom d'utilisateur : ", c['c'])
        if not username.strip():
            printc("❌ Le nom d'utilisateur ne peut pas être vide.", c['r'])
            sys.exit(0)
        printl(f"Nom d'utilisateur : {username}", "2")

        data_path = inputc("Entrer un chemin où stocker les données : ", c['c'])
        if not data_path.strip():
            printc("❌ Le chemin ne peut pas être vide.", c['r'])
            sys.exit(0)
            
        if not Path(data_path).exists():
            create = inputc("Chemin inexistant, voulez-vous le créer ? (o/n) : ", c['c'])
            if create.lower() == "o":
                Path(data_path).mkdir(parents=True, exist_ok=True)
                printl(f"Chemin créé : {data_path}", "2")
            else:
                printc("Setup annulé.", c['r'])
                sys.exit(0)

        printl(f"Chemin des données : {data_path}", "1")

        # --- Méthodes de chiffrement ---
        printc("=== Méthodes de chiffrement disponibles ===", c['c'])
        cipher_methods = list_ciphers(exclude_hashes=True)
        for i, m in enumerate(cipher_methods, 1):
            printc(f"{i}. {m}", c['c'])
        
        try:
            cipher_choice = int(inputc("Quelle methode de chiffrement souhaitez-vous utiliser ? : ", c['c']))
            if cipher_choice < 1 or cipher_choice > len(cipher_methods):
                raise ValueError("Choix invalide")
            selected_cipher_method = cipher_methods[cipher_choice - 1]
            printc(f"Vous avez sélectionné la méthode : {selected_cipher_method}", c['g'])
        except (ValueError, IndexError):
            printc("❌ Choix invalide. Setup annulé.", c['r'])
            sys.exit(0)

        # --- Méthodes de hash ---
        printc("=== Méthodes de stockage sécurisée des mots de passe ===", c['c'])
        hash_methods = list_ciphers(exclude_none_hashes=True)
        for i, m in enumerate(hash_methods, 1):
            printc(f"{i}. {m}", c['c'])
        
        try:
            hash_choice = int(inputc("Quelle methode de hash souhaitez-vous utiliser ? : ", c['c']))
            if hash_choice < 1 or hash_choice > len(hash_methods):
                raise ValueError("Choix invalide")
            selected_hash_method = hash_methods[hash_choice - 1]
            printc(f"Vous avez sélectionné la méthode : {selected_hash_method}", c['g'])
        except (ValueError, IndexError):
            printc("❌ Choix invalide. Setup annulé.", c['r'])
            sys.exit(0)

        # --- Mot de passe ---
        password = getpass.getpass("Entrer un mot de passe maître : ")
        if not password:
            printc("❌ Le mot de passe ne peut pas être vide.", c['r'])
            sys.exit(0)
            
        password_confirm = getpass.getpass("Confirmer le mot de passe maître : ")
        if password != password_confirm:
            printc("❌ Les mots de passe ne correspondent pas. Fermeture.", c['r'])
            sys.exit(0)

        choice = inputc("Voulez-vous un mot de passe de secours ? (o/n) : ", c['c'])
        password_backup = None
        if choice.lower() == "o":
            password_backup = getpass.getpass("Entrer un mot de passe de secours : ")
            if not password_backup:
                printc("❌ Le mot de passe de secours ne peut pas être vide.", c['r'])
                sys.exit(0)
                
            backup_confirm = getpass.getpass("Confirmer le mot de passe de secours : ")
            if password_backup != backup_confirm:
                printc("❌ Les mots de passe de secours ne correspondent pas. Fermeture.", c['r'])
                sys.exit(0)

        # --- Config finale ---
        config_data = {
            "auth": {
                "hash_method": selected_hash_method,
                "password": password,
                "backup_password": password_backup,
            },
            "secure": {
                "cipher_method": selected_cipher_method,
                "config": {
                    "username": username,
                    "data_path": data_path,
                }
            }
        }

        # --- Génération de la clé interne ---
        printl("Génération de la clé interne...", "1")
        internal_key = generate_internal_key()

        # --- Création du dossier data s'il n'existe pas ---
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

        # --- Chiffrement et sauvegarde de la config ---
        printl("Chiffrement et sauvegarde de la configuration...", "1")
        secure_data = chiffrer_config(config_data, internal_key)
        with open(CONFIG_PATH, "wb") as f:
            f.write(secure_data)
        printl(f"Configuration sauvegardée : {CONFIG_PATH}", "2")

        # --- Sauvegarde des clés internes ---
        setup_keys_file(internal_key, password, password_backup)

        printl("Configuration sauvegardée avec succès.", "2")
        printc("✅ Setup terminé ! Redémarrez l'application.", c['g'])
        sys.exit(0)
        
    except KeyboardInterrupt:
        printc("\n❌ Setup interrompu par l'utilisateur.", c['y'])
        sys.exit(0)
    except Exception as e:
        printc(f"\n❌ Erreur critique durant le setup : {e}", c['r'])
        printl(f"Erreur setup : {e}", "5")
        sys.exit(1)