# manager.py

"""
Gestionnaire des opérations sur l'arborescence chiffrée
- Génération d'IDs uniques
- Création/suppression de dossiers et fichiers
- Navigation dans l'arborescence
"""

import uuid
from pathlib import Path
from datetime import datetime
import getpass
import json
import base64

from others.cache import cache_manager
from others.utils import c, inputc, printc, printl, get_path
from others.registry import get_cipher
from crypto.scrypt import derive_key_scrypt
from setup import CONFIG_PATH, KEYS_PATH, load_config, decrypt_key_with_password
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.console import Console

console = Console()

# ====================================
# GÉNÉRATION D'IDS UNIQUES
# ====================================

def generate_id() -> str:
    """
    Génère un ID unique pour un élément (dossier ou fichier)
    Format: UUID4 sans tirets (32 caractères hexadécimaux)
    """
    return uuid.uuid4().hex


# ====================================
# DÉRIVATION DE CLÉS PAR ÉLÉMENT
# ====================================

def derive_element_key(master_password: str, element_id: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Dérive une clé unique pour un élément spécifique
    
    Args:
        master_password: Mot de passe maître
        element_id: ID unique de l'élément
        salt: Salt optionnel (si None, un nouveau salt est généré)
    
    Returns:
        (key, salt): Clé dérivée et salt utilisé
    """
    # Combine master_password + element_id pour avoir une clé unique par élément
    combined = f"{master_password}:{element_id}"
    key, salt = derive_key_scrypt(combined, salt=salt, length=32)
    return key, salt


# ====================================
# CHIFFREMENT/DÉCHIFFREMENT DE NOMS
# ====================================

def encrypt_name(name: str, element_key: bytes, cipher_method: str = "aes-gcm") -> dict:
    """
    Chiffre un nom d'élément
    
    Returns:
        dict avec 'encrypted' (base64) et 'salt' (hex)
    """
    cipher = get_cipher(cipher_method)
    encrypt_fn = cipher["encrypt"]
    
    name_bytes = name.encode('utf-8')
    encrypted_bytes = encrypt_fn(name_bytes, element_key)
    
    return {
        "encrypted": base64.b64encode(encrypted_bytes).decode(),
        "cipher_method": cipher_method
    }


def decrypt_name(encrypted_data: dict, element_key: bytes) -> str:
    """
    Déchiffre un nom d'élément
    
    Args:
        encrypted_data: Dict avec 'encrypted' et 'cipher_method'
        element_key: Clé de déchiffrement
    
    Returns:
        Nom déchiffré
    """
    cipher_method = encrypted_data.get("cipher_method", "aes-gcm")
    cipher = get_cipher(cipher_method)
    decrypt_fn = cipher["decrypt"]
    
    encrypted_bytes = base64.b64decode(encrypted_data["encrypted"])
    decrypted_bytes = decrypt_fn(encrypted_bytes, element_key)
    
    return decrypted_bytes.decode('utf-8')


# ====================================
# GESTION DE LA CONFIG
# ====================================

def load_tree_from_config(master_password: str) -> dict:
    """
    Charge l'arborescence depuis la config
    
    Returns:
        dict: Arborescence complète
    """
    config = load_config(master_password)
    return config.get("tree", {})


def save_tree_to_config(tree: dict, master_password: str, config_data: dict):
    """
    Sauvegarde l'arborescence dans la config
    
    Args:
        tree: Arborescence à sauvegarder
        master_password: Mot de passe maître
        config_data: Config complète déchiffrée
    """
    from setup import chiffrer_config, generate_internal_key
    import json
    
    # Mettre à jour l'arborescence dans la config
    config_data["tree"] = tree
    
    # Charger la clé interne depuis keys.json
    with open(KEYS_PATH, "r", encoding="utf-8") as f:
        keys_json = json.load(f)
    
    group_key = keys_json["config"]["master"]
    internal_key = decrypt_key_with_password(group_key, master_password)
    
    # Re-chiffrer la config complète
    # Note: On doit recréer la structure auth + secure
    auth_section = {
        "hash_method": config_data.get("hash_method", "bcrypt"),
        "password": config_data.get("hashed_password"),
        "backup_password": config_data.get("hashed_backup_password")
    }
    
    secure_section = {
        "cipher_method": config_data.get("cipher_method", "aes-gcm"),
        "config": config_data  # La config déchiffrée complète
    }
    
    full_config = {
        "auth": auth_section,
        "secure": secure_section
    }
    
    secure_data = chiffrer_config(full_config, internal_key)
    
    with open(CONFIG_PATH, "wb") as f:
        f.write(secure_data)
    
    printl("Arborescence sauvegardée dans la config", "2")


# ====================================
# CRÉATION DE DOSSIER
# ====================================

def create_folder(
    name: str,
    parent_id: str | None,
    master_password: str,
    config_data: dict,
    data_path: Path
) -> str:
    """
    Crée un nouveau dossier dans l'arborescence
    
    Args:
        name: Nom du dossier (en clair)
        parent_id: ID du dossier parent (None pour racine)
        master_password: Mot de passe maître
        config_data: Configuration déchiffrée
        data_path: Chemin racine des données
    
    Returns:
        str: ID du dossier créé
    """
    printl(f"Création du dossier '{name}'...", "1")
    
    # 1. Générer un ID unique
    folder_id = generate_id()
    printl(f"ID généré: {folder_id}", "1")
    
    # 2. Dériver une clé unique pour ce dossier
    element_key, salt = derive_element_key(master_password, folder_id)
    
    # 3. Chiffrer le nom
    cipher_method = config_data.get("cipher_method", "aes-gcm")
    encrypted_name = encrypt_name(name, element_key, cipher_method)
    
    # 4. Créer le dossier physique avec nom chiffré
    # Le nom physique est l'ID (pour éviter les collisions)
    physical_folder = data_path / folder_id
    physical_folder.mkdir(parents=True, exist_ok=True)
    printl(f"Dossier physique créé: {physical_folder}", "2")
    
    # 5. Créer l'entrée dans l'arborescence
    tree = config_data.get("tree", {})
    
    folder_entry = {
        "type": "folder",
        "id": folder_id,
        "name_encrypted": encrypted_name,
        "salt": salt.hex(),
        "children": [],
        "parent": parent_id,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    
    tree[folder_id] = folder_entry
    
    # 6. Ajouter aux enfants du parent si ce n'est pas la racine
    if parent_id and parent_id in tree:
        if folder_id not in tree[parent_id]["children"]:
            tree[parent_id]["children"].append(folder_id)
            tree[parent_id]["updated_at"] = datetime.now().isoformat()
    
    # 7. Sauvegarder dans la config
    save_tree_to_config(tree, master_password, config_data)
    
    printc(f"✅ Dossier '{name}' créé avec succès (ID: {folder_id})", c['g'])
    return folder_id


# ====================================
# INITIALISATION DE L'ARBORESCENCE
# ====================================

def init_tree_if_needed(master_password: str, config_data: dict, data_path: Path):
    """
    Initialise l'arborescence avec un dossier racine si elle n'existe pas
    
    Args:
        master_password: Mot de passe maître
        config_data: Configuration déchiffrée
        data_path: Chemin racine des données
    """
    tree = config_data.get("tree", {})
    
    # Vérifier s'il y a déjà un dossier racine
    root_exists = any(
        item.get("type") == "folder" and item.get("parent") is None 
        for item in tree.values()
    )
    
    if not root_exists:
        printl("Aucune arborescence détectée, création du dossier racine...", "3")
        root_id = create_folder(
            name="Root",
            parent_id=None,
            master_password=master_password,
            config_data=config_data,
            data_path=data_path
        )
        printc(f"📁 Dossier racine créé (ID: {root_id})", c['c'])
    else:
        printl("Arborescence existante détectée.", "1")


# ====================================
# FONCTION PUBLIQUE POUR LE MENU
# ====================================

def is_name_taken(tree: dict, parent_id: str, name_to_check: str, master_password: str) -> bool:
    """Vérifie si un nom existe déjà dans un dossier parent en déchiffrant les noms existants."""
    if not isinstance(tree, dict): # Sécurité contre l'erreur 'str'
        return False
        
    for item_id, item in tree.items():
        if item.get("parent") == parent_id:
            try:
                # On doit déchiffrer pour comparer avec le texte en clair saisi par l'user
                salt = bytes.fromhex(item["salt"])
                element_key, _ = derive_element_key(master_password, item_id, salt=salt)
                decrypted_name = decrypt_name(item["name_encrypted"], element_key)
                
                if decrypted_name.lower() == name_to_check.lower():
                    return True
            except Exception:
                continue
    return False

def create_folder_interactive(master_password: str, config_data: dict, current_folder_id: str = None):
    """
    Crée un dossier de manière interactive en vérifiant les doublons.
    """
    console.print("\n[cyan]═══ Création d'un nouveau dossier ═══[/cyan]\n")
    
    # Demander le nom et nettoyer les espaces
    folder_name = inputc("📝 Nom du dossier : ", c['c']).strip()
    
    if not folder_name:
        printc("❌ Le nom ne peut pas être vide.", c['r'])
        return None
    
    # Récupérer l'arborescence
    tree = config_data.get("tree", {})
    if not isinstance(tree, dict):
        tree = {}

    # --- VÉRIFICATION DE SÉCURITÉ MISE À JOUR ---
    if is_name_taken(tree, current_folder_id, folder_name, master_password):
        printc(f"❌ Erreur : Un élément nommé '{folder_name}' existe déjà ici.", c['r'])
        return None
    # --------------------------------
    
    data_path = Path(config_data.get("data_path", "."))
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Création en cours...", total=100)
            
            # Étape 1 : Logique de création physique et config
            progress.update(task, advance=30, description="Génération de l'ID...")
            
            # Appel à la fonction create_folder existante qui gère l'écriture
            folder_id = create_folder(
                name=folder_name,
                parent_id=current_folder_id,
                master_password=master_password,
                config_data=config_data,
                data_path=data_path
            )
            
            progress.update(task, advance=70, description="✅ Terminé !")
            
        printc(f"✅ Dossier '{folder_name}' créé avec succès.", c['g'])
        return folder_id
        
    except Exception as e:
        printc(f"❌ Erreur lors de la création : {e}", c['r'])
        printl(f"Erreur create_folder: {e}", "4")
        return None


# ====================================
# DÉPLACEMENT DE DOSSIERS
# ====================================

def move_element(
    element_id: str,
    new_parent_id: str,
    master_password: str,
    config_data: dict
) -> bool:
    """
    Déplace un élément (dossier OU fichier) vers un nouveau parent
    """
    tree = config_data.get("tree", {})
    
    if element_id not in tree:
        printc("❌ Élément source introuvable.", c['r'])
        return False
    
    if new_parent_id not in tree:
        printc("❌ Dossier destination introuvable.", c['r'])
        return False
    
    element = tree[element_id]
    element_type = element.get("type")
    old_parent_id = element.get("parent")
    
    # Vérifier que la destination est un dossier
    if tree[new_parent_id].get("type") != "folder":
        printc("❌ La destination doit être un dossier.", c['r'])
        return False
    
    # Pour les dossiers, vérifier qu'on ne crée pas une boucle
    if element_type == "folder":
        if new_parent_id == element_id:
            printc("❌ Impossible de déplacer un dossier dans lui-même.", c['r'])
            return False
        
        current = new_parent_id
        while current:
            if current == element_id:
                printc("❌ Impossible de déplacer un dossier dans un de ses enfants.", c['r'])
                return False
            current = tree.get(current, {}).get("parent")
    
    printl(f"Déplacement de {element_id} vers {new_parent_id}...", "1")
    
    # Retirer des enfants de l'ancien parent
    if old_parent_id and old_parent_id in tree:
        if element_id in tree[old_parent_id].get("children", []):
            tree[old_parent_id]["children"].remove(element_id)
            tree[old_parent_id]["updated_at"] = datetime.now().isoformat()
    
    # Ajouter aux enfants du nouveau parent
    if "children" not in tree[new_parent_id]:
        tree[new_parent_id]["children"] = []
    if element_id not in tree[new_parent_id]["children"]:
        tree[new_parent_id]["children"].append(element_id)
        tree[new_parent_id]["updated_at"] = datetime.now().isoformat()
    
    # Mettre à jour le parent de l'élément
    element["parent"] = new_parent_id
    element["updated_at"] = datetime.now().isoformat()
    
    # Sauvegarder
    save_tree_to_config(tree, master_password, config_data)
    
    printc(f"✅ {'Dossier' if element_type == 'folder' else 'Fichier'} déplacé avec succès.", c['g'])
    return True


def move_element_interactive(master_password: str, config_data: dict, current_folder_id: str) -> bool:
    """
    Déplace un élément (dossier OU fichier) de manière interactive
    
    Args:
        master_password: Mot de passe maître
        config_data: Configuration déchiffrée
        current_folder_id: ID du dossier actuel
    
    Returns:
        bool: True si déplacement effectué
    """
    from rich.table import Table
    
    console.print("\n[cyan]═══ Déplacement de dossier ═══[/cyan]\n")
    
    tree = config_data.get("tree", {})
    
    # Afficher les enfants du dossier actuel
    children = get_folder_children(tree, current_folder_id, master_password)

    if not children:
        printc("❌ Aucun élément à déplacer ici.", c['r'])
        return False
    
    # Tableau des éléments disponibles
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Nom de l'élément", style="white")
    
    for i, folder in enumerate(children, 1):
        table.add_row(str(i), f"📁 {folder['name']}" if folder['type'] == 'folder' else f"📄 {folder['name']}")
    
    console.print(table)
    console.print()
    
    # Sélection du dossier à déplacer
    try:
        choice = int(inputc("Quel élément voulez-vous déplacer ? (numéro) : ", c['c']).strip())
        if choice < 1 or choice > len(children):
            printc("❌ Numéro invalide.", c['r'])
            return False
        
        selected_folder = children[choice - 1]
        folder_id = selected_folder["id"]
        
        printc(f"\n📁 Élément sélectionné : {selected_folder['name']}", c['c'])
        
    except ValueError:
        printc("❌ Entrée invalide.", c['r'])
        return False
    
    # Choisir la destination
    console.print("\n[cyan]Où voulez-vous déplacer ce dossier ?[/cyan]")
    console.print("[dim]Entrez le chemin de navigation (ex: .. pour parent, 1 pour premier enfant, etc.)[/dim]\n")
    
    # Pour simplifier, on demande juste de naviguer d'abord
    printc("💡 Astuce : Naviguez d'abord vers le dossier de destination,", c['y'])
    printc("   puis utilisez cette option pour déplacer.", c['y'])
    
    # Lister tous les dossiers possibles
    all_folders = [(fid, f) for fid, f in tree.items() if f.get("type") == "folder" and fid != folder_id]
    
    table2 = Table(show_header=True, header_style="bold cyan")
    table2.add_column("#", style="dim", width=4)
    table2.add_column("Destination", style="white")
    
    destinations = []
    for i, (fid, folder_data) in enumerate(all_folders, 1):
        salt = bytes.fromhex(folder_data["salt"])
        element_key, _ = derive_element_key(master_password, fid, salt=salt)
        dest_name = decrypt_name(folder_data["name_encrypted"], element_key)
        destinations.append((fid, dest_name))
        table2.add_row(str(i), f"📁 {dest_name}")
    
    console.print(table2)
    console.print()
    
    try:
        dest_choice = int(inputc("Vers quel dossier ? (numéro) : ", c['c']).strip())
        if dest_choice < 1 or dest_choice > len(destinations):
            printc("❌ Numéro invalide.", c['r'])
            return False
        
        new_parent_id, dest_name = destinations[dest_choice - 1]
        
        # Confirmation
        printc(f"\n🔄 Déplacer '{selected_folder['name']}' vers '{dest_name}' ?", c['y'])
        confirm = inputc("Confirmer (o/n) : ", c['y']).lower()
        
        if confirm != 'o':
            printc("❌ Annulé.", c['r'])
            return False
        
        # Effectuer le déplacement
        return move_element(folder_id, new_parent_id, master_password, config_data)
        
    except ValueError:
        printc("❌ Entrée invalide.", c['r'])
        return False


# ====================================
# NAVIGATION DANS L'ARBORESCENCE
# ====================================

def get_folder_children(tree: dict, folder_id: str, master_password: str) -> list:
    """
    Récupère les enfants d'un dossier déchiffrés
    Gère aussi le dossier virtuel __ROOT__
    
    Args:
        tree: Arborescence complète
        folder_id: ID du dossier (ou "__ROOT__" pour le niveau racine)
        master_password: Mot de passe maître
    
    Returns:
        list: Liste de dicts avec id, name, type, created_at
    """
    # ===== CAS SPÉCIAL : Dossier virtuel __ROOT__ =====
    if folder_id == "__ROOT__":
        # Retourner tous les dossiers sans parent
        root_folders = []
        for elem_id, elem_data in tree.items():
            if elem_data.get("type") == "folder" and elem_data.get("parent") is None:
                # Déchiffrer le nom
                salt = bytes.fromhex(elem_data["salt"])
                element_key, _ = derive_element_key(master_password, elem_id, salt=salt)
                decrypted_name = decrypt_name(elem_data["name_encrypted"], element_key)
                
                root_folders.append({
                    "id": elem_id,
                    "name": decrypted_name,
                    "type": "folder",
                    "created_at": elem_data.get("created_at", "N/A")
                })
        
        # Trier par nom
        return sorted(root_folders, key=lambda x: x["name"])
    
    # ===== CAS NORMAL : Dossier existant =====
    if folder_id not in tree:
        return []
    
    children_ids = tree[folder_id].get("children", [])
    children_info = []
    
    for child_id in children_ids:
        if child_id not in tree:
            continue
        
        child = tree[child_id]
        
        # Déchiffrer le nom
        salt = bytes.fromhex(child["salt"])
        element_key, _ = derive_element_key(master_password, child_id, salt=salt)
        decrypted_name = decrypt_name(child["name_encrypted"], element_key)
        
        children_info.append({
            "id": child_id,
            "name": decrypted_name,
            "type": child["type"],
            "created_at": child.get("created_at", "N/A")
        })
    
    return children_info


def navigate_interactive(master_password: str, config_data: dict, current_folder_id: str) -> str:
    """
    Navigation interactive dans l'arborescence
    Supporte le dossier virtuel __ROOT__
    
    Args:
        master_password: Mot de passe maître
        config_data: Configuration déchiffrée
        current_folder_id: ID du dossier actuel (ou "__ROOT__")
    
    Returns:
        str: ID du nouveau dossier actuel
    """
    from rich.table import Table
    
    tree = config_data.get("tree", {})
    
    # ===== AFFICHAGE DU TITRE =====
    # CAS SPÉCIAL : Niveau racine virtuel
    if current_folder_id == "__ROOT__":
        console.print("\n[cyan]═══ 🌍 Racine du système ═══[/cyan]\n")
    else:
        # Dossier normal
        current_folder = tree.get(current_folder_id)
        if not current_folder:
            printc("❌ Dossier introuvable.", c['r'])
            printc("Redemarrer le programme.", c['r'])
            return current_folder_id
        
        # Déchiffrer et afficher le nom
        salt = bytes.fromhex(current_folder["salt"])
        element_key, _ = derive_element_key(master_password, current_folder_id, salt=salt)
        folder_name = decrypt_name(current_folder["name_encrypted"], element_key)
        console.print(f"\n[cyan]═══ 📂 {folder_name} ═══[/cyan]\n")
    
    # ===== RÉCUPÉRER LES ENFANTS =====
    children = get_folder_children(tree, current_folder_id, master_password)
    
    if not children:
        console.print("[dim]📭 Ce dossier est vide.[/dim]\n")
    else:
        # Afficher le tableau des enfants
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Type", width=10)
        table.add_column("Nom", style="white")
        table.add_column("Créé le", style="dim", width=12)
        
        for i, child in enumerate(children, 1):
            # Icône selon le type
            if child["type"] == "folder":
                icon = "📁"
                type_label = "folder"
            else:
                icon = "📄"
                type_label = "file"
            
            # Date formatée
            created_date = child.get("created_at", "N/A")
            if created_date != "N/A":
                try:
                    created_date = created_date.split("T")[0]
                except:
                    pass
            
            table.add_row(
                str(i),
                f"{icon} {type_label}",
                child["name"],
                created_date
            )
        
        console.print(table)
    
    # ===== OPTIONS DE NAVIGATION =====
    console.print("\n[dim]Options:[/dim]")
    console.print("[cyan]  [numéro][/cyan] - Entrer dans le dossier")
    
    # Afficher ".." seulement si on n'est pas au niveau racine virtuel
    if current_folder_id != "__ROOT__":
        console.print("[cyan]  ..[/cyan] - Dossier parent")
    
    console.print("[cyan]  m[/cyan] - Déplacer un élément")
    console.print("[cyan]  q[/cyan] - Quitter la navigation")
    
    # ===== TRAITEMENT DU CHOIX =====
    choice = inputc("\n[cyan]Votre choix[/cyan] : ", c['c']).strip().lower()
    
    if choice == "q":
        # Quitter la navigation
        return current_folder_id
    
    elif choice == "m":
        # Déplacer un élément
        if move_element_interactive(master_password, config_data, current_folder_id):
            # Recharger la config
            from setup import load_config
            updated_config = load_config(master_password)
            config_data.update(updated_config)
        return current_folder_id
    
    elif choice == "..":
        # Remonter au parent
        if current_folder_id == "__ROOT__":
            printc("❌ Déjà au niveau racine.", c['r'])
            return current_folder_id
        
        # Vérifier si le dossier a un parent
        current_folder = tree.get(current_folder_id)
        if not current_folder:
            return current_folder_id
        
        parent_id = current_folder.get("parent")
        
        if parent_id is None:
            # Pas de parent → retourner au niveau virtuel
            return "__ROOT__"
        else:
            # Parent normal → y aller
            return parent_id
    
    elif choice.isdigit():
        # Entrer dans un dossier
        idx = int(choice) - 1
        if 0 <= idx < len(children):
            selected = children[idx]
            if selected["type"] == "folder":
                return selected["id"]
            else:
                printc("❌ Ce n'est pas un dossier.", c['r'])
                return current_folder_id
        else:
            printc("❌ Numéro invalide.", c['r'])
            return current_folder_id
    
    else:
        printc("❌ Choix invalide.", c['r'])
        return current_folder_id


# ====================================
# SUPPRESSION TOTALE
# ====================================

def delete_everything_clean(master_password: str, config_data: dict):
    """
    Supprime toute l'arborescence et les fichiers physiques SANS recréer le dossier Root
    Pour avoir un environnement propre avant importation
    
    Args:
        master_password: Mot de passe maître
        config_data: Configuration déchiffrée
    """
    import shutil
    from others.cache import cache_manager
    
    console.print("\n[red bold]⚠️  SUPPRESSION TOTALE (CLEAN) ⚠️[/red bold]\n")
    
    data_path = Path(config_data.get("data_path", "."))
    tree = config_data.get("tree", {})
    
    if not tree:
        printc("✅ Aucune donnée à supprimer.", c['g'])
        # Supprimer le cache quand même
        cache_manager.delete()
        return
    
    console.print(f"[yellow]📁 Chemin des données : {data_path}[/yellow]")
    console.print(f"[yellow]📊 Nombre d'éléments : {len(tree)}[/yellow]\n")
    
    confirm = inputc("[red]Tapez 'SUPPRIMER TOUT' pour confirmer[/red] : ", c['r'])
    
    if confirm != "SUPPRIMER TOUT":
        printc("❌ Suppression annulée.", c['g'])
        return
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Suppression en cours...", total=100)
            
            # 1. Supprimer tous les dossiers physiques
            progress.update(task, advance=20, description="Suppression des dossiers physiques...")
            
            # Vérifier si le cache existe (noms déchiffrés)
            cache_mappings = cache_manager.get_all()
            
            for item_id, item in tree.items():
                item_type = item.get("type", "file")
                
                # Essayer avec le nom du cache (déchiffré) en premier
                if cache_mappings and item_id in cache_mappings:
                    item_path = Path(cache_mappings[item_id]["physical_path"])
                else:
                    # Sinon utiliser le chemin chiffré selon le type
                    if item_type == "folder":
                        item_path = data_path / item_id
                    else:  # fichier
                        item_path = data_path / f"{item_id}.dat"
                
                if item_path.exists():
                    if item_path.is_dir():
                        shutil.rmtree(item_path)
                        printl(f"Supprimé dossier: {item_path.name}", "1")
                    else:
                        item_path.unlink()
                        printl(f"Supprimé fichier: {item_path.name}", "1")
                else:
                    # Fallback : chercher avec le pattern ID* (pour les fichiers déchiffrés)
                    if item_type == "file":
                        for f in data_path.glob(f"{item_id[:8]}*"):
                            if f.is_file():
                                f.unlink()
                                printl(f"Supprimé fichier (fallback): {f.name}", "1")
                                break
                    else:
                        for d in data_path.glob(f"{item_id[:8]}*"):
                            if d.is_dir():
                                shutil.rmtree(d)
                                printl(f"Supprimé dossier (fallback): {d.name}", "1")
                                break
            
            printl("Tous les dossiers physiques supprimés.", "2")
            
            # 2. Supprimer le cache
            progress.update(task, advance=20, description="Suppression du cache...")
            cache_manager.delete()
            printl("Cache supprimé.", "2")
            
            # 3. Vider l'arborescence dans la config
            progress.update(task, advance=30, description="Nettoyage de la configuration...")
            config_data["tree"] = {}
            save_tree_to_config({}, master_password, config_data)
            
            printl("Arborescence vidée de la config.", "2")
            
            progress.update(task, advance=30, description="✅ Terminé !")
        
        printc("\n✅ Toutes les données ont été supprimées avec succès.", c['g'])
        printc("📁 Environnement propre prêt pour l'importation.", c['c'])
        
    except Exception as e:
        printc(f"\n❌ Erreur lors de la suppression : {e}", c['r'])
        printl(f"Erreur delete_everything_clean: {e}", "4")


def delete_everything(master_password: str, config_data: dict):
    """
    Supprime toute l'arborescence et les fichiers physiques
    Gère aussi le cas où les noms sont déchiffrés
    
    Args:
        master_password: Mot de passe maître
        config_data: Configuration déchiffrée
    """
    import shutil
    from others.cache import cache_manager
    
    console.print("\n[red bold]⚠️  SUPPRESSION TOTALE ⚠️[/red bold]\n")
    
    data_path = Path(config_data.get("data_path", "."))
    tree = config_data.get("tree", {})
    
    if not tree:
        printc("✅ Aucune donnée à supprimer.", c['g'])
        # Supprimer le cache quand même
        cache_manager.delete()
        return
    
    console.print(f"[yellow]📁 Chemin des données : {data_path}[/yellow]")
    console.print(f"[yellow]📊 Nombre d'éléments : {len(tree)}[/yellow]\n")
    
    confirm = inputc("[red]Tapez 'SUPPRIMER TOUT' pour confirmer[/red] : ", c['r'])
    
    if confirm != "SUPPRIMER TOUT":
        printc("❌ Suppression annulée.", c['g'])
        return
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Suppression en cours...", total=100)
            
            # 1. Supprimer tous les dossiers physiques
            progress.update(task, advance=20, description="Suppression des dossiers physiques...")
            
            # Vérifier si le cache existe (noms déchiffrés)
            cache_mappings = cache_manager.get_all()
            
            for item_id, item in tree.items():
                item_type = item.get("type", "file")
                
                # Essayer avec le nom du cache (déchiffré) en premier
                if cache_mappings and item_id in cache_mappings:
                    item_path = Path(cache_mappings[item_id]["physical_path"])
                else:
                    # Sinon utiliser le chemin chiffré selon le type
                    if item_type == "folder":
                        item_path = data_path / item_id
                    else:  # fichier
                        item_path = data_path / f"{item_id}.dat"
                
                if item_path.exists():
                    if item_path.is_dir():
                        shutil.rmtree(item_path)
                        printl(f"Supprimé dossier: {item_path.name}", "1")
                    else:
                        item_path.unlink()
                        printl(f"Supprimé fichier: {item_path.name}", "1")
                else:
                    # Fallback : chercher avec le pattern ID* (pour les fichiers déchiffrés)
                    if item_type == "file":
                        for f in data_path.glob(f"{item_id[:8]}*"):
                            if f.is_file():
                                f.unlink()
                                printl(f"Supprimé fichier (fallback): {f.name}", "1")
                                break
                    else:
                        for d in data_path.glob(f"{item_id[:8]}*"):
                            if d.is_dir():
                                shutil.rmtree(d)
                                printl(f"Supprimé dossier (fallback): {d.name}", "1")
                                break
            
            printl("Tous les dossiers physiques supprimés.", "2")
            
            # 2. Supprimer le cache
            progress.update(task, advance=20, description="Suppression du cache...")
            cache_manager.delete()
            printl("Cache supprimé.", "2")
            
            # 3. Vider l'arborescence dans la config
            progress.update(task, advance=30, description="Nettoyage de la configuration...")
            config_data["tree"] = {}
            save_tree_to_config({}, master_password, config_data)
            
            printl("Arborescence vidée de la config.", "2")
            
            progress.update(task, advance=30, description="✅ Terminé !")
        
        printc("\n✅ Toutes les données ont été supprimées avec succès.", c['g'])
        
        # Recréer le dossier Root
        printc("🔄 Recréation du dossier Root...", c['c'])
        init_tree_if_needed(master_password, config_data, data_path)
        printc("✅ Dossier Root recréé.", c['g'])
        
    except Exception as e:
        printc(f"\n❌ Erreur lors de la suppression : {e}", c['r'])
        printl(f"Erreur delete_everything: {e}", "4")

# ====================================
# CRÉATION DE FICHIERS (.dat)
# ====================================

def create_file_dat(
    name: str,
    content: str,
    file_type: str,  # "note", "password", "credential"
    parent_id: str,
    master_password: str,
    config_data: dict,
    data_path: Path
) -> str:
    """
    Crée un fichier .dat chiffré (nom + contenu)
    
    file_type détermine l'extension déchiffrée :
    - "note" -> .txt
    - "password" -> .json
    - "credential" -> .json
    """
    printl(f"Création du fichier '{name}' (type: {file_type})...", "1")
    
    # 1. Générer ID
    file_id = generate_id()
    
    # 2. Dériver clé unique
    element_key, salt = derive_element_key(master_password, file_id)
    
    # 3. Chiffrer le nom
    cipher_method = config_data.get("cipher_method", "aes-gcm")
    encrypted_name = encrypt_name(name, element_key, cipher_method)
    
    # 4. Chiffrer le contenu
    cipher = get_cipher(cipher_method)
    encrypt_fn = cipher["encrypt"]
    content_bytes = content.encode('utf-8')
    encrypted_content = encrypt_fn(content_bytes, element_key)
    
    # 5. Fichier physique : ID.dat (binaire)
    physical_file = data_path / f"{file_id}.dat"
    with open(physical_file, 'wb') as f:
        f.write(encrypted_content)
    
    printl(f"Fichier créé: {physical_file}", "2")
    
    # 6. Entrée dans l'arborescence
    tree = config_data.get("tree", {})
    
    file_entry = {
        "type": "file",
        "file_type": file_type,
        "id": file_id,
        "name_encrypted": encrypted_name,
        "salt": salt.hex(),
        "parent": parent_id,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "size": len(encrypted_content)
    }
    
    tree[file_id] = file_entry
    
    # 7. Ajouter au parent
    if parent_id in tree:
        if "children" not in tree[parent_id]:
            tree[parent_id]["children"] = []
        if file_id not in tree[parent_id]["children"]:
            tree[parent_id]["children"].append(file_id)
            tree[parent_id]["updated_at"] = datetime.now().isoformat()
    
    # 8. Sauvegarder
    save_tree_to_config(tree, master_password, config_data)
    
    printc(f"✅ Fichier '{name}' créé", c['g'])
    return file_id


def decrypt_file_content(file_id: str, master_password: str, config_data: dict, data_path: Path) -> str:
    """Déchiffre le contenu d'un fichier .dat"""
    tree = config_data.get("tree", {})
    file_entry = tree[file_id]
    
    # Dériver clé
    salt = bytes.fromhex(file_entry["salt"])
    element_key, _ = derive_element_key(master_password, file_id, salt=salt)
    
    # Lire fichier chiffré
    # Chercher soit ID.dat soit ID_xxx.ext (déchiffré)
    dat_file = data_path / f"{file_id}.dat"
    
    if not dat_file.exists():
        # Chercher le fichier déchiffré
        for f in data_path.glob(f"{file_id[:8]}_*"):
            if f.is_file():
                dat_file = f
                break
    
    if not dat_file.exists():
        raise FileNotFoundError(f"Fichier {file_id} introuvable")
    
    with open(dat_file, 'rb') as f:
        encrypted_bytes = f.read()
    
    # Déchiffrer
    cipher_method = config_data.get("cipher_method", "aes-gcm")
    cipher = get_cipher(cipher_method)
    decrypt_fn = cipher["decrypt"]
    
    decrypted_bytes = decrypt_fn(encrypted_bytes, element_key)
    return decrypted_bytes.decode('utf-8')

def view_file_content(file_id: str, master_password: str, config_data: dict, data_path: Path):
    """Affiche le contenu déchiffré d'un fichier"""
    content = decrypt_file_content(file_id, master_password, config_data, data_path)
    
    tree = config_data.get("tree", {})
    file_entry = tree[file_id]
    file_type = file_entry.get("file_type")
    
    console.print(f"\n[cyan]═══ Contenu du fichier ═══[/cyan]\n")
    
    if file_type in ["password", "credential"]:
        # Afficher le JSON formaté
        import json
        data = json.loads(content)
        for key, value in data.items():
            console.print(f"[cyan]{key}:[/cyan] {value}")
    else:
        # Afficher le texte brut
        console.print(content)

# ====================================
# SUPPRESSION D'ÉLÉMENTS
# ====================================

def delete_element(
    element_id: str,
    master_password: str,
    config_data: dict,
    data_path: Path,
    recursive: bool = True
) -> bool:
    """Supprime un élément (dossier ou fichier)"""
    tree = config_data.get("tree", {})
    
    if element_id not in tree:
        printc("❌ Élément introuvable.", c['r'])
        return False
    
    element = tree[element_id]
    element_type = element.get("type")
    
    printl(f"Suppression de {element_id} (type: {element_type})...", "1")
    
    # Si dossier et a des enfants
    if element_type == "folder" and element.get("children"):
        if not recursive:
            printc("❌ Le dossier contient des éléments.", c['r'])
            return False
        
        # Supprimer récursivement les enfants
        for child_id in list(element["children"]):
            delete_element(child_id, master_password, config_data, data_path, recursive=True)
    
    # Supprimer le fichier/dossier physique
    cached = cache_manager.get(element_id)
    
    if cached:
        # Utiliser le chemin du cache
        phys_path = Path(cached["physical_path"])
    else:
        # Chemin chiffré
        if element_type == "folder":
            phys_path = data_path / element_id
        else:
            phys_path = data_path / f"{element_id}.dat"

    # Supprimer physiquement
    if phys_path.exists():
        try:
            if phys_path.is_dir():
                import shutil
                shutil.rmtree(phys_path)
            else:
                phys_path.unlink()
            printl(f"Supprimé: {phys_path}", "2")
        except Exception as e:
            printl(f"Erreur suppression physique: {e}", "4")
    else:
        # Essayer de trouver le fichier avec un glob
        printl(f"Fichier {phys_path} introuvable, recherche...", "3")
        
        # Pour les fichiers, chercher avec le pattern ID*
        if element_type == "file":
            for f in data_path.glob(f"{element_id[:8]}*"):
                if f.is_file():
                    f.unlink()
                    printl(f"Supprimé: {f}", "2")
                    break
        else:
            for d in data_path.glob(f"{element_id[:8]}*"):
                if d.is_dir():
                    import shutil
                    shutil.rmtree(d)
                    printl(f"Supprimé: {d}", "2")
                    break
    
    # Retirer du parent
    parent_id = element.get("parent")
    if parent_id and parent_id in tree:
        if element_id in tree[parent_id].get("children", []):
            tree[parent_id]["children"].remove(element_id)
            tree[parent_id]["updated_at"] = datetime.now().isoformat()
    
    # Supprimer de l'arborescence
    del tree[element_id]
    
    # Supprimer du cache
    if cached:
        cache_manager.data["mappings"].pop(element_id, None)
    
    # Sauvegarder
    save_tree_to_config(tree, master_password, config_data)
    
    return True


# ====================================
# INTERFACES INTERACTIVES
# ====================================

def create_file_interactive(master_password: str, config_data: dict, current_folder_id: str):
    """Interface pour créer un fichier"""
    console.print("\n[cyan]═══ Création d'un fichier ═══[/cyan]\n")
    
    # Type de fichier
    console.print("[cyan]Type de fichier :[/cyan]")
    console.print("  1. 📝 Note (.txt)")
    console.print("  2. 🔑 Mot de passe (.json)")
    console.print("  3. 👤 Identifiant (.json)\n")
    
    type_choice = inputc("Choisissez le type : ", c['c']).strip()
    
    type_map = {
        "1": "note",
        "2": "password",
        "3": "credential"
    }
    
    if type_choice not in type_map:
        printc("❌ Choix invalide.", c['r'])
        return None
    
    file_type = type_map[type_choice]
    
    # Nom du fichier
    name = inputc("\n📝 Nom du fichier : ", c['c']).strip()
    if not name:
        printc("❌ Le nom ne peut pas être vide.", c['r'])
        return None
    
    # Récupérer l'arborescence pour vérifier les doublons
    tree = config_data.get("tree", {})
    if not isinstance(tree, dict):
        tree = {}

    # --- VÉRIFICATION DE SÉCURITÉ POUR LES DOUBLONS ---
    if is_name_taken(tree, current_folder_id, name, master_password):
        printc(f"❌ Erreur : Un élément nommé '{name}' existe déjà ici.", c['r'])
        return None
    # --------------------------------
    
    # Contenu selon le type
    if file_type == "note":
        console.print("\n[dim]Entrez votre note (ligne vide pour terminer) :[/dim]")
        lines = []
        try:
            while True:
                line = input()
                if not line:
                    break
                lines.append(line)
        except EOFError:
            pass
        content = "\n".join(lines)
    
    elif file_type == "password":
        password = getpass.getpass("\n🔒 Mot de passe : ")
        site = inputc("🌐 Site/Application : ", c['c']).strip()
        notes = inputc("📝 Notes (optionnel) : ", c['c']).strip()
        
        content = json.dumps({
            "password": password,
            "site": site,
            "notes": notes,
            "created": datetime.now().isoformat()
        }, indent=2)
    
    else:  # credential
        username = inputc("\n👤 Nom d'utilisateur : ", c['c']).strip()
        password = getpass.getpass("🔒 Mot de passe : ")
        email = inputc("📧 Email (optionnel) : ", c['c']).strip()
        site = inputc("🌐 Site/Application : ", c['c']).strip()
        
        content = json.dumps({
            "username": username,
            "password": password,
            "email": email,
            "site": site,
            "created": datetime.now().isoformat()
        }, indent=2)
    
    if not content:
        printc("❌ Contenu vide.", c['r'])
        return None
    
    # Créer le fichier
    data_path = Path(config_data.get("data_path", "."))
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Création...", total=100)
            
            file_id = create_file_dat(
                name=name,
                content=content,
                file_type=file_type,
                parent_id=current_folder_id,
                master_password=master_password,
                config_data=config_data,
                data_path=data_path
            )
            
            progress.update(task, completed=100)
        
        return file_id
    
    except Exception as e:
        printc(f"❌ Erreur : {e}", c['r'])
        printl(f"Erreur create_file: {e}", "4")
        return None


def delete_element_interactive(master_password: str, config_data: dict, current_folder_id: str):
    """Interface pour supprimer un élément"""
    from rich.table import Table
    
    console.print("\n[cyan]═══ Suppression d'élément ═══[/cyan]\n")
    
    tree = config_data.get("tree", {})
    children = get_folder_children(tree, current_folder_id, master_password)
    
    if not children:
        printc("❌ Ce dossier est vide.", c['r'])
        return False
    
    # Tableau des éléments
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Type", width=10)
    table.add_column("Nom", style="white")
    
    for i, child in enumerate(children, 1):
        icon = "📁" if child["type"] == "folder" else "📄"
        table.add_row(str(i), f"{icon} {child['type']}", child["name"])
    
    console.print(table)
    console.print()
    
    try:
        choice = int(inputc("Quel élément supprimer ? (numéro) : ", c['c']).strip())
        if choice < 1 or choice > len(children):
            printc("❌ Numéro invalide.", c['r'])
            return False
        
        selected = children[choice - 1]
        
        # Confirmation
        printc(f"\n⚠️  Supprimer '{selected['name']}' ?", c['y'])
        if selected["type"] == "folder":
            printc("   (tous les sous-éléments seront supprimés)", c['y'])
        
        confirm = inputc("Confirmer (o/n) : ", c['y']).lower()
        
        if confirm != 'o':
            printc("❌ Annulé.", c['r'])
            return False
        
        # Supprimer
        data_path = Path(config_data.get("data_path", "."))
        success = delete_element(
            selected["id"],
            master_password,
            config_data,
            data_path,
            recursive=True
        )
        
        if success:
            printc(f"✅ '{selected['name']}' supprimé.", c['g'])
        
        return success
        
    except ValueError:
        printc("❌ Entrée invalide.", c['r'])
        return False