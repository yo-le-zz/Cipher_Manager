# others/cache.py

"""
Système de cache pour accélérer la navigation
- Déchiffre les noms et renomme les dossiers/fichiers physiques temporairement
- Pour les fichiers .dat : change l'extension pour les rendre ouvrables
- Stocke les correspondances dans un cache chiffré
- À la fermeture : rechiffre et remet en .dat
"""

import orjson
import base64
from pathlib import Path
from datetime import datetime
from typing import Dict
import shutil

from others.utils import printl, printc, c, get_path
from others.registry import get_cipher
from crypto.scrypt import derive_key_scrypt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.console import Console

console = Console()

CACHE_PATH = get_path("cache/names.cache")


# ====================================
# GESTION DU CACHE
# ====================================

class CacheManager:
    """
    Gère le cache des noms déchiffrés
    
    Structure du cache (chiffré):
    {
        "mappings": {
            "element_id": {
                "decrypted_name": "Mon Dossier",
                "physical_path": "/path/to/folder",
                "type": "folder"  # ou "file"
            }
        "content_mappings": {},  # IDs des fichiers dont le contenu est déchiffré
        },
        "metadata": {
            "created_at": "2024-01-30T10:00:00",
            "total_items": 5
        }
    }
    """
    
    def __init__(self):
        self.data = {
            "mappings": {},
            "metadata": {
                "created_at": datetime.now().isoformat(),
                "total_items": 0
            }
        }
        self.loaded = False
    
    # ====================================
    # CHARGEMENT / SAUVEGARDE
    # ====================================
    
    def load(self, master_password: str) -> bool:
        if not CACHE_PATH.exists():
            return False
        
        try:
            printl("Chargement du cache...", "1")
            with open(CACHE_PATH, "rb") as f:
                encrypted_data = f.read()
            
            # Utilisation d'un SEL FIXE pour le cache
            cache_salt = b"cache_system_salt_fixed"
            key, _ = derive_key_scrypt(master_password, salt=cache_salt, length=32)
            
            cipher = get_cipher("aes-gcm")
            decrypted_bytes = cipher["decrypt"](encrypted_data, key)
            
            self.data = orjson.loads(decrypted_bytes)
            self.loaded = True
            printl(f"Cache chargé : {len(self.data['mappings'])} éléments", "2")
            return True
            
        except Exception as e:
            printl(f"Erreur lors du chargement du cache : {str(e)}", "3")
            return False
    
    def save(self, master_password: str):
        try:
            printl("Sauvegarde du cache...", "1")
            self.data["metadata"]["total_items"] = len(self.data["mappings"])
            self.data["metadata"]["last_save"] = datetime.now().isoformat()
            
            data_bytes = orjson.dumps(self.data)
            
            # MÊME SEL ICI
            cache_salt = b"cache_system_salt_fixed"
            key, _ = derive_key_scrypt(master_password, salt=cache_salt, length=32)
            
            cipher = get_cipher("aes-gcm")
            encrypted_data = cipher["encrypt"](data_bytes, key)
            
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(CACHE_PATH, "wb") as f:
                f.write(encrypted_data)
            
            printl(f"Cache sauvegardé : {len(self.data['mappings'])} éléments", "2")
        except Exception as e:
            printl(f"Erreur lors de la sauvegarde du cache : {str(e)}", "4")
    
    def delete(self):
        """Supprime le fichier de cache"""
        if CACHE_PATH.exists():
            CACHE_PATH.unlink()
            printl("Cache supprimé.", "2")
        self.data["mappings"] = {}
        self.data["metadata"]["total_items"] = 0
        self.loaded = False
    
    # ====================================
    # GESTION DES ENTRÉES
    # ====================================
    
    def add(self, element_id: str, decrypted_name: str, physical_path: str, item_type: str):
        """Ajoute un élément au cache"""
        self.data["mappings"][element_id] = {
            "decrypted_name": decrypted_name,
            "physical_path": physical_path,
            "type": item_type
        }
        printl(f"Cache: ajout {element_id[:8]}... -> {decrypted_name}", "1")
    
    def get(self, element_id: str) -> dict | None:
        """Récupère un élément du cache"""
        return self.data["mappings"].get(element_id)
    
    def get_all(self) -> Dict[str, dict]:
        """Retourne tous les mappings"""
        return self.data["mappings"]
    
    def exists(self, element_id: str) -> bool:
        """Vérifie si un élément est en cache"""
        return element_id in self.data["mappings"]
    
    # ====================================
    # DÉCHIFFREMENT PHYSIQUE
    # ====================================
    
    def decrypt_physical_names(self, tree: dict, master_password: str, data_path: Path):
        from manager import derive_element_key, decrypt_name
        
        console.print("\n[cyan]🔓 Déchiffrement des noms physiques...[/cyan]\n")
        
        # Tenter de charger le cache existant
        if not self.loaded:
            cache_loaded = self.load(master_password)
        else:
            cache_loaded = True

        items = list(tree.items())
        items_to_decrypt = []
        items_from_cache = 0
        
        # Vérifier quels items peuvent être renommés depuis le cache
        for element_id, item in items:
            cached_item = self.get(element_id)
            
            # Vérifier si le fichier est déjà déchiffré (existe avec le bon nom)
            if cached_item:
                expected_path = Path(cached_item["physical_path"])
                if expected_path.exists():
                    # Déjà déchiffré et au bon endroit
                    items_from_cache += 1
                    printl(f"✓ {element_id[:8]}... déjà déchiffré", "1")
                    continue
                
                # Le cache existe mais le fichier est rechiffré
                # On peut juste le renommer sans re-déchiffrer !
                item_type = item.get("type")
                
                if item_type == "folder":
                    encrypted_path = data_path / element_id
                else:
                    encrypted_path = data_path / f"{element_id}.dat"
                
                if encrypted_path.exists():
                    try:
                        encrypted_path.rename(expected_path)
                        items_from_cache += 1
                        printl(f"✓ {element_id[:8]}... renommé depuis le cache", "2")
                        continue
                    except Exception as e:
                        printl(f"Erreur renommage depuis cache: {e}", "3")
            
            # Besoin de vraiment déchiffrer
            items_to_decrypt.append((element_id, item))
        
        if items_from_cache > 0:
            console.print(f"[green]✅ {items_from_cache} fichier(s) restauré(s) depuis le cache (0 déchiffrement)[/green]")
        
        if not items_to_decrypt:
            console.print("\n[green]✅ Tous les noms sont déchiffrés ![/green]\n")
            return
        
        console.print(f"[yellow]🔐 {len(items_to_decrypt)} fichier(s) à déchiffrer...[/yellow]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("Déchiffrement en cours...", total=len(items_to_decrypt))
            
            for element_id, item in items_to_decrypt:
                try:
                    # Déchiffrer le nom
                    salt = bytes.fromhex(item["salt"])
                    element_key, _ = derive_element_key(master_password, element_id, salt=salt)
                    decrypted_name = decrypt_name(item["name_encrypted"], element_key)
                    
                    item_type = item.get("type")
                    
                    if item_type == "folder":
                        # DOSSIER : simple renommage
                        old_path = data_path / element_id
                        new_name = f"{element_id[:8]}_{decrypted_name}"
                        new_path = data_path / new_name
                        
                        if old_path.exists() and old_path != new_path:
                            old_path.rename(new_path)
                            printl(f"Renommé: {element_id[:8]}... -> {decrypted_name}", "2")
                        
                        self.add(element_id, decrypted_name, str(new_path), item_type)
                    
                    else:  # FICHIER
                        # Fichier .dat -> renommer avec extension ouvrable
                        file_type = item.get("file_type", "note")
                        
                        # Extension selon le type
                        ext_map = {
                            "note": ".txt",
                            "password": ".json",
                            "credential": ".json"
                        }
                        ext = ext_map.get(file_type, ".txt")
                        
                        old_path = data_path / f"{element_id}.dat"
                        new_name = f"{element_id[:8]}_{decrypted_name}{ext}"
                        new_path = data_path / new_name
                        
                        if old_path.exists() and old_path != new_path:
                            # Simple renommage, le contenu reste chiffré !
                            old_path.rename(new_path)
                            printl(f"Renommé: {element_id[:8]}.dat -> {decrypted_name}{ext}", "2")
                        
                        self.add(element_id, decrypted_name, str(new_path), "file")
                    
                except Exception as e:
                    printl(f"Erreur déchiffrement {element_id}: {e}", "4")
                
                progress.update(task, advance=1)
        
        # Sauvegarder le cache
        self.save(master_password)
        console.print("\n[green]✅ Déchiffrement terminé ![/green]\n")
    
    # ====================================
    # RECHIFFREMENT PHYSIQUE (FERMETURE)
    # ====================================
    
    def encrypt_physical_names_and_cleanup(self, tree: dict, data_path: Path):
        """
        Rechiffre tous les noms physiques
        Pour les fichiers : remet l'extension .dat
        
        Args:
            tree: Arborescence complète
            data_path: Chemin racine des données
        """
        console.print("\n[cyan]🔒 Rechiffrement des noms physiques...[/cyan]\n")
        
        mappings = self.get_all()
        
        if not mappings:
            printl("Aucun nom à rechiffrer.", "1")
            return
        
        items = list(mappings.items())
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("Rechiffrement en cours...", total=len(items))
            
            for element_id, mapping in items:
                try:
                    # Chemin actuel (déchiffré)
                    current_path = Path(mapping["physical_path"])
                    
                    item_type = mapping.get("type")
                    
                    if item_type == "folder":
                        # DOSSIER : renommer avec ID
                        encrypted_path = data_path / element_id
                        
                        if current_path.exists() and current_path != encrypted_path:
                            current_path.rename(encrypted_path)
                            printl(f"Rechiffré: {mapping['decrypted_name']} -> {element_id}", "1")
                    
                    else:  # FICHIER
                        # FICHIER : renommer avec ID.dat
                        encrypted_path = data_path / f"{element_id}.dat"
                        
                        if current_path.exists() and current_path != encrypted_path:
                            # Renommer en .dat
                            current_path.rename(encrypted_path)
                            printl(f"Rechiffré: {mapping['decrypted_name']} -> {element_id}.dat", "1")
                    
                except Exception as e:
                    printl(f"Erreur rechiffrement {element_id}: {e}", "4")
                
                progress.update(task, advance=1)
        
        # NE PAS supprimer le cache, juste le garder pour la prochaine fois
        console.print("\n[green]✅ Tous les noms ont été rechiffrés ![/green]\n")
        console.print("[dim]💡 Le cache est conservé pour accélérer le prochain déchiffrement[/dim]\n")

# --- Gestion du Contenu ---

    def decrypt_all_contents(self, tree: dict, master_password: str, data_path: Path):
        """Déchiffre le contenu des fichiers et remplace le binaire par le clair"""
        from manager import derive_element_key
        
        console.print("\n[cyan]🔓 Déchiffrement du contenu des fichiers...[/cyan]\n")
        
        # Initialiser content_mappings si nécessaire
        if "content_mappings" not in self.data:
            self.data["content_mappings"] = {}
        
        # Filtrer uniquement les fichiers
        files_to_decrypt = [(eid, item) for eid, item in tree.items() if item.get("type") == "file"]
        
        if not files_to_decrypt:
            console.print("[yellow]📭 Aucun fichier à déchiffrer.[/yellow]\n")
            return
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("Déchiffrement du contenu...", total=len(files_to_decrypt))
            
            for element_id, item in files_to_decrypt:
                try:
                    # Vérifier si le contenu est déjà déchiffré
                    if element_id in self.data["content_mappings"]:
                        progress.update(task, advance=1, description="Déjà déchiffré...")
                        continue
                    
                    # Trouver le chemin actuel du fichier (déjà renommé par decrypt_physical_names)
                    mapping = self.get(element_id)
                    file_path = None
                    
                    if mapping and mapping["type"] == "file":
                        # Utiliser le chemin complet du cache
                        file_path = Path(mapping["physical_path"])
                    else:
                        # Fallback : chercher le fichier avec l'ID
                        dat_file = data_path / f"{element_id}.dat"
                        if dat_file.exists():
                            file_path = dat_file
                        else:
                            # Chercher avec le préfixe ID
                            for f in data_path.glob(f"{element_id[:8]}_*"):
                                if f.is_file():
                                    file_path = f
                                    break
                    
                    if not file_path or not file_path.exists():
                        progress.update(task, advance=1, description=f"❌ Fichier introuvable")
                        continue
                    
                    # Déchiffrer directement le contenu
                    try:
                        # Lire le contenu chiffré
                        with open(file_path, 'rb') as f:
                            encrypted_bytes = f.read()
                        
                        # Dériver la clé et déchiffrer
                        salt = bytes.fromhex(item["salt"])
                        element_key, _ = derive_element_key(master_password, element_id, salt=salt)
                        
                        from manager import get_cipher
                        cipher_method = item.get("cipher_method", "aes-gcm")
                        cipher = get_cipher(cipher_method)
                        decrypt_fn = cipher["decrypt"]
                        
                        decrypted_bytes = decrypt_fn(encrypted_bytes, element_key)
                        decrypted_content = decrypted_bytes.decode('utf-8')
                        
                        # Remplacer le contenu du fichier par le contenu déchiffré
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(decrypted_content)
                        
                        # Marquer comme déchiffré dans le cache
                        self.data["content_mappings"][element_id] = True
                        progress.update(task, advance=1, description=f"✅ {file_path.name}")
                        
                    except Exception as decrypt_error:
                        printl(f"Erreur déchiffrement contenu {element_id}: {decrypt_error}", "4")
                        progress.update(task, advance=1, description=f"❌ Erreur déchiffrement {element_id[:8]}...")
                        
                except Exception as e:
                    printl(f"Erreur traitement fichier {element_id}: {e}", "4")
                    progress.update(task, advance=1, description=f"❌ Erreur {element_id[:8]}...")
        
        # Sauvegarder le cache mis à jour
        self.save(master_password)
        console.print("\n[green]✅ Déchiffrement du contenu terminé ![/green]\n")

    def encrypt_everything_and_cleanup(self, tree: dict, master_password: str, data_path: Path):
        """Rechiffre le contenu ET les noms, puis supprime le cache complètement"""
        from manager import derive_element_key, create_file_dat
        
        console.print("\n[cyan]🔒 Rechiffrement complet et nettoyage...[/cyan]\n")
        
        # Initialiser content_mappings si nécessaire
        if "content_mappings" not in self.data:
            self.data["content_mappings"] = {}
        
        mappings = self.get_all()
        
        if not mappings:
            console.print("[yellow]📭 Aucun élément à rechiffrer.[/yellow]\n")
            return
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("Rechiffrement complet...", total=len(mappings))
            
            for element_id, mapping in mappings.items():
                try:
                    current_path = Path(mapping["physical_path"])
                    if not current_path.exists():
                        progress.update(task, advance=1, description="⚠️ Fichier manquant")
                        continue
                    
                    item_type = mapping.get("type")
                    item = tree.get(element_id)
                    
                    if item_type == "file" and item:
                        # A. Rechiffrer le contenu si nécessaire
                        if element_id in self.data["content_mappings"]:
                            # Lire le contenu clair
                            with open(current_path, 'r', encoding='utf-8') as f:
                                clear_content = f.read()
                            
                            # Recréer le fichier chiffré avec create_file_dat
                            file_type = item.get("file_type", "note")
                            parent_id = item.get("parent")
                            
                            # Supprimer l'ancien fichier
                            current_path.unlink()
                            
                            # Recréer le fichier chiffré
                            new_file_id = create_file_dat(
                                name=mapping["decrypted_name"],
                                content=clear_content,
                                file_type=file_type,
                                parent_id=parent_id,
                                master_password=master_password,
                                config_data={"cipher_method": item.get("cipher_method", "aes-gcm"), "data_path": str(data_path)},
                                data_path=data_path
                            )
                            
                            progress.update(task, advance=1, description=f"🔒 {mapping['decrypted_name']}")
                        else:
                            # Juste renommer en .dat si le contenu n'était pas déchiffré
                            encrypted_path = data_path / f"{element_id}.dat"
                            if current_path != encrypted_path:
                                current_path.rename(encrypted_path)
                            progress.update(task, advance=1, description=f"📝 {mapping['decrypted_name']}")
                    
                    elif item_type == "folder":
                        # DOSSIER : renommer avec ID
                        encrypted_path = data_path / element_id
                        if current_path != encrypted_path:
                            current_path.rename(encrypted_path)
                        progress.update(task, advance=1, description=f"📁 {mapping['decrypted_name']}")
                    
                except Exception as e:
                    printl(f"Erreur rechiffrement {element_id}: {e}", "4")
                    progress.update(task, advance=1, description=f"❌ Erreur {element_id[:8]}...")
        
        # Vider complètement le cache
        self.data["mappings"] = {}
        self.data["content_mappings"] = {}
        self.save(master_password)
        
        # Supprimer le fichier de cache
        if CACHE_PATH.exists():
            CACHE_PATH.unlink()
        
        console.print("\n[green]✅ Rechiffrement complet terminé ![/green]")
        console.print("[green]🗑️  Cache supprimé pour plus de sécurité[/green]\n")

    def encrypt_everything_back(self, tree: dict, master_password: str, data_path: Path):
        """Rechiffre le contenu ET renomme en ID.dat"""
        from manager import create_file_dat
        
        console.print("\n[cyan]🔒 Rechiffrement total...[/cyan]\n")
        
        # Initialiser content_mappings si nécessaire
        if "content_mappings" not in self.data:
            self.data["content_mappings"] = {}
        
        mappings = self.get_all()
        
        if not mappings:
            console.print("[yellow]📭 Aucun élément à rechiffrer.[/yellow]\n")
            return
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("Rechiffrement total...", total=len(mappings))
            
            # On itère sur le cache car c'est lui qui sait ce qui est "ouvert"
            for eid, mapping in list(mappings.items()):
                try:
                    current_path = Path(mapping["physical_path"])
                    if not current_path.exists():
                        continue

                    item_type = mapping.get("type")
                    item = tree.get(eid)
                    
                    if item_type == "file" and item:
                        # A. Rechiffrer le contenu si nécessaire
                        if eid in self.data["content_mappings"]:
                            # Lire le contenu clair
                            with open(current_path, 'r', encoding='utf-8') as f:
                                clear_content = f.read()
                            
                            # Recréer le fichier chiffré avec create_file_dat
                            file_type = item.get("file_type", "note")
                            parent_id = item.get("parent")
                            
                            # Supprimer l'ancien fichier
                            current_path.unlink()
                            
                            # Recréer le fichier chiffré
                            new_file_id = create_file_dat(
                                name=mapping["decrypted_name"],
                                content=clear_content,
                                file_type=file_type,
                                parent_id=parent_id,
                                master_password=master_password,
                                config_data={"cipher_method": item.get("cipher_method", "aes-gcm"), "data_path": str(data_path)},
                                data_path=data_path
                            )
                            
                            progress.update(task, advance=1, description=f"🔒 {mapping['decrypted_name']}")
                        else:
                            # Juste renommer en .dat si le contenu n'était pas déchiffré
                            encrypted_path = data_path / f"{eid}.dat"
                            if current_path != encrypted_path:
                                current_path.rename(encrypted_path)
                            progress.update(task, advance=1, description=f"📝 {mapping['decrypted_name']}")
                    
                    elif item_type == "folder":
                        # DOSSIER : renommer avec ID
                        encrypted_path = data_path / eid
                        if current_path != encrypted_path:
                            current_path.rename(encrypted_path)
                        progress.update(task, advance=1, description=f"📁 {mapping['decrypted_name']}")
                    
                except Exception as e:
                    printl(f"Erreur rechiffrement {eid}: {e}", "4")
                
                progress.update(task, advance=1)
        
        # Garder le cache pour la prochaine fois (ne pas supprimer)
        console.print("\n[green]✅ Tout rechiffré ![/green]\n")
        console.print("[dim]💡 Le cache est conservé pour accélérer le prochain déchiffrement[/dim]\n")


# ====================================
# INSTANCE GLOBALE
# ====================================

cache_manager = CacheManager()