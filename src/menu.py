# menu.py

from others.utils import c, inputc, printc, printl
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import sys
from pathlib import Path

# Import des fonctions de gestion
from manager import (
    create_file_interactive,
    delete_element_interactive,
    init_tree_if_needed,
    create_folder_interactive,
    navigate_interactive,
    delete_everything
)
from others.cache import cache_manager

console = Console()

def display_menu():
    """
    Affiche le menu principal avec Rich
    """
    # Créer un tableau pour le menu
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Option", style="cyan", width=3)
    table.add_column("Description", style="white")
    
    # Options du menu
    options = [
        ("1", "📂 Naviguer dans les dossiers"),
        ("2", "➕ Créer un dossier"),
        ("3", "📝 Ajouter note/mot de passe"),
        ("4", "🔍 Rechercher un élément"),
        ("5", "🗑️  Supprimer un élément"),
        ("6", "🔓 Tout déchiffrer (noms + contenu)"),
        ("7", "🔒 Tout rechiffrer (noms + contenu)"),
        ("8", "💾 Exporter les données"),
        ("9", "💾 Importer les données"),
        ("10", "⚠️  Tout supprimer (DANGER)"),
        ("0", "🚪 Quitter"),
    ]
    
    for opt, desc in options:
        table.add_row(opt, desc)
    
    # Afficher dans un panel
    panel = Panel(
        table,
        title="[bold cyan]cipher_manager - Menu Principal[/bold cyan]",
        border_style="cyan"
    )
    console.print(panel)


def menu(config: dict, master_password: str):
    """
    Fonction principale du menu
    Gère la navigation et les actions utilisateur
    
    Args:
        config: Configuration déchiffrée de l'utilisateur
        master_password: Mot de passe maître (nécessaire pour les opérations)
    """
    printl("Entrée dans le menu principal", "1")
    
    # Initialiser l'arborescence si nécessaire
    data_path = Path(config.get("data_path", "."))
    init_tree_if_needed(master_password, config, data_path)
    
    # Charger le cache si disponible
    cache_manager.load(master_password)
    
    # Trouver le dossier racine
    tree = config.get("tree", {})
    current_folder_id = None
    for folder_id, item in tree.items():
        if item.get("type") == "folder" and item.get("parent") is None:
            current_folder_id = folder_id
            break
    
    if not current_folder_id:
        printc("❌ Impossible de trouver le dossier racine.", c['r'])
        sys.exit(1)
    
    while True:
        console.print()  # Ligne vide
        display_menu()
        
        choice = inputc("\n[cyan]Choisissez une option[/cyan] : ", c['c']).strip()
        
        if choice == "1":
            # Navigation
            current_folder_id = navigate_interactive(master_password, config, current_folder_id)
            
        elif choice == "2":
            # Création de dossier
            folder_id = create_folder_interactive(master_password, config, current_folder_id)
            if folder_id:
                # Recharger la config après modification
                from setup import load_config
                config = load_config(master_password)
            
        elif choice == "3":
            # Création de fichier
            file_id = create_file_interactive(master_password, config, current_folder_id)
            if file_id:
                # Recharger la config
                from setup import load_config
                config = load_config(master_password)
            
        elif choice == "4":
            printc("\n🔜 Recherche - En développement", c['y'])
            # TODO: Appeler fonction de recherche

        elif choice == "5":
            # Suppression d'élément
            success = delete_element_interactive(master_password, config, current_folder_id)
            if success:
                # Recharger la config
                from setup import load_config
                config = load_config(master_password)
            
        elif choice == "6":
            # Tout déchiffrer (noms + contenu)
            tree = config.get("tree", {})
            data_path = Path(config.get("data_path", "."))
            
            # 1. Déchiffrer les noms physiques
            cache_manager.decrypt_physical_names(tree, master_password, data_path)
            
            # 2. Déchiffrer le contenu des fichiers
            cache_manager.decrypt_all_contents(tree, master_password, data_path)
            
            printc("\n✅ Tout déchiffré ! Les fichiers sont maintenant lisibles.", c['g'])
            printc("⚠️  Utilisez l'option 7 pour rechiffrer automatiquement.", c['y'])
            
        elif choice == "7":
            # Tout rechiffrer (noms + contenu)
            tree = config.get("tree", {})
            data_path = Path(config.get("data_path", "."))
            
            # Rechiffrer tout mais garder le cache
            cache_manager.encrypt_everything_back(tree, master_password, data_path)
            
            printc("\n✅ Tout rechiffré ! Les fichiers sont à nouveau sécurisés.", c['g'])
            printc("💡 Le cache est conservé pour accélérer le prochain déchiffrement.", c['y'])
        
        elif choice == "8":
            printc("\n🔜 Exportation - En développement", c['y'])
        
        elif choice == "9":
            printc("\n🔜 Importation - En développement", c['y'])
        
        elif choice == "10":
            # Suppression totale
            delete_everything(master_password, config)
            # Recharger la config
            from setup import load_config
            config = load_config(master_password)
            # Réinitialiser le dossier actuel
            tree = config.get("tree", {})
            for folder_id, item in tree.items():
                if item.get("type") == "folder" and item.get("parent") is None:
                    current_folder_id = folder_id
                    break
                
        elif choice == "0":
            printc("\n👋 Fermeture sécurisée en cours...", c['c'])
            
            # Rechiffrer tout (noms + contenu)
            tree = config.get("tree", {})
            data_path = Path(config.get("data_path", "."))
            cache_manager.encrypt_everything_back(tree, master_password, data_path)
            
            # SUPPRIMER le cache uniquement à la fermeture
            cache_manager.delete()
            printl("Cache supprimé.", "2")
            
            printl("Fermeture du menu", "1")
            printc("✅ Fermeture sécurisée terminée.", c['g'])
            sys.exit(0)
            
        else:
            printc("\n❌ Option invalide. Veuillez choisir une option du menu.", c['r'])