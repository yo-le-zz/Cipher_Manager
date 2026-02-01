# crypto/utils.py

# librairies de style

# ===RICHE==============================
try:
    from rich.console import Console
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None
# ======================================

# Autres librairies
from datetime import datetime

# librairies d'arborescence et système
from multiprocessing.util import INFO
import sys
from pathlib import Path

# ======================================
# MAGIC NUMBERS
# ======================================
DEBUG = False
class LogLevel:
    INFO = "1"
    SUCCESS = "2"
    WARNING = "3"
    ERROR = "4"
    CRITICAL = "5"
# ======================================


# ACCESS PATH

def get_app_path() -> Path:
    """
    Retourne le dossier racine pour accéder aux fichiers de l'app.
    En dev, c'est src/ ; en PyInstaller, c'est _MEIPASS
    """
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    else:
        return Path(__file__).resolve().parent  # src/

    
def get_path(relative_path: str) -> Path:
    """
    Retourne un chemin absolu relatif à l'endroit où l'exécutable se trouve.
    Fonctionne aussi bien en développement qu'avec PyInstaller.
    """
    if getattr(sys, "frozen", False):
        # PyInstaller : le répertoire de l'exécutable
        base_path = Path(sys.executable).parent
    else:
        # Développement : le répertoire src/
        base_path = Path(__file__).resolve().parent
    
    return base_path / relative_path

# ======================
# LETTRES RAPIDES
# ======================
# c = couleurs de base / style

# Couleurs simples
c = {}
c['g'] = "green"
c['r'] = "red"
c['y'] = "yellow"
c['b'] = "blue"
c['c'] = "cyan"
c['m'] = "magenta"
c['w'] = "white"
c['k'] = "black"

# Styles combinés
c['bg'] = lambda color: f"on {color}"       # arrière-plan
c['bold'] = lambda color: f"bold {color}"   # gras
c['dim'] = lambda color: f"dim {color}"     # dim
c['under'] = lambda color: f"underline {color}"  # underline

# ======================
# HELPER
# ======================
def printc(text: str, style: str = None):
    """Print avec style rapide"""
    if RICH and console:
        style = style or ""  # si style None
        console.print(text, style=style)
    else:
        # fallback pour terminal classique
        if style:
            # ANSI escape minimal
            colors = {
                "black": "\033[30m",
                "red": "\033[31m",
                "green": "\033[32m",
                "yellow": "\033[33m",
                "blue": "\033[34m",
                "magenta": "\033[35m",
                "cyan": "\033[36m",
                "white": "\033[37m",
            }
            reset = "\033[0m"
            print(f"{colors.get(style, '')}{text}{reset}")
        else:
            print(text)
            
def inputc(text: str, style: str = None) -> str:
    """Print + input avec style rapide et retourne la valeur"""
    if RICH and console:
        style = style or ""
        return console.input(f"[{style}]{text}[/{style}]")
    else:
        # fallback ANSI
        if style:
            colors = {
                "black": "\033[30m",
                "red": "\033[31m",
                "green": "\033[32m",
                "yellow": "\033[33m",
                "blue": "\033[34m",
                "magenta": "\033[35m",
                "cyan": "\033[36m",
                "white": "\033[37m",
            }
            reset = "\033[0m"
            return input(f"{colors.get(style, '')}{text}{reset}")
        else:
            return input(text)
    
# ======================
# LOGS
# ======================
def printl(msg: str, level: str = LogLevel.INFO):
    if DEBUG:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_msg = f"[{timestamp}] {msg}"

        # Couleur selon niveau
        level_map = {
            LogLevel.INFO: c['b'],
            LogLevel.SUCCESS: c['g'],
            LogLevel.WARNING: c['y'],
            LogLevel.ERROR: c['r'],
            LogLevel.CRITICAL: c['m']
        }
        style = level_map.get(level, c['w'])  # blanc si inconnu

        if RICH:
            printc(full_msg, style)
        else:
            print(full_msg)
