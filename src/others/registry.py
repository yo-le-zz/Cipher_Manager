# others/registry.py

"""
Registry central des méthodes de chiffrement / hash
Permet d'accéder dynamiquement aux fonctions enc / dec / hash / verify
"""

# ============================
# IMPORTS DES CIPHERS
# ============================

# Chiffrement réversible
from cipher import (
    enc_fernet,
    dec_fernet,
    enc_aes_gcm,
    dec_aes_gcm,
    enc_chacha20,
    dec_chacha20,
)

from crypto import (
    hash_password,
    verify_password,
    derive_key_scrypt,
)



# ============================
# REGISTRY
# ============================

CIPHERS = {
    # ======================
    # RÉVERSIBLES
    # ======================
    "fernet": {
        "type": "symmetric",
        "encrypt": enc_fernet,
        "decrypt": dec_fernet,
    },
    "aes-gcm": {
        "type": "symmetric",
        "encrypt": enc_aes_gcm,
        "decrypt": dec_aes_gcm,
    },
    "chacha20-poly1305": {
        "type": "symmetric",
        "encrypt": enc_chacha20,
        "decrypt": dec_chacha20,
    },

    # ======================
    # SENS UNIQUE
    # ======================
    "bcrypt": {
        "type": "hash",
        "hash": hash_password,
        "verify": verify_password,
    },
    "scrypt": {
        "type": "kdf",
        "derive": derive_key_scrypt,
    },
}


# ============================
# HELPERS
# ============================

def get_cipher(name: str) -> dict:
    """
    Retourne le dictionnaire d'un cipher
    """
    cipher = CIPHERS.get(name.lower())
    if not cipher:
        raise ValueError(f"Cipher inconnu : {name}")
    return cipher


def list_ciphers(exclude_hashes: bool = False, exclude_none_hashes: bool = False) -> list:
    keys = list(CIPHERS.keys())
    
    if exclude_hashes:
        keys = [k for k in keys if CIPHERS[k]['type'] == 'symmetric']
    if exclude_none_hashes:
        # Exclut les symmetric ET les kdf, garde seulement type="hash"
        keys = [k for k in keys if CIPHERS[k]['type'] == 'hash']
    
    return keys

def is_reversible(name: str) -> bool:
    """
    Indique si un cipher est réversible
    """
    cipher = get_cipher(name)
    return cipher.get("type") == "symmetric"
