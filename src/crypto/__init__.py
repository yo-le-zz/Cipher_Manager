# crypto/__init__.py

from .bcrypt import hash_password as _hash_bcrypt, verify_password as _verify_bcrypt
from .scrypt import derive_key_scrypt

def hash_password(password: str, method: str = "bcrypt") -> bytes:
    """Hash un mot de passe selon la méthode choisie"""
    if method.lower() == "bcrypt":
        return _hash_bcrypt(password)
    elif method.lower() == "scrypt":
        # Utiliser scrypt comme hash (stocker salt + key ensemble)
        key, salt = derive_key_scrypt(password)
        # Format: salt (16 bytes) + key (32 bytes) = 48 bytes total
        return salt + key
    else:
        raise ValueError(f"Méthode de hash '{method}' non supportée")

def verify_password(password: str, hashed: bytes, method: str = "bcrypt") -> bool:
    """Vérifie un mot de passe selon la méthode"""
    if method.lower() == "bcrypt":
        return _verify_bcrypt(password, hashed)
    elif method.lower() == "scrypt":
        # Extraire salt (16 bytes) et key (32 bytes)
        salt = hashed[:16]
        stored_key = hashed[16:]
        # Re-dériver et comparer
        derived_key, _ = derive_key_scrypt(password, salt=salt)
        return derived_key == stored_key
    else:
        raise ValueError(f"Méthode '{method}' non supportée")

__all__ = [
    "hash_password",
    "verify_password",
    "derive_key_scrypt",
]