# cipher/fernet.py

from cryptography.fernet import Fernet
import base64

def enc_fernet(data: bytes, key: bytes) -> bytes:
    # Convertir la clé brute en format Fernet (base64 url-safe)
    fernet_key = base64.urlsafe_b64encode(key)
    f = Fernet(fernet_key)
    return f.encrypt(data)

def dec_fernet(data: bytes, key: bytes) -> bytes:
    # Convertir la clé brute en format Fernet (base64 url-safe)
    fernet_key = base64.urlsafe_b64encode(key)
    f = Fernet(fernet_key)
    return f.decrypt(data)