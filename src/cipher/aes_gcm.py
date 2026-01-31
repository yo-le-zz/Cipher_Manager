# cipher/aes_gcm.py

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def enc_aes_gcm(data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    # Pas besoin de .encode() si data est déjà en bytes
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def dec_aes_gcm(blob: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = blob[:12]
    ciphertext = blob[12:]
    # Retourne bytes directement, pas str
    return aesgcm.decrypt(nonce, ciphertext, None)