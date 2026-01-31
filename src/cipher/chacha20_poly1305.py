# cipher/chacha20_poly1305.py

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def enc_chacha20(data: bytes, key: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, data, None)
    return nonce + ciphertext

def dec_chacha20(blob: bytes, key: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key)
    nonce = blob[:12]
    ciphertext = blob[12:]
    return chacha.decrypt(nonce, ciphertext, None)