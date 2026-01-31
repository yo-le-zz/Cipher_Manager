# crypto/scrypt.py

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import os

def derive_key_scrypt(
    password: str,
    salt: bytes | None = None,
    length: int = 32
) -> tuple[bytes, bytes]:
    """
    Retourne (key, salt)
    """
    if salt is None:
        salt = os.urandom(16)

    kdf = Scrypt(
        salt=salt,
        length=length,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )

    key = kdf.derive(password.encode())
    return key, salt
