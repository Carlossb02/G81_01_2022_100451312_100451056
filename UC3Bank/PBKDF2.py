"""PBKDF2"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

salt=os.urandom(16)

def pbkdf2_derive(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=400000)
    return kdf.derive(bytes(password, encoding='latin-1')).decode('latin-1'), salt.decode('latin-1')

def pbkdf2_verify(password, key, salt_user):
    kdf= PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_user,
        iterations=400000)
    return kdf.verify(bytes(password, encoding='latin-1'), key)