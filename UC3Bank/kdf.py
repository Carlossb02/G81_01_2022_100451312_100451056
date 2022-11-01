"""kdf"""
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

salt=os.urandom(16)

def derive(password):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(bytes(password, encoding='latin-1')).decode('latin-1'), salt.decode('latin-1')

def verify(password, key, salt_user):
    kdf = Scrypt(salt=salt_user, length=32, n=2**14, r=8, p=1)
    return kdf.verify(bytes(password, encoding='latin-1'), key)