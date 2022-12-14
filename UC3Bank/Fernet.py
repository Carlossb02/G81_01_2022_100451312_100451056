from cryptography.fernet import Fernet
import base64
from kdf import *
from PBKDF2 import *

def fernet_gen_key():
    key=Fernet.generate_key()
    return key.decode("latin-1")

def fernet_encrypt(message, key, salt):
    key_64 = base64.urlsafe_b64encode(derive_fernet(key.decode("latin-1"), salt.encode("latin-1"))[0].encode("latin-1"))
    f= Fernet(key_64)

    token= f.encrypt(message.encode("latin-1"))
    return token.decode("latin-1"), key_64

def fernet_decrypt(token, key, salt):
    key_64 = base64.urlsafe_b64encode(derive_fernet(key.decode("latin-1"), salt.encode("latin-1"))[0].encode("latin-1"))
    f= Fernet(key_64)
    message= f.decrypt(token)
    return message.decode("latin-1")