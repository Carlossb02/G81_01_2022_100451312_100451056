from cryptography.fernet import Fernet
from PBKDF2 import *

def fernet_gen_key():
    key=Fernet.generate_key()
    return key.decode("latin-1")

def fernet_encrypt(message):
    key= fernet_gen_key()
    f= Fernet(key)
    token= f.encrypt(message.encode("latin-1"))
    return token.decode("latin-1"), key

def fernet_decrypt(token, key):
    f= Fernet(key)
    message= f.decrypt(token)
    return message.decode("latin-1")