import os
import exrex
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils

def rsa_genkeys(username, password):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    if not os.path.exists("Database/System/Users/PRIVATE/PRK_" + username + ".pem"):
        rsa_serialization_private(private_key, username, password)
    if not os.path.exists("Database/System/Users/PUBLIC/PBK_" + username + ".pem"):
        rsa_serialization_public(private_key, username)

def rsa_serialization_private(private_key, username, password):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('latin-1'))
    )
    with open("Database/System/Users/PRIVATE/PRK_"+username+".pem", "wb+") as file:
        file.write(pem)


def rsa_serialization_public(private_key, username):
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("Database/System/Users/PUBLIC/PBK_"+username+".pem", "wb+") as file:
        file.write(pem)

def rsa_load_private(username, password):

    if os.path.exists("Database/System/Users/PRIVATE/PRK_" + username + ".pem"):
        with open("Database/System/Users/PRIVATE/PRK_" + username + ".pem", "rb") as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=password.encode('latin-1'),
            )
        return private_key
    #ERROR RSA_001: Nunca debería poder aparecer este error salvo que la base de datos sea borrada parcial o totalmente.
    #Indica que la clave privada del usuario no se encuentra en el sistema.
    print ("\033[91mError: Error RSA_001, contacta con un administrador\n")

def rsa_load_public(username):
    if os.path.exists("Database/System/Users/PUBLIC/PBK_" + username + ".pem"):
        with open("Database/System/Users/PUBLIC/PBK_" + username + ".pem", "rb") as file:
            public_key = serialization.load_pem_public_key(
                file.read(),
            )
        return public_key
    #ERROR RSA_002: Nunca debería poder aparecer este error salvo que la base de datos sea borrada parcial o totalmente.
    #Indica que la clave pública del usuario no se encuentra en el sistema.
    print ("\033[91mError: Error RSA_001, contacta con un administrador\n")

def rsa_sign_text(username, password, text):
    """El texto es firmado por el usuario 'username'"""
    private_key=rsa_load_private(username, password)
    signature = private_key.sign(
        text.encode('latin-1'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())
    return signature.decode('latin-1')


def rsa_verify_sign(remitente, signature, text):
    public_key=rsa_load_public(remitente)
    try:
        public_key.verify(
            signature.encode('latin-1'),
            text.encode('latin-1'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        #RSA_003 indica que no se ha podido verificar la firma del mensaje
        raise Exception("\033[91mError: Error RSA_003, contacta con un administrador\n")

def rsa_encrypt(message, username):
    public_key = rsa_load_public(username)
    message=message.encode("latin-1")
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext.decode("latin-1")


def rsa_decrypt(ciphertext, username, password):
    private_key = rsa_load_private(username, password)
    plaintext = private_key.decrypt(
        ciphertext.encode("latin-1"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode("latin-1")

#keys=rsa_genkeys("Juan", "Prueba1")
#rsa_load_private("Puan", "Prueba1")
#print(isinstance(rsa_load_public("Juan"), rsa.RSAPublicKey))
#a=rsa_sign_text("Juan", "Prueba1", "Buenas tardes")
#rsa_verify_sign("Juan", a, "Buenas tardes"))
#print(exrex.getone(r'SL[a-zA-Z0-9]{4}'+str(int(datetime.datetime.utcnow().timestamp()))[7:]))
#a=rsa_encrypt("SLpwFC824", "Juan")
#print(len(rsa_sign_text("Juan", "Prueba1", "SLpwFC824")))
#print(rsa_decrypt(a, "Juan", "Prueba1"))