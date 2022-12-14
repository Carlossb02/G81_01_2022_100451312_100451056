from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from RSA import *
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15 as asym_padding

def cert_verify_company(company):
    issuer_public_key=rsa_load_public("System")
    cert_to_check = cert_read_pem("Database/Certs/nuevoscerts/"+company+".pem")
        #x509.load_pem_x509_certificate(pem_data_to_check)
    issuer_public_key.verify(
        cert_to_check.signature,
        cert_to_check.tbs_certificate_bytes,
        # Depends on the algorithm used to create the certificate
        padding.PKCS1v15(),
        cert_to_check.signature_hash_algorithm,
)
    cert_verify_ca()

def cert_verify_ca():
    issuer_public_key=rsa_load_public("System")
    cert_to_check = cert_read_pem("Database/Certs/ac1cert.pem")
        #x509.load_pem_x509_certificate(pem_data_to_check)
    issuer_public_key.verify(
        cert_to_check.signature,
        cert_to_check.tbs_certificate_bytes,
        # Depends on the algorithm used to create the certificate
        padding.PKCS1v15(),
        cert_to_check.signature_hash_algorithm,
)

def cert_read_pem(path):
    with open(path) as file:
        certificado = x509.load_pem_x509_certificate(file.read().encode("latin-1"),)
    return certificado

