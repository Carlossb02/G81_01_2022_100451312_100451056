import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from RSA import *

def generar_certificado(empresa, password):
    key=rsa_load_private(empresa.nombre, password)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, empresa.pais),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, empresa.estado),
        x509.NameAttribute(NameOID.LOCALITY_NAME, empresa.ciudad),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, empresa.nombre),
        x509.NameAttribute(NameOID.COMMON_NAME, empresa.web),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    # Sign our certificate with our private key
    ).sign(key, hashes.SHA256())
    # Write our certificate out to disk.
    with open("path/to/certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))