import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from RSA import rsa_load_private
# Generate a CSR

def csr_company(empresa, user, password):
    if os.path.exists("Database/Certs/Solicitudes/"+user+".pem"):
        return
    key=rsa_load_private(user, password)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, empresa.pais),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, empresa.estado),
        x509.NameAttribute(NameOID.LOCALITY_NAME, empresa.ciudad),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, empresa.nombre),
        x509.NameAttribute(NameOID.COMMON_NAME, empresa.web),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(u"localhost"),
            x509.DNSName(u"www.uc3bank.es"),
        ]),
        critical=False,
    # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256())
    # Write our CSR out to disk.
    with open("Database/Certs/Solicitudes/"+user+".pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
