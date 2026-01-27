import os
import uuid
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP521R1()
CERTS_DIR = "../certs"

os.makedirs(CERTS_DIR, exist_ok=True)

def generate_ca():
    """Gera a CA Raiz do projeto."""
    private_key = ec.generate_private_key(CURVE)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"SIC Project Root CA"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(private_key, hashes.SHA256())
    return private_key, cert

def generate_device_cert(ca_key, ca_cert, nid, is_sink=False):
    """Gera um certificado assinado pela CA para um dispositivo."""
    device_key = ec.generate_private_key(CURVE)
    subject_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, str(nid))]
    
    if is_sink:
        subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Sink-Device"))

    subject = x509.Name(subject_attributes)
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(
        device_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(ca_key, hashes.SHA256())
    return device_key, cert

def save_key_cert(name, key, cert):
    """Guarda a chave privada e o certificado em formato PEM."""
    key_pem = key.private_bytes(encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    with open(os.path.join(CERTS_DIR, f"{name}_key.pem"), "wb") as f: f.write(key_pem)
    with open(os.path.join(CERTS_DIR, f"{name}_cert.pem"), "wb") as f: f.write(cert_pem)

ca_key, ca_cert = generate_ca()
save_key_cert("ca", ca_key, ca_cert)

s_key, s_cert = generate_device_cert(ca_key, ca_cert, str(uuid.uuid4()), is_sink=True)
save_key_cert("sink", s_key, s_cert)

for i in range(1, 4):
    n_key, n_cert = generate_device_cert(ca_key, ca_cert, str(uuid.uuid4()))
    save_key_cert(f"node{i}", n_key, n_cert)

print("Certificados PEM gerados com sucesso na pasta 'certs'.")