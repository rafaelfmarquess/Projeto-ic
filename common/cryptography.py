import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac 

def verify_certificate(cert_to_verify, ca_cert):
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert_to_verify.signature,
            cert_to_verify.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        
        now = datetime.datetime.utcnow()
        if cert_to_verify.not_valid_before > now or cert_to_verify.not_valid_after < now:
            print("[CRYPTO] Certificado fora do prazo de validade.")
            return False
            
        return True
    except Exception as e:
        print(f"[CRYPTO] Falha na verificação: {e}")
        return False

def get_nid_from_cert(cert):
    for attribute in cert.subject:
        if attribute.oid == NameOID.COMMON_NAME:
            return attribute.value
    return None

def generate_dh_keys():
    private_key = ec.generate_private_key(ec.SECP521R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_session_key(private_key, peer_public_key_bytes):
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
    
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'session-key-agreement',
    ).derive(shared_secret)
    
    return derived_key