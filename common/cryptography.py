from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

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
            return False
            
        return True
    except Exception:
        return False

def get_nid_from_cert(cert):
    for attribute in cert.subject:
        if attribute.oid == NameOID.COMMON_NAME:
            return attribute.value
    return None