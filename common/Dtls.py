import mbedtls.tls as tls
from mbedtls.x509 import CRT
from mbedtls.pk import ECC

class DTLSHandler:
    def __init__(self, cert_pem, key_pem, ca_cert_pem, is_server=False):
        trust_store = tls.TrustStore()
        trust_store.add(CRT.from_pem(ca_cert_pem.decode()))

        self.conf = tls.DTLSConfiguration(
            validate_certificates=True,
            trust_store=trust_store,
            certificate_chain=([CRT.from_pem(cert_pem.decode())], ECC.from_pem(key_pem.decode()))
        )
        
        if is_server:
            self.context = tls.DTLSServerContext(self.conf)
            self.session = self.context.wrap_buffers()
        else:
            self.context = tls.DTLSClientContext(self.conf)
            self.session = self.context.wrap_buffers(server_hostname="SINK")
            
        self.is_established = False

    def handle_incoming(self, data):
        try:
            self.session.receive_from_network(data)
            if self.is_established:
                return self.session.read(4096)
            
            self.do_handshake()
            return None
        except Exception as e:
            print(f"[DTLS] Erro ao processar: {e}")
            return None

    def do_handshake(self):
        try:
            if not self.is_established:
                self.session.do_handshake()
                self.is_established = True
                print("[DTLS] Canal Seguro Estabelecido!")
        except tls.WantWriteError:
            pass
        except tls.WantReadError:
            pass

    def get_outgoing_network_data(self):
        return self.session.peek_outgoing_for_network()

    def encrypt(self, message):
        if self.is_established:
            self.session.write(message.encode())
            return self.get_outgoing_network_data()
        return None

def is_client_hello(data):

    return len(data) > 13 and data[0] == 22 and data[13] == 1