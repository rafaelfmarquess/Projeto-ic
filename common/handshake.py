import dbus
from common.consts import *
from common.cryptography import verify_certificate, generate_dh_keys, derive_session_key
from cryptography import x509
from common.protocol import Packet
import common.consts as consts
from common.cryptography import verify_mac
from cryptography.hazmat.primitives import serialization

class HandshakeManager:
    def __init__(self, ca_cert, local_cert, local_key):
        self.ca_cert = ca_cert
        self.local_cert = local_cert
        self.local_key = local_key
        self.session_keys = {}  
        self.local_dh_priv = None 
    
    def _initiate_ecdh(self, peer_addr):
        bus = dbus.SystemBus()
        dev_path = f"{ADAPTER_PATH}/dev_{peer_addr.replace(':', '_')}"
        dh_uuid = '77777777-7777-7777-7777-777777777777'

        self.local_dh_priv, local_dh_pub = generate_dh_keys()
        local_pub_bytes = local_dh_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        try:
            obj_manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, "/"), DBUS_OM_IFACE)
            objs = obj_manager.GetManagedObjects()

            for path, ifaces in objs.items():
                if GATT_CHARACTERISTIC_IFACE in ifaces:
                    props = ifaces[GATT_CHARACTERISTIC_IFACE]
                    if props['UUID'].lower() == dh_uuid and path.startswith(dev_path):
                        char_iface = dbus.Interface(bus.get_object(BLUEZ_SERVICE, path), GATT_CHARACTERISTIC_IFACE)
                        
                        peer_dh_pub_bytes = bytes(char_iface.ReadValue({}))
                        
                        char_iface.WriteValue(dbus.Array(local_pub_bytes, signature='y'), {})
                        
                        return derive_session_key(self.local_dh_priv, peer_dh_pub_bytes)
            return None
        except Exception:
            return None
    
    def _get_and_verify_peer_cert(self, peer_addr):
        bus = dbus.SystemBus()
        dev_path = f"{ADAPTER_PATH}/dev_{peer_addr.replace(':', '_')}"
        cert_uuid = '99999999-9999-9999-9999-999999999999'

        try:
            obj_manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, "/"), DBUS_OM_IFACE)
            objs = obj_manager.GetManagedObjects()

            for path, ifaces in objs.items():
                if GATT_CHARACTERISTIC_IFACE in ifaces:
                    props = ifaces[GATT_CHARACTERISTIC_IFACE]
                    if props['UUID'].lower() == cert_uuid and path.startswith(dev_path):
                        char_iface = dbus.Interface(bus.get_object(BLUEZ_SERVICE, path), GATT_CHARACTERISTIC_IFACE)
                        cert_bytes = bytes(char_iface.ReadValue({}))
                        cert = x509.load_pem_x509_certificate(cert_bytes)
                        
                        if verify_certificate(cert, self.ca_cert):
                            return cert.public_key()
            return None
        except Exception:
            return None
        
    def perform_handshake(self, ctrl, peer_addr):
        print(f"[*] A iniciar handshake seguro com {peer_addr}...")
        
        peer_pub_key = self._get_and_verify_peer_cert(peer_addr)
        if not peer_pub_key:
            print(f"[!] Falha na autenticação de {peer_addr}. Abortar.")
            return False

        session_key = self._initiate_ecdh(peer_addr)
        if session_key:
            self.session_keys[peer_addr] = session_key
            print(f"[+] Chave de sessão estabelecida com {peer_addr}: {session_key.hex()[:10]}...")
            return True
        
        return False

    def handle_incoming_key(self, peer_addr, peer_dh_pub_bytes):
        try:
            if not self.local_dh_priv:
                self.local_dh_priv, _ = generate_dh_keys()

            session_key = derive_session_key(self.local_dh_priv, peer_dh_pub_bytes)
            self.session_keys[peer_addr] = session_key
            print(f"[SINK] Chave de sessão gerada para {peer_addr}")
        except Exception as e:
            print(f"[!] Erro ao processar chave do peer: {e}")
            
    def confirmSession(self,peerAddr,isInitiator = True):
        key = self.session_keys.get(peerAddr)
        if not key : return False
        
        if isInitiator:
            pkt = Packet(consts.MY_NID,"SINK","Control","KEY_CONFIRMATION")
            print(f"[*] A enviar confirmação de chave para {peer_addr}...")
            
            return True
        return False

