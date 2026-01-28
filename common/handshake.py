import json
import dbus
from common.consts import *
from common.cryptography import verify_certificate, generate_dh_keys, derive_session_key
from cryptography import x509
from common.protocol import Packet
import common.consts as consts
from common.cryptography import verifyMac
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
            
    def confirmSession(self, peerAddr, isInitiator=True, received_pkt=None):
        key = self.session_keys.get(peerAddr)
        if not key:
            print(f"[!] Erro: Nenhuma chave de sessão encontrada para {peerAddr}")
            return False

        if isInitiator:
            pkt = Packet(consts.MY_NID, "SINK", "Control", "KEY_CONFIRMATION")
            data_to_send = pkt.to_bytes(key)

            try:
                bus = dbus.SystemBus()
                dev_path = f"{consts.ADAPTER_PATH}/dev_{peerAddr.replace(':', '_')}"
            
                obj_manager = dbus.Interface(bus.get_object(consts.BLUEZ_SERVICE, "/"), consts.DBUS_OM_IFACE)
                objs = obj_manager.GetManagedObjects()
            
                char_path = None
                for path, ifaces in objs.items():
                    if consts.GATT_CHARACTERISTIC_IFACE in ifaces:
                        if ifaces[consts.GATT_CHARACTERISTIC_IFACE]['UUID'].lower() == consts.CHAT_MSG_UUID.lower() and path.startswith(dev_path):
                            char_path = path
                            break

                if char_path:
                    char_iface = dbus.Interface(bus.get_object(consts.BLUEZ_SERVICE, char_path), consts.GATT_CHARACTERISTIC_IFACE)
                    char_iface.WriteValue(dbus.Array(data_to_send, signature='y'), {})
                    print(f"[*] Confirmação (HMAC) enviada para {peerAddr}")
                    return True
                else:
                    print("[!] Inbox do Sink não encontrada para envio de confirmação.")
                    return False
            except Exception as e:
                print(f"[!] Erro ao enviar confirmação GATT: {e}")
                return False
        else:
            try:
                if not received_pkt or not received_pkt.mac:
                    return False

                original_data = {
                    "src": received_pkt.src_nid, 
                    "dst": received_pkt.dst_nid,
                    "svc": received_pkt.service, 
                    "plt": received_pkt.payload, 
                    "mac": None
                }            
                verifyMac(key, json.dumps(original_data).encode('utf-8'), bytes.fromhex(received_pkt.mac))
                print(f"[+] SUCESSO: Chave de {peerAddr} confirmada e validada!")
                return True
            except Exception as e:
                print(f"[!] ERRO: Falha na confirmação da chave de {peerAddr}: {e}")
                return False
