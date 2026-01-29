import json
import base64
import syncUi
import dbus.mainloop.glib
from common.gatt import (
    Application, Service, Characteristic, 
    CertificateCharacteristic, KeyExchangeCharacteristic
)
from common.advertiser import Advertiser
from common.scanner import ForwardingTable
from common.consts import *
from common.protocol import Packet
from common.Dtls import DTLSHandler
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import common.consts as consts
from common.handshake import HandshakeManager
from common.cryptography import get_nid_from_cert, generate_dh_keys
from gi.repository import GLib

MY_CERT = None
MY_KEY = None
CA_CERT = None
CA_CERT_PEM = None
SINK_CERT_PEM = None
SINK_KEY_PEM = None
handshake_manager = None
dtls_sessions = {}

class InboxCharacteristic(Characteristic):
    def __init__(self, bus, index, service, ft):
        self.ft = ft
        Characteristic.__init__(self, bus, index, CHAT_MSG_UUID, ['write'], service)

    def WriteValue(self, value, options):
        sender_path = options.get('device', 'unknown')
        peer_addr = sender_path.split('dev_')[-1].replace('_', ':')
        
        key = handshake_manager.session_keys.get(peer_addr)
        
        packet = Packet.from_bytes(bytes(value), key)
        
        if packet:
            self.ft.update_route(packet.src_nid, peer_addr)
            
            if not handshake_manager.is_nonce_valid(peer_addr, bytes.fromhex(packet.nonce)):
                print(f"[!] REPLAY DETECTADO de {peer_addr}. Mensagem descartada.")
                return []
            if packet.service == "DTLS":
                self._handle_dtls_e2e(packet, peer_addr)
            elif packet.service == "Control" and packet.payload == "KEY_CONFIRM_GCM":
                handshake_manager.confirmSession(peer_addr, isInitiator=False, received_pkt=packet)
            else:
                print(f"[SINK] Mensagem CIFRADA recebida de {packet.src_nid}: {packet.payload}")
        else:
            print(f"[!] AVISO: Falha na decifragem ou TAG inválida de {peer_addr}. Mensagem descartada.")
        
        return []
    
    def _handle_dtls_e2e(self, packet, last_hop_mac):
        nid = packet.src_nid
        if nid not in dtls_sessions:
            dtls_sessions[nid] = DTLSHandler(SINK_CERT_PEM, SINK_KEY_PEM, CA_CERT_PEM, is_server=True)
        
        raw_dtls = base64.b64decode(packet.payload)
        clear_text = dtls_sessions[nid].handle_incoming(raw_dtls) 
        
        resp_handshake = dtls_sessions[nid].get_outgoing_network_data()
        if resp_handshake:
            self._send_raw_dtls(nid, last_hop_mac, resp_handshake)
            
        if clear_text:
            try:
                app_data = json.loads(clear_text.decode('utf-8'))
                port = app_data.get("port")
                message = app_data.get("data")
                
                print(f"--- MENSAGEM DTLS (NID: {nid}, PORT: {port}) ---")
                print(f"Conteúdo: {message}")
                
                self.send_downlink_msg(nid, last_hop_mac, port, f"ACK Port {port}")
                
                if self.ui_ref:
                    self.ui_ref.add_log(nid, f"P:{port} - {message}")
            except Exception as e:
                print(f"[SINK] Erro ao processar payload da app: {e}")

    def send_downlink_msg(self, target_nid, last_hop_mac, port, message):
        payload = json.dumps({"port": port, "data": message})
        dtls_cipher = dtls_sessions[target_nid].encrypt(payload)
        if dtls_cipher:
            self._send_raw_dtls(target_nid, last_hop_mac, dtls_cipher)

    def _send_raw_dtls(self, nid, mac, data):
        pkt = Packet(consts.MY_NID, nid, "DTLS", base64.b64encode(data).decode())
        key = handshake_manager.session_keys.get(mac)
        nonce = handshake_manager.get_next_tx_nonce(mac)
        handshake_manager._write_to_remote_inbox(mac, pkt.to_bytes(key, nonce))
        
class HeartbeatCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        self.uuid = '87654321-4321-4321-4321-210987654321'
        Characteristic.__init__(self, bus, index, self.uuid, ['notify'], service)
        self.counter = 0
        self.notifying = False
        self.silenced_macs = set()

    def send_heartbeat(self):
        if self.notifying:
            self.counter += 1
            data = str(self.counter).encode('utf-8')
            signed = MY_KEY.sign(data, ec.ECDSA(hashes.SHA256()))
            value = data + b'|' + signed
            self.PropertiesChanged(GATT_CHARACTERISTIC_IFACE, {'Value': dbus.Array(value, signature='y')}, [])
            print(f"[SINK] Heartbeat enviado: {self.counter}")
        return True

    def StartNotify(self):
        self.notifying = True

    def StopNotify(self):
        self.notifying = False

def load_credentials():
    global MY_CERT, MY_KEY, CA_CERT, CA_CERT_PEM, SINK_CERT_PEM, SINK_KEY_PEM
    try:
        with open("../certs/ca_cert.pem", "rb") as f:
            CA_CERT_PEM = f.read()
            CA_CERT = x509.load_pem_x509_certificate(CA_CERT_PEM)
        
        with open("../certs/sink_cert.pem", "rb") as f:
            SINK_CERT_PEM = f.read()
            MY_CERT = x509.load_pem_x509_certificate(SINK_CERT_PEM)
            consts.MY_NID = get_nid_from_cert(MY_CERT)
        
        with open("../certs/sink_key.pem", "rb") as f:
            SINK_KEY_PEM = f.read()
            MY_KEY = serialization.load_pem_private_key(SINK_KEY_PEM, password=None)
            
        print(f"[SINK] Credenciais carregadas. NID: {consts.MY_NID}")
    except Exception as e:
        print(f"[!] Erro ao carregar certificados: {e}")
        exit(1)

def main():
    global handshake_manager
    load_credentials()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    ft = ForwardingTable()
    
    handshake_manager = HandshakeManager(CA_CERT, MY_CERT, MY_KEY)
    
    app = Application(bus)
    service = Service(bus, '/org/bluez/example/service', 0, INBOX_SERVICE_UUID, True)
    
    cert_bytes = MY_CERT.public_bytes(serialization.Encoding.PEM)
    service.add_characteristic(CertificateCharacteristic(bus, 2, service, cert_bytes))
    
    _, local_dh_pub = generate_dh_keys()
    pub_bytes = local_dh_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    def on_key_received(value,options):
        device_path = options.get('device', '')
        peer_addr = device_path.split('dev_')[-1].replace('_', ':')
        handshake_manager.handle_incoming_key(peer_addr, value)

    key_chrc = KeyExchangeCharacteristic(bus, 3, service, pub_bytes, on_key_received)
    service.add_characteristic(key_chrc)

    service.add_characteristic(InboxCharacteristic(bus, 0, service, ft))
    service.add_characteristic(HeartbeatCharacteristic(bus, 1, service))
    
    app.add_service(service)
    
    manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, ADAPTER_PATH), GATT_MANAGER_IFACE)
    manager.RegisterApplication(app.path, {}, reply_handler=None, error_handler=None)

    GLib.timeout_add_seconds(5, service.get_characteristics()[3].send_heartbeat)
    
    hb_chrc = service.get_characteristics()[3] # Heartbeat é a 4ª característica
    ui = syncUi.SinkUI(handshake_manager, ft, hb_chrc)
    
    inbox_chrc = service.get_characteristics()[2] # Inbox é a 3ª característica
    inbox_chrc.ui_ref = ui
    
    ui.start()
    
    adv = Advertiser()
    adv.start_advertising(0, [SERVICE_UUID, INBOX_SERVICE_UUID])
    
    print(f"[SINK] Ativo. NID: {consts.MY_NID}")
    GLib.MainLoop().run()

if __name__ == "__main__":
    main()