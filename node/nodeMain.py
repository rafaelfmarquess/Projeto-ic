import sys
import dbus
import dbus.mainloop.glib
from common.scanner import NodeControl, ForwardingTable
from common.gatt import Characteristic
from common.advertiser import Advertiser
from common.gatt import Application, Service, CertificateCharacteristic, KeyExchangeCharacteristic
from common.consts import *
import common.consts as consts
from common.protocol import Packet
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from common.cryptography import get_nid_from_cert, verify_certificate, generate_dh_keys
from common.handshake import HandshakeManager
from gi.repository import GLib

MY_CERT = None
MY_KEY = None
CA_CERT = None
handshake_manager = None

class NodeInboxCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        Characteristic.__init__(self, bus, index, CHAT_MSG_UUID, ['write'], service)

    def WriteValue(self, value, options):
        sender_path = options.get('device', 'unknown')
        peer_addr = sender_path.split('dev_')[-1].replace('_', ':')
        
        key = handshake_manager.session_keys.get(peer_addr)
        
        packet = Packet.from_bytes(bytes(value), key)
        
        if packet:
            if not handshake_manager.is_nonce_valid(peer_addr, bytes.fromhex(packet.nonce)):
                print(f"[!] REPLAY DETECTADO de {peer_addr}. Mensagem descartada.")
                return []
            if packet.service == "Control" and packet.payload == "KEY_CONFIRM_ACK":
                handshake_manager.confirmSession(peer_addr, isInitiator=True, received_pkt=packet)
            else:
                print(f"[NODE] Mensagem cifrada recebida de {packet.src_nid}: {packet.payload}")
        else:
            print(f"[!] Erro: Falha na integridade (Tag GCM inválida) de {peer_addr}")
        
        return []

class HeartbeatMonitor:
    def __init__(self, node_control, sink_pub_key):
        self.missed_count = 0
        self.ctrl = node_control
        self.sink_pub_key = sink_pub_key 

    def heartbeat_received(self, value):
        try:
            parts = bytes(value).split(b'|', 1)
            if len(parts) < 2: return
            
            counter_data = parts[0]
            signature = parts[1]
            
            self.sink_pub_key.verify(signature, counter_data, ec.ECDSA(hashes.SHA256()))
            print(f"[NODE] Heartbeat verificado com sucesso: {counter_data.decode()}")
            self.missed_count = 0
        except Exception as e:
            print(f"[!] Erro na verificação do Heartbeat (Possível intruso): {e}")

    def check_liveness(self):
        self.missed_count += 1
        if self.missed_count >= 3:
            print("[!] LINK DOWN: 3 heartbeats perdidos ou falha de autenticação. A resetar nó...")
            self.ctrl.destroy_all_connections() 
            return False
        return True

def setup_heartbeat_listener(ctrl, monitor):
    bus = dbus.SystemBus()
    dev_path = f"{ADAPTER_PATH}/dev_{ctrl.current_uplink.replace(':', '_')}"
    hb_uuid = '87654321-4321-4321-4321-210987654321'
    
    try:
        obj_manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, "/"), DBUS_OM_IFACE)
        objs = obj_manager.GetManagedObjects()
        
        for path, ifaces in objs.items():
            if GATT_CHARACTERISTIC_IFACE in ifaces:
                props = ifaces[GATT_CHARACTERISTIC_IFACE]
                if props['UUID'] == hb_uuid and dev_path in path:
                    char_obj = bus.get_object(BLUEZ_SERVICE, path)
                    bus.add_signal_receiver(
                        lambda iface, changed, inval: monitor.heartbeat_received(changed['Value']) if 'Value' in changed else None,
                        dbus_interface=DBUS_PROP_IFACE,
                        signal_name="PropertiesChanged",
                        path=path
                    )
                    dbus.Interface(char_obj, GATT_CHARACTERISTIC_IFACE).StartNotify()
                    print("[NODE] Escuta de Heartbeat ativada.")
                    return True
    except Exception as e:
        print(f"[!] Erro ao ligar ao Heartbeat: {e}")
    return False

def load_node_credentials(node_name):
    global MY_CERT, MY_KEY, CA_CERT
    try:
        with open("../certs/ca_cert.pem", "rb") as f:
            CA_CERT = x509.load_pem_x509_certificate(f.read())
        with open(f"../certs/{node_name}_cert.pem", "rb") as f:
            MY_CERT = x509.load_pem_x509_certificate(f.read())
            consts.MY_NID = get_nid_from_cert(MY_CERT)
        with open(f"../certs/{node_name}_key.pem", "rb") as f:
            MY_KEY = serialization.load_pem_private_key(f.read(), password=None)
        print(f"[NODE] Credenciais carregadas para {node_name}. NID oficial: {consts.MY_NID}")
    except Exception as e:
        print(f"[!] Erro ao carregar certificados: {e}")
        exit(1)

def main():
    global handshake_manager
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    
    if len(sys.argv) < 2:
        print("Uso: python3 nodeMain.py [node1|node2|node3]")
        return
    
    load_node_credentials(sys.argv[1])
    handshake_manager = HandshakeManager(CA_CERT, MY_CERT, MY_KEY)
    
    ctrl = NodeControl()
    adv = Advertiser()

    if ctrl.establish_uplink():
        if handshake_manager.perform_handshake(ctrl, ctrl.current_uplink):
            
            handshake_manager.confirmSession(ctrl.current_uplink, isInitiator=True)
            
            sink_pub_key = handshake_manager._get_and_verify_peer_cert(ctrl.current_uplink)
            monitor = HeartbeatMonitor(ctrl, sink_pub_key)
            GLib.timeout_add_seconds(5, monitor.check_liveness)
            setup_heartbeat_listener(ctrl, monitor)

            bus = dbus.SystemBus()
            app = Application(bus)
            service = Service(bus, '/org/bluez/node/service', 0, SERVICE_UUID, True)
            
            cert_pem = MY_CERT.public_bytes(serialization.Encoding.PEM)
            service.add_characteristic(CertificateCharacteristic(bus, 0, service, cert_pem))
            
            _, local_dh_pub = generate_dh_keys()
            dh_pub_bytes = local_dh_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_chrc = KeyExchangeCharacteristic(bus, 1, service, dh_pub_bytes,
                                               lambda val, opts: handshake_manager.handle_incoming_key(
                                                   opts.get('device','').split('dev_')[-1].replace('_', ':'), val))
            service.add_characteristic(key_chrc)
            
            service.add_characteristic(NodeInboxCharacteristic(bus, 2, service))
            
            app.add_service(service)
            
            manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, ADAPTER_PATH), GATT_MANAGER_IFACE)
            manager.RegisterApplication(app.path, {}, reply_handler=None, error_handler=None)
            
            adv.start_advertising(ctrl.my_hop_count, [SERVICE_UUID])
            print(f"[NODE] Setup concluído. À espera de confirmação mútua e dados.")
        else:
            print("[!] Falha crítica no handshake. A desconectar...")
            ctrl.destroy_all_connections()
    else:
        adv.start_advertising(255, [SERVICE_UUID])

    GLib.MainLoop().run()

if __name__ == "__main__":
    main()