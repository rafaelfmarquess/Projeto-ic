import dbus.mainloop.glib
from common.scanner import *
from common.advertiser import Advertiser
from common.gatt import Application, Service
from common.consts import *
from common.protocol import *
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from common.cryptography import get_nid_from_cert
from common.cryptography import verify_certificate
import common.consts as consts
from cryptography.hazmat.primitives import serialization
from gi.repository import GLib

class HeartbeatMonitor:
    def __init__(self, node_control):
        self.missed_count = 0
        self.ctrl = node_control

    def heartbeat_received(self, value):
        try:
            parts = bytes(value).split(b'|', 1)
            counter_data = parts[0]
            signature = parts[1]
            self.sink_pub_key.verify(signature, counter_data, ec.ECDSA(hashes.SHA256()))
            print(f"[NODE] Heartbeat verificado com sucesso: {counter_data.decode()}")
            self.missed_count = 0
        except Exception as e:
            print(f"[!] Erro na verificação do Heartbeat: {e}")

    def check_liveness(self):
        self.missed_count += 1
        if self.missed_count >= 3:
            print("[!] LINK DOWN: 3 heartbeats perdidos. A resetar nó...")
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
                    char_iface = dbus.Interface(char_obj, GATT_CHARACTERISTIC_IFACE)
                    char_iface.StartNotify()
                    print("[NODE] Escuta de Heartbeat ativada.")
                    return True
    except Exception as e:
        print(f"[!] Erro ao ligar ao Heartbeat: {e}")
    return False

def get_and_verify_uplink_cert(ctrl):
    bus = dbus.SystemBus()
    dev_path = f"{ADAPTER_PATH}/dev_{ctrl.current_uplink.replace(':', '_')}"
    cert_uuid = '99999999-9999-9999-9999-999999999999'

    try:
        obj_manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, "/"), DBUS_OM_IFACE)
        objs = obj_manager.GetManagedObjects()

        char_path = None
        for path, ifaces in objs.items():
            if GATT_CHARACTERISTIC_IFACE in ifaces:
                props = ifaces[GATT_CHARACTERISTIC_IFACE]
                if props['UUID'].lower() == cert_uuid.lower() and path.startswith(dev_path):
                    char_path = path
                    break

        if not char_path:
            print("[!] Característica de certificado não encontrada no uplink.")
            return None

        char_obj = bus.get_object(BLUEZ_SERVICE, char_path)
        char_iface = dbus.Interface(char_obj, GATT_CHARACTERISTIC_IFACE)
        
        cert_bytes = bytes(char_iface.ReadValue({}))

        cert = x509.load_pem_x509_certificate(cert_bytes)
        
        if verify_certificate(cert, CA_CERT):
            print(f"[+] Certificado do uplink ({ctrl.current_uplink}) verificado com sucesso.")
            return cert.public_key()
        else:
            print("[!] O certificado do uplink é INVÁLIDO ou não foi assinado pela nossa CA.")
            return None

    except Exception as e:
        print(f"[!] Erro crítico ao obter/verificar certificado do uplink: {e}")
        return None

def send_message_to_sink(ctrl, text):
    pkt = Packet(src_nid=MY_NID, dst_nid="SINK", service="Inbox", payload=text)
    raw_bytes = pkt.to_bytes()
    print(f"[NODE] Pacote pronto para enviar: {pkt.payload}")
    
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
            
        print(f"[NODE] Credenciais de {node_name} carregadas. NID: {consts.MY_NID}")
    except Exception as e:
        print(f"[!] Erro ao carregar certificados para {node_name}: {e}")
        exit(1)


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    ctrl = NodeControl()
    adv = Advertiser()
    ft = ForwardingTable()
    if len(sys.argv) < 2:
        print("Uso: python3 nodeMain.py [node1|node2|node3]")
        return
    node_selection = sys.argv[1]
    load_node_credentials(node_selection)

    if ctrl.establish_uplink():
        # 1. FASE DE HANDSHAKE
        sink_pub_key = get_and_verify_uplink_cert(ctrl)
        
        if sink_pub_key:
            monitor = HeartbeatMonitor(ctrl, sink_pub_key)
            GLib.timeout_add_seconds(5, monitor.check_liveness)
            setup_heartbeat_listener(ctrl, monitor)

            bus = dbus.SystemBus()
            app = Application(bus)
            app.add_service(Service(bus, '/org/bluez/node/service', 0, SERVICE_UUID, True))
            
            manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, ADAPTER_PATH), GATT_MANAGER_IFACE)
            manager.RegisterApplication(app.path, {}, reply_handler=None, error_handler=None)
            
            adv.start_advertising(ctrl.my_hop_count, [SERVICE_UUID])
        else:
            print("[!] Abortar: Uplink não é confiável.")
            ctrl.destroy_all_connections()
    GLib.MainLoop().run()

if __name__ == "__main__":
    main()