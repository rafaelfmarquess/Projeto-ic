import dbus.mainloop.glib
from common.gatt import Application, Service, Characteristic
from common.advertiser import Advertiser
from common.scanner import ForwardingTable
from common.consts import *
from common.protocol import *
from common.gatt import *
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import common.consts as consts
from common.cryptography import get_nid_from_cert
from cryptography.hazmat.primitives import serialization
from gi.repository import GLib

MY_CERT = None
MY_KEY = None
CA_CERT = None

class InboxCharacteristic(Characteristic):
    def __init__(self, bus, index, service,ft):
        self.ft = ft
        Characteristic.__init__(self, bus, index, CHAT_MSG_UUID, ['write'], service)

    def WriteValue(self, value, options):
        packet = Packet.from_bytes(bytes(value))
        if packet:
            sender_path = options.get('device', 'unknown')
            self.ft.update_route(packet.src_nid, sender_path)
            
            print(f"[SINK] Inbox: '{packet.payload}' recebido de {packet.src_nid}")
        return []

class HeartbeatCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        self.uuid = '87654321-4321-4321-4321-210987654321'
        Characteristic.__init__(self, bus, index, self.uuid, ['notify'], service)
        self.counter = 0
        self.notifying = False

    def send_heartbeat(self):
        if self.notifying:
            self.counter += 1
            data = str(self.counter).encode('utf-8')
            signed = MY_KEY.sign(data,ec.ECDSA(hashes.SHA256()))
            value = data + b'|' + signed
            self.PropertiesChanged(GATT_CHARACTERISTIC_IFACE, {'Value': dbus.Array(value, signature='y')}, [])
            print(f"[SINK] Heartbeat enviado: {self.counter}")
        return True

    def StartNotify(self):
        self.notifying = True

    def StopNotify(self):
        self.notifying = False

def load_credentials():
    global MY_CERT, MY_KEY, CA_CERT
    try:
        with open("../certs/ca_cert.pem", "rb") as f:
            CA_CERT = x509.load_pem_x509_certificate(f.read())
        
        with open("../certs/sink_cert.pem", "rb") as f:
            MY_CERT = x509.load_pem_x509_certificate(f.read())
            consts.MY_NID = get_nid_from_cert(MY_CERT)
        
        with open("../certs/sink_key.pem", "rb") as f:
            MY_KEY = serialization.load_pem_private_key(f.read(), password=None)
            
        print(f"[SINK] Credenciais carregadas. NID: {consts.MY_NID}")
    except Exception as e:
        print(f"[!] Erro ao carregar certificados: {e}")
        exit(1)

def main():
    load_credentials()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    ft = ForwardingTable()
    
    app = Application(bus)
    service = Service(bus, '/org/bluez/example/service', 0, INBOX_SERVICE_UUID, True)
    cert_chrc = CertificateCharacteristic(bus, 2, service, MY_CERT.public_bytes(serialization.Encoding.PEM))
    service.add_characteristic(cert_chrc)
    service.add_characteristic(InboxCharacteristic(bus, 0, service, ft))
    service.add_characteristic(HeartbeatCharacteristic(bus, 1, service))
    app.add_service(service)
    
    manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, ADAPTER_PATH), GATT_MANAGER_IFACE)
    manager.RegisterApplication(app.path, {}, reply_handler=None, error_handler=None)

    GLib.timeout_add_seconds(5, service.get_characteristics()[1].send_heartbeat)
    
    adv = Advertiser()
    adv.start_advertising(0, [SERVICE_UUID, INBOX_SERVICE_UUID])
    
    print(f"[SINK] Ativo. NID: {consts.MY_NID}")
    GLib.MainLoop().run()

if __name__ == "__main__":
    main()