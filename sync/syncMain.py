import dbus.mainloop.glib
from common.gatt import Application, Service, Characteristic
from common.advertiser import Advertiser
from common.scanner import ForwardingTable
from common.consts import *
from common.protocol import *
from cryptography import x509
from common.cryptography import get_nid_from_cert
from gi.repository import GLib

class InboxCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
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
            value = str(self.counter).encode('utf-8')
            self.PropertiesChanged(GATT_CHARACTERISTIC_IFACE, {'Value': dbus.Array(value, signature='y')}, [])
            print(f"[SINK] Heartbeat enviado: {self.counter}")
        return True

    def StartNotify(self):
        self.notifying = True

    def StopNotify(self):
        self.notifying = False

def load_identity():
    try:
        with open("../certs/sink_cert.pem", "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
            consts.MY_NID = get_nid_from_cert(cert)
            print(f"[SINK] Identidade carregada do certificado: {consts.MY_NID}")
    except FileNotFoundError:
        print("[!] Erro: Certificado do Sink não encontrado em ../certs/")
        exit(1)

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    ft = ForwardingTable()
    
    app = Application(bus)
    service = Service(bus, '/org/bluez/example/service', 0, INBOX_SERVICE_UUID, True)
    service.add_characteristic(InboxCharacteristic(bus, 0, service, ft))
    service.add_characteristic(HeartbeatCharacteristic(bus, 1, service))
    app.add_service(service)
    
    manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, ADAPTER_PATH), GATT_MANAGER_IFACE)
    manager.RegisterApplication(app.path, {}, reply_handler=None, error_handler=None)

    GLib.timeout_add_seconds(5, service.get_characteristics()[1].send_heartbeat)
    
    adv = Advertiser()
    adv.start_advertising(0, [SERVICE_UUID, INBOX_SERVICE_UUID])
    
    print(f"[SINK] Ativo. NID: {MY_NID}")
    GLib.MainLoop().run()

if __name__ == "__main__":
    main()