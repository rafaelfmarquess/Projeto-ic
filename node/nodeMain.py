import dbus.mainloop.glib
from common.scanner import *
from common.advertiser import Advertiser
from common.gatt import Application, Service
from common.consts import *
from common.protocol import *
from gi.repository import GLib

class HeartbeatMonitor:
    def __init__(self, node_control):
        self.missed_count = 0
        self.ctrl = node_control

    def heartbeat_received(self, value):
        print(f"[NODE] Heartbeat recebido: {value}")
        self.missed_count = 0

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

def send_message_to_sink(ctrl, text):
    """Encapsula e envia uma mensagem para o Sink via Uplink."""
    pkt = Packet(src_nid=MY_NID, dst_nid="SINK", service="Inbox", payload=text)
    raw_bytes = pkt.to_bytes()
    print(f"[NODE] Pacote pronto para enviar: {pkt.payload}")

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    ctrl = NodeControl()
    adv = Advertiser()
    ft = ForwardingTable()

    if ctrl.establish_uplink():
        monitor = HeartbeatMonitor(ctrl)
        GLib.timeout_add_seconds(5, monitor.check_liveness)
        setup_heartbeat_listener(ctrl, monitor)

        send_message_to_sink(ctrl, "Olá do Nó IoT!")

        bus = dbus.SystemBus()
        app = Application(bus)
        app.add_service(Service(bus, '/org/bluez/node/service', 0, SERVICE_UUID, True))
        
        manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, ADAPTER_PATH), GATT_MANAGER_IFACE)
        manager.RegisterApplication(app.path, {}, reply_handler=None, error_handler=None)
        
        adv.start_advertising(ctrl.my_hop_count, [SERVICE_UUID])
    else:
        adv.start_advertising(255, [SERVICE_UUID])

    GLib.MainLoop().run()

if __name__ == "__main__":
    main()