import dbus.mainloop.glib
from common.scanner import NodeControl
from common.advertiser import Advertiser
from common.gatt import Application, Service
from common.consts import *
from gi.repository import GLib

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    ctrl = NodeControl()
    adv = Advertiser()

    if ctrl.establish_uplink():
        print(f"[NODE] Conectado ao Uplink. Meu Hop Count: {ctrl.my_hop_count}")
        bus = dbus.SystemBus()
        app = Application(bus)
        app.add_service(Service(bus, '/org/bluez/node/service', 0, SERVICE_UUID, True))
        
        manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, ADAPTER_PATH), GATT_MANAGER_IFACE)
        manager.RegisterApplication(app.path, {}, reply_handler=None, error_handler=None)
        
        adv.start_advertising(ctrl.my_hop_count)
    else:
        print("[NODE] Nenhum uplink encontrado. Isolado.")
        adv.start_advertising(255)

    GLib.MainLoop().run()

if __name__ == "__main__":
    main()