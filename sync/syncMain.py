import dbus.mainloop.glib
from common.gatt import Application, Service, Characteristic
from common.advertiser import Advertiser
from common.consts import *
from gi.repository import GLib

class InboxCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        Characteristic.__init__(self, bus, index, CHAT_MSG_UUID, ['write'], service)

    def WriteValue(self, value, options):
        msg = bytes(value).decode('utf-8')
        print(f"[SINK] Mensagem recebida no Inbox: {msg}")
        return []

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    
    app = Application(bus)
    inbox_service = Service(bus, '/org/bluez/example/service', 0, INBOX_SERVICE_UUID, True)
    inbox_service.add_characteristic(InboxCharacteristic(bus, 0, inbox_service))
    app.add_service(inbox_service)
    
    manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, ADAPTER_PATH), GATT_MANAGER_IFACE)
    manager.RegisterApplication(app.path, {}, 
                                reply_handler=lambda: print("GATT Application Registered"),
                                error_handler=lambda e: print(f"Registration failed: {e}"))

    adv = Advertiser()
    adv.start_advertising(0)
    
    print(f"[SINK] Pronto. NID: {MY_NID}")
    GLib.MainLoop().run()

if __name__ == "__main__":
    main()