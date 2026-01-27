import dbus
import dbus.service
from common.consts import SERVICE_UUID, BLUEZ_SERVICE, ADAPTER_PATH

LE_ADVERTISING_MANAGER_IFACE = 'org.bluez.LEAdvertisingManager1'
LE_ADVERTISEMENT_IFACE = 'org.bluez.LEAdvertisement1'

class Advertisement(dbus.service.Object):
    def __init__(self, bus, index, hop_count,uuids):
        self.path = f"/org/bluez/example/advertisement{index}"
        self.bus = bus
        self.hop_count = hop_count
        self.uuids = uuids
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        return {
            LE_ADVERTISEMENT_IFACE: {
                'Type': 'peripheral',
                'ServiceUUIDs': self.uuids,
                'ServiceData': {SERVICE_UUID: [dbus.Byte(self.hop_count)]},
                'IncludeTxPower': dbus.Boolean(True),
            }
        }

    @dbus.service.method('org.freedesktop.DBus.Properties', in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != LE_ADVERTISEMENT_IFACE:
            raise dbus.exceptions.DBusException('interface incorreta')
        return self.get_properties()[LE_ADVERTISEMENT_IFACE]

    @dbus.service.method(LE_ADVERTISEMENT_IFACE, in_signature='', out_signature='')
    def Release(self):
        print(f'{self.path}: Advertisement released')

class Advertiser:
    def __init__(self):
        self.bus = dbus.SystemBus()
        self.adv_manager = dbus.Interface(
            self.bus.get_object(BLUEZ_SERVICE, ADAPTER_PATH),
            LE_ADVERTISING_MANAGER_IFACE
        )
        self.adv = None

    def start_advertising(self, hop_count,uuids):
        self.adv = Advertisement(self.bus, 0, hop_count, uuids)
        self.adv_manager.RegisterAdvertisement(
            self.adv.path, {},
            reply_handler=lambda: print("Publicidade registada com sucesso!"),
            error_handler=lambda e: print(f"Erro ao registar: {e}")
        )