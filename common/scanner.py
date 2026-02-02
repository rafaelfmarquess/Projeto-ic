import time
import sys
from pydbus import SystemBus
from gi.repository import GLib 
from common.consts import SERVICE_UUID, ADAPTER_PATH, BLUEZ_SERVICE

class NodeControl:
    def __init__(self):
        self.bus = SystemBus()
        self.mngr = self.bus.get(BLUEZ_SERVICE, "/")
        self.adapter = self.bus.get(BLUEZ_SERVICE, ADAPTER_PATH)
        self.connected_devices = {}
        self.current_uplink = None
        self.my_hop_count = -1

    def scan_network(self):
        print(f"[*] A procurar potenciais uplinks (SIC {SERVICE_UUID})...")
        found_devices = []
        try:
            discovery_filter = {'UUIDs': GLib.Variant('as', [SERVICE_UUID])}
            self.adapter.SetDiscoveryFilter(discovery_filter)
            self.adapter.StartDiscovery()
            time.sleep(5)
            self.adapter.StopDiscovery()
        except Exception as e:
            print(f"[!] Erro no scan: {e}")
            return []

        objects = self.mngr.GetManagedObjects()
        for path, interfaces in objects.items():
            if "org.bluez.Device1" in interfaces:
                props = interfaces["org.bluez.Device1"]
                uuids = props.get("UUIDs", [])
                
                if SERVICE_UUID.lower() in [u.lower() for u in uuids]:
                    addr = props.get("Address")
                    service_data = props.get("ServiceData", {})
                    hops = -1
                    if SERVICE_UUID in service_data:
                        hops = int.from_bytes(service_data[SERVICE_UUID], "big")
                    
                    found_devices.append({'addr': addr, 'hops': hops})

        return found_devices

    def establish_uplink(self, manual_addr=None, manual_hops=None):
        if manual_addr is not None:
            target_addr, target_hops = manual_addr, manual_hops
        else:
            devices = self.scan_network()
            if not devices: return False
            best = min(devices, key=lambda d: d['hops'] if d['hops'] >= 0 else float('inf'))
            target_addr, target_hops = best['addr'], best['hops']

        if self.connect_uplink(target_addr):
            self.my_hop_count = target_hops + 1
            self.current_uplink = target_addr
            return True
        return False

    def connect_uplink(self, mac_address):

        device_path = f"{ADAPTER_PATH}/dev_{mac_address.replace(':', '_')}"
        
        try:
            print(f"[*] A conectar a {mac_address}...")
            device = self.bus.get(BLUEZ_SERVICE, device_path)
            
            device.Connect() 
            
            print(f"[+] Conectado com sucesso a {mac_address}")
            self.connected_devices[mac_address] = device
            return True
        except Exception as e:
            print(f"[!] Falha ao conectar: {e}")
            return False

    def destroy_connection(self, mac_address):

        if mac_address in self.connected_devices:
            try:
                print(f"[*] A destruir conexão com {mac_address}...")
                self.connected_devices[mac_address].Disconnect()
                del self.connected_devices[mac_address]
                print("[+] Desconectado.")
            except Exception as e:
                print(f"[!] Erro ao desconectar: {e}")
        else:
            print("[!] Dispositivo não está na lista de ativos locais.")
    def destroy_all_connections(self):
        print("[*] Reação em Cadeia: A quebrar todas as ligações...")    
        for addr in list(self.connected_devices.keys()):
            self.destroy_connection(addr)
    
        if self.current_uplink:
            self.destroy_connection(self.current_uplink)
            self.current_uplink = None
            self.my_hop_count = -1

        print("[!] Nó isolado. Reinicie o programa para procurar novo Uplink.")
        
class ForwardingTable:
    def __init__(self):
        self.table = {} 

    def update_route(self, nid, path):
        if nid not in self.table:
            print(f"[*] Nova rota aprendida: NID {nid} via {path}")
        self.table[nid] = path