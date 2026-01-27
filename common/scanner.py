import time
import sys
from pydbus import SystemBus
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
        try:
            self.adapter.SetDiscoveryFilter({'UUIDs': [SERVICE_UUID]})
            self.adapter.StartDiscovery()
            time.sleep(5)
            self.adapter.StopDiscovery()
        except Exception as e:
            print(f"[!] Erro no scan: {e}")
            return None

        objects = self.mngr.GetManagedObjects()
        best_addr = None
        min_hops = float('inf')

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
                    
                    print(f" -> Dispositivo: {addr}, Hops detectados: {hops}")

                    if 0 <= hops < min_hops:
                        min_hops = hops
                        best_addr = addr

        if best_addr:
            print(f"[+] Melhor uplink encontrado: {best_addr} com {min_hops} hops.")
            return best_addr, min_hops
        return None, -1

    def establish_uplink(self):
        target_addr, target_hops = self.scan_network()
        if target_addr:
            success = self.connect_uplink(target_addr)
            if success:
                self.my_hop_count = target_hops + 1
                self.current_uplink = target_addr
                print(f"[*] Novo estado: O meu hop_count é {self.my_hop_count}")
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