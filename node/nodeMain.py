import sys
import dbus
import base64
import random
import json
import dbus.mainloop.glib
from common.scanner import NodeControl, ForwardingTable
from common.gatt import Characteristic
from common.advertiser import Advertiser
from common.gatt import Application, Service, CertificateCharacteristic, KeyExchangeCharacteristic
from common.consts import *
import common.consts as consts
from common.protocol import Packet
from common.Dtls import DTLSHandler
import nodeUi
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
dtls = None

forwarding_table = ForwardingTable()

class NodeInboxCharacteristic(Characteristic):
    def __init__(self, bus, index, service,ctrl):
        self.ctrl = ctrl
        self.routed_count = 0
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
    
            forwarding_table.update_route(packet.src_nid, peer_addr)

            if packet.dst_nid == consts.MY_NID:
                if packet.service == "DTLS":
                    raw_dtls = base64.b64decode(packet.payload)
                    clear_text = dtls.handle_incoming(raw_dtls)
                    resp = dtls.get_outgoing_network_data()
                    if resp:
                        self._send_dtls_to_sink(resp)
                        
                    if clear_text:
                        try:
                            app_data = json.loads(clear_text.decode('utf-8'))
                            if app_data.get("type") == "MAILBOX_CONTENT":
                                msgs = app_data.get("messages", [])
                                if not msgs:
                                    print("[MAILBOX] Não tens mensagens novas.")
                                else:
                                    print(f"\n--- TENS {len(msgs)} MENSAGENS NOVAS ---")
                                    for m in msgs:
                                        print(f"De {m['from']}: {m['msg']}")
                            elif app_data.get("type") == "NODE_LIST":
                                nodes = app_data.get("nodes", [])
                                print(f"\n[REDE] Nós ativos no sistema: {', '.join(nodes)}")
                            else:
                                port = app_data.get("port")
                                data = app_data.get("data")
                                print(f"[APP] Recebido na Porta {port}: {data}")
                        except:
                            print(f"[DTLS] Recebido (Raw): {clear_text.decode()}")
                else:
                    self._process_locally(packet, peer_addr)
            elif packet.dst_nid == "SINK":
                print(f"[*] A reencaminhar pacote de {packet.src_nid} para o SINK...")
                self._forward_packet(packet, self.ctrl.current_uplink)
            else:
                target_mac = forwarding_table.table.get(packet.dst_nid)
                if target_mac:
                    print(f"[*] A reencaminhar pacote para downlink {packet.dst_nid} via {target_mac}")
                    self._forward_packet(packet, target_mac)
                else:
                    print(f"[!] Rota desconhecida para {packet.dst_nid}. Descartado.")
        return []
    
    def _forward_packet(self, packet, target_mac):
        target_key = handshake_manager.session_keys.get(target_mac)
        if target_key:
            if target_mac == self.ctrl.current_uplink:
                self.routed_count += 1
            new_nonce = handshake_manager.get_next_tx_nonce(target_mac)
            data = packet.to_bytes(target_key, new_nonce)
            handshake_manager._write_to_remote_inbox(target_mac, data)

    def _process_locally(self, packet, peer_addr):
        if packet.service == "Control" and packet.payload == "KEY_CONFIRM_ACK":
            handshake_manager.confirmSession(peer_addr, isInitiator=True, received_pkt=packet)
        else:
            print(f"[NODE] Mensagem local recebida de {packet.src_nid}: {packet.payload}")
            
    def _start_dtls_handshake(self):
        global dtls
        print("[DTLS] A iniciar handshake ponta-a-ponta...")
        dtls.do_handshake()
        hello_data = dtls.get_outgoing_network_data()
        
        if hello_data:
            self._send_dtls_to_sink(hello_data)
            
    def _send_dtls_to_sink(self, dtls_data):
        payload = base64.b64encode(dtls_data).decode()
        pkt = Packet(consts.MY_NID, "SINK", "DTLS", payload)
        self._forward_packet(pkt, self.ctrl.current_uplink)

    def send_app_data(self, message):
        global dtls        
        if not dtls or not dtls.is_established:
            print("[!] Erro: Canal DTLS ainda não está estabelecido. Handshake em curso?")
            return
        
        app_packet = {
            "port": random.randint(1024, 65535),
            "data": message
        }
        json_payload = json.dumps(app_packet)
        
        dtls_payload = dtls.encrypt(json_payload)        
        if dtls_payload:
            self._send_dtls_to_sink(dtls_payload)
            print(f"[*] Mensagem enviada com sucesso para o Sink.")
        else:
            print("[!] Erro ao cifrar mensagem com DTLS.")

    def request_network_nodes(self):
        if not dtls or not dtls.is_established:
            print("[!] Erro: Canal DTLS não estabelecido.")
            return

        pedido = {
            "port": random.randint(1024, 65535),
            "type": "LIST_NODES"
        }
        dtls_payload = dtls.encrypt(json.dumps(pedido))
        self._send_dtls_to_sink(dtls_payload)
        print("[*] Pedido de listagem enviado ao Sink...")
    def send_to_node(self, dest_nid, message):
        payload = {
            "port": random.randint(1024, 65535),
            "type": "SEND_TO_NODE",
            "dst_nid": dest_nid,
            "data": message
        }
        dtls_payload = dtls.encrypt(json.dumps(payload))
        self._send_dtls_to_sink(dtls_payload)
        print(f"[*] Mensagem enviada para o Sink com destino a {dest_nid}")

    def fetch_mailbox(self):
        payload = {
            "port": random.randint(1024, 65535),
            "type": "GET_MESSAGES"
        }
        dtls_payload = dtls.encrypt(json.dumps(payload))
        self._send_dtls_to_sink(dtls_payload)
        print("[*] A consultar mensagens pendentes no Sink...")
    
class HeartbeatMonitor:
    def __init__(self, node_control, sink_pub_key,HeartB_FW):
        self.missed_count = 0
        self.ctrl = node_control
        self.sink_pub_key = sink_pub_key 
        self.HeartB_FW = HeartB_FW
        

    def heartbeat_received(self, value):
        try:
            parts = bytes(value).split(b'|', 1)
            if len(parts) < 2: return
            
            counter_data = parts[0]
            signature = parts[1]
            
            self.sink_pub_key.verify(signature, counter_data, ec.ECDSA(hashes.SHA256()))
            print(f"[NODE] Heartbeat verificado com sucesso: {counter_data.decode()}")
            self.missed_count = 0
            if self.HeartB_FW:
                print(f"[NODE] Heartbeat verificado. A propagar para downlinks...")
                self.HeartB_FW.forward_heartbeat(value)
        except Exception as e:
            print(f"[!] Erro na verificação do Heartbeat (Possível intruso): {e}")

    def check_liveness(self):
        self.missed_count += 1
        if self.missed_count >= 3:
            print("[!] LINK DOWN: 3 heartbeats perdidos ou falha de autenticação. A resetar nó...")
            self.ctrl.destroy_all_connections() 
            return False
        return True

class NodeHeartbeatCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        self.uuid = '87654321-4321-4321-4321-210987654321'
        Characteristic.__init__(self, bus, index, self.uuid, ['notify'], service)

    def forward_heartbeat(self, value):
        self.PropertiesChanged(GATT_CHARACTERISTIC_IFACE, {'Value': dbus.Array(value, signature='y')}, [])

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
    global handshake_manager,dtls
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    
    if len(sys.argv) < 2:
        print("Uso: python3 nodeMain.py [node1|node2|node3]")
        return
    
    load_node_credentials(sys.argv[1])
    
    with open("../certs/ca_cert.pem", "rb") as f: ca_pem = f.read()
    with open(f"../certs/{sys.argv[1]}_cert.pem", "rb") as f: cert_pem = f.read()
    with open(f"../certs/{sys.argv[1]}_key.pem", "rb") as f: key_pem = f.read()
    
    dtls = DTLSHandler(cert_pem, key_pem, ca_pem, is_server=False)

    handshake_manager = HandshakeManager(CA_CERT, MY_CERT, MY_KEY)
    
    ctrl = NodeControl()
    adv = Advertiser()

    if ctrl.establish_uplink():
        if handshake_manager.perform_handshake(ctrl, ctrl.current_uplink):
            
            handshake_manager.confirmSession(ctrl.current_uplink, isInitiator=True)
            
            bus = dbus.SystemBus()
            app = Application(bus)
            service = Service(bus, '/org/bluez/node/service', 0, SERVICE_UUID, True)
            
            sink_pub_key = handshake_manager._get_and_verify_peer_cert(ctrl.current_uplink)
            HeartB_FW = NodeHeartbeatCharacteristic(bus, 3, service)
            service.add_characteristic(HeartB_FW)
            
            monitor = HeartbeatMonitor(ctrl, sink_pub_key,HeartB_FW)
            GLib.timeout_add_seconds(5, monitor.check_liveness)
            setup_heartbeat_listener(ctrl, monitor)
                       
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
            
            inbox = NodeInboxCharacteristic(bus, 2, service,ctrl)
            service.add_characteristic(inbox)
            
            app.add_service(service)
            GLib.idle_add(inbox._start_dtls_handshake)
            manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, ADAPTER_PATH), GATT_MANAGER_IFACE)
            manager.RegisterApplication(app.path, {}, reply_handler=None, error_handler=None)
            
            ui = nodeUi.NodeUI(ctrl, handshake_manager, inbox, monitor, forwarding_table)
            ui.start()
            
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