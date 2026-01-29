from common.ui import BaseUI
import common.consts as consts


class NodeUI(BaseUI):
    def __init__(self, ctrl, handshake_mngr, inbox, monitor, ft):
        super().__init__()
        self.ctrl = ctrl
        self.hm = handshake_mngr
        self.inbox = inbox
        self.monitor = monitor
        self.ft = ft

    def display(self):
        self.clear()
        print(f"=== UI DO NÓ (NID: {consts.MY_NID}) ===")
        print(f"Uplink: {self.ctrl.current_uplink or 'Nenhum'} | Hops: {self.ctrl.my_hop_count}")
        print(f"Downlinks: {list(self.hm.session_keys.keys())}")
        print(f"Mensagens p/ Uplink: {getattr(self.inbox, 'routed_count', 0)}")
        print(f"Heartbeats Perdidos: {self.monitor.missed_count}")
        print(f"Tabela de Rotas: {self.ft.table}")
        print("-" * 30)
        print("1. Enviar Mensagem Segura (DTLS) ao Sink")
        print("2. Procurar novos vizinhos (Scan)")
        print("3. Lista de nós na rede")
        print("4. Enviar mensagem para outro Nó (via Sink)")
        print("5. Verificar a minha caixa de correio no Sink")
        print("q. Sair")

    def handle_input(self, choice):
        if choice == '1':
            msg = input("Digite a mensagem: ")
            if hasattr(self.inbox, 'send_app_data'):
                self.inbox.send_app_data(msg)
        elif choice == '2':
            print("\n[*] Pesquisando vizinhos próximos...")
            devices = self.ctrl.scan_network()
            
            if not devices:
                print("[!] Nenhum dispositivo encontrado.")
                input("Pressione Enter...")
                return

            print("\nID  | ENDEREÇO MAC       | HOPS ATÉ AO SINK")
            print("-" * 45)
            for idx, dev in enumerate(devices):
                print(f"{idx:<3} | {dev['addr']} | {dev['hops']}")
            
            sel = input("\nEscolha o ID para conectar (ou 'c' para cancelar): ")
            if sel.isdigit() and int(sel) < len(devices):
                target = devices[int(sel)]
                print(f"[*] Tentando ligar a {target['addr']}...")
                if self.ctrl.establish_uplink(target['addr'], target['hops']):
                    print("[+] Uplink estabelecido com sucesso!")
                else:
                    print("[!] Falha ao conectar.")
            input("\nPressione Enter para voltar...")
        elif choice == '3':
            if hasattr(self.inbox, 'request_network_nodes'):
                self.inbox.request_network_nodes()
            input("\nAguardando resposta... Pressione Enter.")
        elif choice == '4':
            dest = input("NID do destinatário: ")
            msg = input("Mensagem: ")
            self.inbox.send_to_node(dest, msg)
        elif choice == '5':
            self.inbox.fetch_mailbox()
        elif choice == 'q':
            self.running = False