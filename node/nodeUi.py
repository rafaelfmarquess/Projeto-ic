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
        print("q. Sair")

    def handle_input(self, choice):
        if choice == '1':
            msg = input("Digite a mensagem: ")
            if hasattr(self.inbox, 'send_app_data'):
                self.inbox.send_app_data(msg)
        elif choice == 'q':
            self.running = False