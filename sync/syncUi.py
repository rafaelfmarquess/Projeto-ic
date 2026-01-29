from common.ui import BaseUI
import common.consts as consts

class SinkUI(BaseUI):
    def __init__(self, handshake_mngr, ft, hb_char):
        super().__init__()
        self.hm = handshake_mngr
        self.ft = ft
        self.hb_char = hb_char
        self.msg_log = []

    def add_log(self, nid, msg):
        self.msg_log.append(f"[{nid}]: {msg}")

    def display(self):
        self.clear()
        print(f"=== UI DO SINK (NID: {consts.MY_NID}) ===")
        print(f"Nós Ligados: {list(self.hm.session_keys.keys())}")
        print(f"Rotas Ativas: {self.ft.table}")
        print("-" * 30)
        print("Últimas Mensagens Recebidas (E2E):")
        for log in self.msg_log[-5:]:
            print(log)
        print("-" * 30)
        print("1. Parar Heartbeat para um Nó (Simular Falha)")
        print("q. Sair")

    def handle_input(self, choice):
        if choice == '1':
            mac = input("Introduza o MAC do Nó a silenciar: ")
            if hasattr(self.hb_char, 'StopNotify'):
                self.hb_char.StopNotify()
                print(f"Simulando quebra de link com {mac}")
                input("Pressione Enter para continuar...")
                self.hb_char.StartNotify()