import threading
import os

class BaseUI:
    def __init__(self):
        self.running = True

    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while self.running:
            self.display()
            choice = input("\nSeleção > ")
            self.handle_input(choice)

    def display(self):
        pass

    def handle_input(self, choice):
        pass