import json
from common.consts import MY_NID
from common.cryptography import MAC

class Packet:
    def __init__(self, src_nid, dst_nid, service, payload, mac=None):
        self.src_nid = src_nid
        self.dst_nid = dst_nid
        self.service = service
        self.payload = payload
        self.mac = mac 

    def to_bytes(self,sessionKey = None):
        data = {
            "src": self.src_nid,
            "dst": self.dst_nid,
            "svc": self.service,
            "plt": self.payload,
            "mac": self.mac
        }
        if sessionKey:
            raw_content = json.dumps(data).encode('utf-8')
            data["mac"] = MAC(sessionKey,raw_content).hex()
        return json.dumps(data).encode('utf-8')

    @staticmethod
    def from_bytes(raw_data):
        try:
            d = json.loads(raw_data.decode('utf-8'))
            return Packet(d['src'], d['dst'], d['svc'], d['plt'], d.get('mac'))
        except Exception as e:
            print(f"[PROTOCOL] Erro ao processar pacote: {e}")
            return None