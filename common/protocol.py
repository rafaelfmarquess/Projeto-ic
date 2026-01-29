import json
import base64
from common.consts import MY_NID
from common.cryptography import MAC
from common.cryptography import encrypt_payload, decrypt_payload

class Packet:
    def __init__(self, src_nid, dst_nid, service, payload, mac=None, nonce=None):
        self.src_nid = src_nid
        self.dst_nid = dst_nid
        self.service = service
        self.payload = payload
        self.mac = mac
        self.nonce = nonce 

    def to_bytes(self, session_key=None,nonce = None):
        out_plt, out_mac, out_nonce = self.payload, self.mac, self.nonce
        
        if session_key:
            ct_tag = encrypt_payload(session_key, self.payload,nonce)
            out_plt = base64.b64encode(ct_tag[:-16]).decode('utf-8')
            out_mac = ct_tag[-16:].hex() 
            out_nonce = nonce.hex()

        data = {"src": self.src_nid, "dst": self.dst_nid, "svc": self.service, 
                "plt": out_plt, "mac": out_mac, "nonce": out_nonce}
        return json.dumps(data).encode('utf-8')

    @staticmethod
    def from_bytes(raw_data, session_key=None):
        try:
            d = json.loads(raw_data.decode('utf-8'))
            pkt = Packet(d['src'], d['dst'], d['svc'], d['plt'], d.get('mac'), d.get('nonce'))
            
            if session_key and pkt.nonce and pkt.mac:
                ct_with_tag = base64.b64decode(pkt.payload) + bytes.fromhex(pkt.mac)
                pkt.payload = decrypt_payload(session_key, bytes.fromhex(pkt.nonce), ct_with_tag)
            return pkt
        except Exception as e:
            print(f"[PROTOCOL] Falha na decifragem/integridade: {e}")
            return None