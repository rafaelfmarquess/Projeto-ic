import asyncio
from bleak import BleakScanner, BleakClient
from common.consts import SERVICE_UUID

class NodeScanner:
    def __init__(self):
        self.uplink_client = None
        self.uplink_address = None
    async def scan_devices(self):
        print("\n[Scanner] Scanning for SIC devices (5s)...")
        
        devices = await BleakScanner.discover()
