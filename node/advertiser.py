import asyncio
import logging
from bleak import BleakAdvertisingData, BleakGATTCharacteristic
from common.consts import SERVICE_UUID

class NodeAdvertiser:
    def __init__(self):
        self.advertising = False
    
    async def start(self):
        print(f"[Advertiser] Configured with UUID: {SERVICE_UUID}")
    