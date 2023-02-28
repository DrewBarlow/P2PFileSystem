import asyncio
from typing import Tuple

class PeerClient:
    REMOTE_PORT: int = 5111

    def __init__(self, ip_addr: str, port: int=REMOTE_PORT) -> None:
        self._ip_addr: str = ip_addr
        self._port: int = port
        return

