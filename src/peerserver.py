import asyncio

class PeerServer:
    HOST_IP: str = "127.0.0.1"
    HOST_PORT: int = 5111

    def __init__(self, port: int=HOST_PORT) -> None:
        self._port: int = port

